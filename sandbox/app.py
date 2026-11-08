import asyncio
import hashlib
import hmac
import os
import re
import sqlite3
import shlex
import threading
import time
import io
import uuid
from typing import Literal

import docker
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="LLMRoute user sandbox", docs_url=None, redoc_url=None)
client = docker.from_env(timeout=8)
SECRET = os.environ.get("AGENT_SANDBOX_SECRET", "")
IMAGE = os.environ.get("AGENT_SANDBOX_IMAGE", "python:3.12-slim")
MAX_CONCURRENT = int(os.environ.get("AGENT_SANDBOX_CONCURRENCY", "8"))
MAX_WORKSPACE_BYTES = int(os.environ.get("AGENT_SANDBOX_WORKSPACE_BYTES", str(256 * 1024 * 1024)))
MAX_TOTAL_WORKSPACE_BYTES = int(os.environ.get("AGENT_SANDBOX_TOTAL_WORKSPACE_BYTES", str(20 * 1024 * 1024 * 1024)))
semaphore = asyncio.Semaphore(MAX_CONCURRENT)
user_locks: dict[str, asyncio.Lock] = {}
storage_lock = threading.Lock()
jobs_lock = threading.Lock()
active_jobs: dict[str, str | None] = {}
cancelled_jobs: dict[str, float] = {}
STATE_DB = "/var/lib/sandbox/storage.db"
os.makedirs(os.path.dirname(STATE_DB), exist_ok=True)
with sqlite3.connect(STATE_DB) as db:
    db.execute("CREATE TABLE IF NOT EXISTS workspace_usage(user_hash TEXT PRIMARY KEY, bytes INTEGER NOT NULL)")

@app.on_event("startup")
def prepare_runtime_image():
    try:
        client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        client.images.pull(IMAGE)

class ExecuteInput(BaseModel):
    job_id: str = Field(default_factory=lambda: uuid.uuid4().hex, min_length=1, max_length=128)
    user_id: str = Field(min_length=1, max_length=128)
    language: Literal["python", "shell"]
    code: str = Field(min_length=1, max_length=65536)
    timeout_seconds: int = Field(default=30, ge=1, le=60)


def volume_for(user_id: str):
    digest = hashlib.sha256(user_id.encode()).hexdigest()[:32]
    name = f"llmroute-user-{digest}"
    try:
        return client.volumes.get(name), False
    except docker.errors.NotFound:
        try:
            return client.volumes.create(name=name, labels={"app": "llmroute", "kind": "user-workspace", "user_hash": digest}), True
        except docker.errors.APIError:
            return client.volumes.get(name), False


def cancellation_requested(job_id: str):
    with jobs_lock:
        expiry = cancelled_jobs.get(job_id)
        if expiry is None:
            return False
        if expiry < time.monotonic():
            cancelled_jobs.pop(job_id, None)
            return False
        return True


def state_helper(volume):
    helper = client.containers.run(
        IMAGE,
        command=["sh", "-lc", "mkdir -p /state/workspace && chmod 0777 /state/workspace && exec sleep infinity"],
        volumes={volume.name: {"bind": "/state", "mode": "rw"}},
        network_mode="none",
        tmpfs={"/tmp": "rw,noexec,nosuid,size=16m"},
        mem_limit="64m",
        nano_cpus=250_000_000,
        pids_limit=16,
        cap_drop=["ALL"],
        cap_add=["CHOWN", "DAC_OVERRIDE", "FOWNER"],
        security_opt=["no-new-privileges:true"],
        detach=True,
        auto_remove=False,
    )
    for _ in range(50):
        result = helper.exec_run(["sh", "-lc", "test -d /state/workspace"])
        if result.exit_code == 0:
            return helper
        time.sleep(0.1)
    helper.remove(force=True)
    raise RuntimeError("workspace storage initialization failed")


def archive_bytes(container, path):
    stream, _ = container.get_archive(path)
    return b"".join(stream)


def load_workspace(helper, target):
    data = archive_bytes(helper, "/state/workspace")
    if len(data) > MAX_WORKSPACE_BYTES:
        raise ValueError("用户沙盒工作区已超过 256 MB 限额，请先删除部分文件")
    if not target.put_archive("/workspace", data):
        raise RuntimeError("failed to restore user workspace")


def save_workspace(user_hash: str, container, helper):
    data = archive_bytes(container, "/workspace")
    if len(data) > MAX_WORKSPACE_BYTES:
        return False
    with storage_lock, sqlite3.connect(STATE_DB, timeout=30) as db:
        db.execute("BEGIN IMMEDIATE")
        previous = db.execute("SELECT bytes FROM workspace_usage WHERE user_hash=?", (user_hash,)).fetchone()
        old_size = int(previous[0]) if previous else 0
        total = int(db.execute("SELECT COALESCE(SUM(bytes),0) FROM workspace_usage").fetchone()[0])
        if total - old_size + len(data) > MAX_TOTAL_WORKSPACE_BYTES:
            db.rollback()
            return False
        if not helper.put_archive("/state/workspace", data):
            db.rollback()
            raise RuntimeError("failed to persist user workspace")
        db.execute("INSERT INTO workspace_usage(user_hash,bytes) VALUES(?,?) ON CONFLICT(user_hash) DO UPDATE SET bytes=excluded.bytes", (user_hash, len(data)))
        db.commit()
    return True


def run_code(request: ExecuteInput):
    if cancellation_requested(request.job_id):
        return {"exit_code": 137, "timed_out": False, "cancelled": True, "output": "执行已中断", "truncated": False, "duration_ms": 0}
    volume, _ = volume_for(request.user_id)
    helper = state_helper(volume)
    container = None
    started = time.monotonic()
    timed_out = False
    persisted = True
    try:
        # Docker archive restore requires a writable container layer; this throwaway container remains unprivileged and is destroyed after execution.
        container = client.containers.run(
            IMAGE,
            command=["sleep", "infinity"],
            user="0:0",
            working_dir="/workspace",
            network_mode="bridge",
            read_only=False,
            tmpfs={"/tmp": "rw,noexec,nosuid,size=64m", "/var/tmp": "rw,noexec,nosuid,size=64m", "/workspace": "rw,nosuid,nodev,size=256m,mode=1777"},
            mem_limit="512m",
            nano_cpus=1_000_000_000,
            pids_limit=64,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            detach=True,
            auto_remove=False,
            labels={"app": "llmroute", "kind": "user-execution", "user_hash": hashlib.sha256(request.user_id.encode()).hexdigest()[:32]},
        )
        with jobs_lock:
            active_jobs[request.job_id] = container.id
        cancelled_before_start = cancellation_requested(request.job_id)
        if cancelled_before_start:
            try:
                container.kill()
            except docker.errors.APIError:
                pass
            return {"exit_code": 137, "timed_out": False, "cancelled": True, "output": "执行已中断", "truncated": False, "duration_ms": int((time.monotonic() - started) * 1000)}
        load_workspace(helper, container)
        cancelled_before_exec = cancellation_requested(request.job_id)
        if cancelled_before_exec:
            return {"exit_code": 137, "timed_out": False, "cancelled": True, "output": "执行已中断", "truncated": False, "duration_ms": int((time.monotonic() - started) * 1000)}
        program = ["python", "-u", "-c", request.code] if request.language == "python" else ["sh", "-lc", request.code]
        run_command = "timeout --signal=KILL " + shlex.quote(f"{request.timeout_seconds}s") + " " + shlex.join(program)
        command = ["sh", "-lc", run_command + " > /tmp/agent-output.log 2>&1; result=$?; bytes=$(wc -c < /tmp/agent-output.log); head -c 20000 /tmp/agent-output.log; if [ $bytes -gt 20000 ]; then printf \"\\n__LLMROUTE_OUTPUT_TRUNCATED__\"; fi; exit $result"]
        result = container.exec_run(
            command,
            user="10001:10001",
            workdir="/workspace",
            environment={"HOME":"/workspace/.home","PYTHONUSERBASE":"/workspace/.local","PYTHONPATH":"/workspace/.local/lib/python3.12/site-packages","PATH":"/workspace/.local/bin:/usr/local/bin:/usr/bin:/bin","PYTHONDONTWRITEBYTECODE":"1"},
        )
        exit_code = int(result.exit_code if result.exit_code is not None else 1)
        timed_out = exit_code == 124 or exit_code == 137
        cancelled = cancellation_requested(request.job_id)
        persisted = save_workspace(hashlib.sha256(request.user_id.encode()).hexdigest()[:32], container, helper)
        output = (result.output or b"").decode("utf-8", errors="replace") if isinstance(result.output, bytes) else str(result.output or "")
        truncated = "__LLMROUTE_OUTPUT_TRUNCATED__" in output
        output = output.replace("__LLMROUTE_OUTPUT_TRUNCATED__", "[输出过长，已截断]")
        if not persisted:
            output += "\n[个人工作区或平台工作区总容量已达上限，本轮文件变更未保存]"
        limit = 22000
        if len(output) > limit:
            output = output[:limit] + "\n[输出过长，已截断]"
            truncated = True
        return {"exit_code": exit_code, "timed_out": timed_out and not cancelled, "cancelled": cancelled, "output": output, "truncated": truncated, "duration_ms": int((time.monotonic() - started) * 1000)}
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except docker.errors.NotFound:
                pass
        try:
            helper.remove(force=True)
        except docker.errors.NotFound:
            pass


@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/execute")
async def execute(request: ExecuteInput, authorization: str | None = Header(default=None)):
    if not SECRET or not authorization or not hmac.compare_digest(authorization, f"Bearer {SECRET}"):
        raise HTTPException(status_code=401, detail="unauthorized")
    lock = user_locks.setdefault(request.user_id, asyncio.Lock())
    with jobs_lock:
        active_jobs[request.job_id] = None
    try:
        async with semaphore:
            async with lock:
                try:
                    return await asyncio.to_thread(run_code, request)
                except docker.errors.ImageNotFound:
                    raise HTTPException(status_code=503, detail="sandbox runtime image is unavailable")
                except docker.errors.APIError as exc:
                    raise HTTPException(status_code=503, detail=f"sandbox runtime error: {exc.explanation or 'unknown'}")
                except Exception as exc:
                    raise HTTPException(status_code=500, detail=f"sandbox execution failed: {str(exc)[:500]}")
    finally:
        with jobs_lock:
            active_jobs.pop(request.job_id, None)
            cancelled_jobs.pop(request.job_id, None)


@app.post("/cancel/{job_id}")
def cancel(job_id: str, authorization: str | None = Header(default=None)):
    if not SECRET or not authorization or not hmac.compare_digest(authorization, f"Bearer {SECRET}"):
        raise HTTPException(status_code=401, detail="unauthorized")
    if len(job_id) > 128:
        raise HTTPException(status_code=400, detail="invalid job id")
    with jobs_lock:
        cancelled_jobs[job_id] = time.monotonic() + 120
        container_id = active_jobs.get(job_id)
    if container_id:
        try:
            client.containers.get(container_id).kill()
        except docker.errors.NotFound:
            pass
        except docker.errors.APIError as exc:
            raise HTTPException(status_code=503, detail=f"sandbox cancellation failed: {exc.explanation or 'unknown'}")
    return {"cancelled": True}
