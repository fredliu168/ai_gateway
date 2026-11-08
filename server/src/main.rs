use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use argon2::{PasswordHasher, PasswordVerifier};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use chrono::{Datelike, TimeZone, Timelike};
use chrono_tz::Asia::Shanghai;
use jsonwebtoken::{EncodingKey, Header, encode};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    FromRow, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{env, net::SocketAddr, sync::Arc};
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    redis: Option<ConnectionManager>,
    jwt_secret: Arc<String>,
    upstream_key: Arc<String>,
    http: reqwest::Client,
    credentials_key: Arc<[u8; 32]>,
    sandbox_url: Arc<String>,
    sandbox_secret: Arc<String>,
}

#[derive(Deserialize)]
struct AgentSandboxInput {
    language: String,
    code: String,
    #[serde(default = "default_sandbox_timeout")]
    timeout_seconds: u32,
}

fn default_sandbox_timeout() -> u32 {
    30
}

async fn execute_agent_sandbox(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AgentSandboxInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let claims = actor(&headers, &s.jwt_secret)?;
    if claims.api_key_id.is_some() {
        return Err(fail(StatusCode::FORBIDDEN, "Agent 沙盒需要平台账号登录"));
    }
    let active: Option<i64> = sqlx::query_scalar("SELECT active FROM users WHERE id=?")
        .bind(&claims.sub)
        .fetch_optional(&s.db)
        .await
        .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "账号状态校验暂不可用"))?;
    if active != Some(1) {
        return Err(fail(StatusCode::UNAUTHORIZED, "账号已停用或不存在"));
    }
    if !["python", "shell"].contains(&input.language.as_str())
        || input.code.trim().is_empty()
        || input.code.len() > 65_536
    {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "沙盒仅支持不超过 64 KB 的 Python 或 Shell 代码",
        ));
    }
    let response = s.http
        .post(format!("{}/execute", s.sandbox_url.trim_end_matches('/')))
        .bearer_auth(s.sandbox_secret.as_str())
        .json(&json!({"user_id":claims.sub,"language":input.language,"code":input.code,"timeout_seconds":input.timeout_seconds.clamp(1,60)}))
        .timeout(std::time::Duration::from_secs(75))
        .send().await
        .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "Agent 沙盒暂不可用"))?;
    let status = response.status();
    let value = response
        .json::<Value>()
        .await
        .unwrap_or_else(|_| json!({"detail":"Agent 沙盒返回无法解析的响应"}));
    if !status.is_success() {
        let message = value
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("Agent 沙盒执行失败");
        return Err(fail(
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            message,
        ));
    }
    Ok(Json(value))
}

#[derive(Deserialize)]
struct AgentChatInput {
    model: String,
    messages: Vec<Value>,
    #[serde(default = "default_agent_max_tokens")]
    max_tokens: i64,
}

fn default_agent_max_tokens() -> i64 {
    8192
}

async fn agent_chat(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AgentChatInput>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let claims = actor(&headers, &s.jwt_secret)?;
    if claims.api_key_id.is_some() {
        return Err(fail(StatusCode::FORBIDDEN, "Agent 模式需要平台账号登录"));
    }
    let active: Option<i64> = sqlx::query_scalar("SELECT active FROM users WHERE id=?")
        .bind(&claims.sub)
        .fetch_optional(&s.db)
        .await
        .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "账号状态校验暂不可用"))?;
    if active != Some(1) {
        return Err(fail(StatusCode::UNAUTHORIZED, "账号已停用或不存在"));
    }
    if input.model.trim().is_empty() || input.messages.is_empty() {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "Agent 请求缺少模型或对话内容",
        ));
    }
    if input.messages.len() > 200 {
        return Err(fail(StatusCode::BAD_REQUEST, "对话历史过长"));
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let cancellation = Arc::new(tokio::sync::Notify::new());
    let cancel_monitor = cancellation.clone();
    let client_stream = tx.clone();
    tokio::spawn(async move {
        let monitor = tokio::spawn(async move {
            client_stream.closed().await;
            cancel_monitor.notify_one();
        });
        let result = run_agent_session(s, claims, input, &tx, cancellation).await;
        monitor.abort();
        let _ = monitor.await;
        match result {
            Ok((input_tokens, output_tokens, truncated)) => {
                let _ = send_agent_event(&tx, json!({"type":"done","usage":{"prompt_tokens":input_tokens,"completion_tokens":output_tokens},"truncated":truncated})).await;
            }
            Err(message) => {
                let _ = send_agent_event(&tx, json!({"type":"error","error":{"message":message}}))
                    .await;
            }
        }
        let _ = tx.send(Ok(Bytes::from_static(b"data: [DONE]\n\n"))).await;
    });
    let stream = futures_util::stream::unfold(rx, |mut receiver| async {
        receiver.recv().await.map(|item| (item, receiver))
    });
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache, no-transform")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
        .into_response())
}

async fn send_agent_event(
    tx: &tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    value: Value,
) -> bool {
    tx.send(Ok(Bytes::from(format!("data: {}\n\n", value))))
        .await
        .is_ok()
}

async fn run_agent_session(
    s: AppState,
    claims: Claims,
    input: AgentChatInput,
    tx: &tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    cancellation: Arc<tokio::sync::Notify>,
) -> Result<(i64, i64, bool), String> {
    let today = Utc::now().with_timezone(&Shanghai).date_naive();
    let mut messages = input.messages;
    messages.insert(0, json!({
        "role":"system",
        "content":format!("你是汇智 AI Gateway 的云端自主 Agent。先分析用户目标并制定简短、可执行的步骤；再根据目标自主决定是否需要工具。需要实时信息、网页资料、计算或文件处理时，使用 run_python 在当前用户的长期云端沙盒执行。不得依赖针对某类问题预写的查询脚本；根据任务自行编写通用 Python 代码，优先用标准库 urllib 访问互联网。每次执行后检查输出，必要时修正方案并继续调用工具。完成后用中文直接、简洁地回答用户问题，不要附加数据来源或执行过程说明；不得猜测工具未提供的信息。当前北京时间日期：{today}。")
    }));
    let tools = json!([{"type":"function","function":{"name":"run_python","description":"在当前登录用户的专属长期云端沙盒中运行 Python 3。/workspace 文件会持久保存。可按需访问互联网、读写文件和处理数据。单次运行不超过 60 秒。请根据任务自主规划并生成代码，不要调用预设任务脚本。","parameters":{"type":"object","properties":{"code":{"type":"string","description":"为当前执行步骤编写的 Python 3 代码"},"timeout_seconds":{"type":"integer","minimum":1,"maximum":60,"description":"执行超时秒数，默认 30"}},"required":["code"],"additionalProperties":false}}}]);
    let mut input_tokens = 0_i64;
    let mut output_tokens = 0_i64;

    for round in 0..8 {
        if tx.is_closed() {
            return Err("客户端已断开连接".into());
        }
        let body = json!({
            "model":input.model.clone(),
            "messages":messages.clone(),
            "max_tokens":input.max_tokens.clamp(1, 32768),
            "stream":true,
            "tools":tools,
            "tool_choice":"auto"
        });
        let response =
            stream_openai_chat(s.clone(), claims.clone(), body, Some(cancellation.clone()))
                .await
                .map_err(|(_, Json(value))| {
                    value
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("模型请求失败")
                        .to_string()
                })?;
        let status = response.status();
        let mut data_stream = response.into_body().into_data_stream();
        if !status.is_success() {
            let mut error_bytes = Vec::new();
            while let Some(Ok(chunk)) = futures_util::StreamExt::next(&mut data_stream).await {
                error_bytes.extend_from_slice(&chunk);
            }
            let value: Value = serde_json::from_slice(&error_bytes).unwrap_or_else(|_| json!({}));
            return Err(value
                .pointer("/error/message")
                .or_else(|| value.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("模型请求失败")
                .to_string());
        }

        let mut pending = String::new();
        let mut round_text = String::new();
        let mut round_usage: Option<Value> = None;
        let mut finish_reason = String::new();
        let mut calls: Vec<Value> = Vec::new();
        let mut stream_error = None;
        while let Some(chunk) = futures_util::StreamExt::next(&mut data_stream).await {
            let chunk = chunk.map_err(|_| "模型流式响应中断".to_string())?;
            pending.push_str(&String::from_utf8_lossy(&chunk));
            let lines = pending.split('\n').map(str::to_owned).collect::<Vec<_>>();
            pending = lines.last().cloned().unwrap_or_default();
            for line in lines.iter().take(lines.len().saturating_sub(1)) {
                let Some(raw) = line.trim_end_matches('\r').strip_prefix("data:") else {
                    continue;
                };
                let raw = raw.trim();
                if raw.is_empty() || raw == "[DONE]" {
                    continue;
                }
                let Ok(event) = serde_json::from_str::<Value>(raw) else {
                    continue;
                };
                if let Some(error) = event.pointer("/error/message").and_then(Value::as_str) {
                    stream_error = Some(error.to_owned());
                    continue;
                }
                let choice = &event["choices"][0];
                if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                    finish_reason = reason.to_owned();
                }
                if let Some(usage) = event.get("usage") {
                    round_usage = Some(usage.clone());
                }
                let delta = &choice["delta"];
                if let Some(content) = delta.get("content").and_then(Value::as_str) {
                    round_text.push_str(content);
                    if !send_agent_event(tx, json!({"type":"content","delta":content})).await {
                        return Err("客户端已断开连接".into());
                    }
                }
                if let Some(reasoning) = delta
                    .get("reasoning_content")
                    .or_else(|| delta.get("reasoning"))
                    .and_then(Value::as_str)
                {
                    if !send_agent_event(tx, json!({"type":"reasoning","delta":reasoning})).await {
                        return Err("客户端已断开连接".into());
                    }
                }
                if let Some(tool_deltas) = delta.get("tool_calls").and_then(Value::as_array) {
                    for tool in tool_deltas {
                        let index = tool.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                        while calls.len() <= index {
                            calls.push(json!({"id":"","type":"function","function":{"name":"","arguments":""}}));
                        }
                        let current = &mut calls[index];
                        if let Some(id) = tool.get("id").and_then(Value::as_str) {
                            current["id"] = json!(id);
                        }
                        if let Some(name) = tool.pointer("/function/name").and_then(Value::as_str) {
                            current["function"]["name"] = json!(format!(
                                "{}{}",
                                current
                                    .pointer("/function/name")
                                    .and_then(Value::as_str)
                                    .unwrap_or(""),
                                name
                            ));
                        }
                        if let Some(args) =
                            tool.pointer("/function/arguments").and_then(Value::as_str)
                        {
                            current["function"]["arguments"] = json!(format!(
                                "{}{}",
                                current
                                    .pointer("/function/arguments")
                                    .and_then(Value::as_str)
                                    .unwrap_or(""),
                                args
                            ));
                        }
                    }
                }
            }
        }
        if !pending.trim().is_empty() {
            if let Some(raw) = pending.trim_end_matches('\r').strip_prefix("data:") {
                if let Ok(event) = serde_json::from_str::<Value>(raw.trim()) {
                    if let Some(usage) = event.get("usage") {
                        round_usage = Some(usage.clone());
                    }
                }
            }
        }
        if let Some(error) = stream_error {
            return Err(error);
        }
        if let Some(usage) = round_usage {
            input_tokens += usage
                .get("prompt_tokens")
                .or_else(|| usage.get("input_tokens"))
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .max(0);
            output_tokens += usage
                .get("completion_tokens")
                .or_else(|| usage.get("output_tokens"))
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .max(0);
        }
        let truncated = finish_reason == "length";
        let calls: Vec<Value> = calls
            .into_iter()
            .filter(|call| {
                call.pointer("/function/name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| !name.is_empty())
            })
            .collect();
        if calls.is_empty() {
            return Ok((input_tokens, output_tokens, truncated));
        }
        messages.push(json!({"role":"assistant","content":if round_text.is_empty(){Value::Null}else{json!(round_text)},"tool_calls":calls.clone()}));
        for call in calls {
            let tool_id = call
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("agent-tool-{round}"));
            let name = call
                .pointer("/function/name")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            let args: Value = serde_json::from_str(
                call.pointer("/function/arguments")
                    .and_then(Value::as_str)
                    .unwrap_or("{}"),
            )
            .map_err(|_| "Agent 工具参数无法解析".to_string())?;
            if name != "run_python" {
                return Err(format!("Agent 请求了不支持的工具：{name}"));
            }
            let code = args
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            if code.trim().is_empty() || code.len() > 65_536 {
                return Err("Agent 生成的 Python 代码为空或超过 64 KB".into());
            }
            let timeout = args
                .get("timeout_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(30)
                .clamp(1, 60) as u32;
            let job_id = Uuid::new_v4().to_string();
            if !send_agent_event(
                tx,
                json!({"type":"tool_start","name":name,"code":code,"timeout_seconds":timeout}),
            )
            .await
            {
                return Err("客户端已断开连接".into());
            }
            let execute = s.http.post(format!("{}/execute", s.sandbox_url.trim_end_matches('/')))
                .bearer_auth(s.sandbox_secret.as_str())
                .json(&json!({"job_id":job_id,"user_id":claims.sub,"language":"python","code":code,"timeout_seconds":timeout}))
                .timeout(std::time::Duration::from_secs(75)).send();
            let result = tokio::select! {
                result = execute => result,
                _ = cancellation.notified() => {
                    let _ = s.http.post(format!("{}/cancel/{job_id}", s.sandbox_url.trim_end_matches('/')))
                        .bearer_auth(s.sandbox_secret.as_str())
                        .timeout(std::time::Duration::from_secs(5)).send().await;
                    return Err("客户端已断开连接".into());
                }
            };
            let (exit_code, mut output) = match result {
                Ok(response) => {
                    let status = response.status();
                    let value = response
                        .json::<Value>()
                        .await
                        .unwrap_or_else(|_| json!({"detail":"Agent 沙盒返回无法解析的响应"}));
                    if status.is_success() {
                        (
                            value.get("exit_code").and_then(Value::as_i64).unwrap_or(0),
                            value
                                .get("output")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned(),
                        )
                    } else {
                        (
                            -1,
                            value
                                .get("detail")
                                .and_then(Value::as_str)
                                .unwrap_or("Agent 沙盒执行失败")
                                .to_owned(),
                        )
                    }
                }
                Err(_) => (-1, "Agent 沙盒暂不可用".to_owned()),
            };
            if output.len() > 18_000 {
                output.truncate(18_000);
                output.push_str("\n[工具输出已截断]");
            }
            if !send_agent_event(tx, json!({"type":"tool_result","name":name,"code":code,"output":output,"exit_code":exit_code})).await { return Err("客户端已断开连接".into()); }
            messages.push(json!({"role":"tool","tool_call_id":tool_id,"content":json!({"exit_code":exit_code,"output":output}).to_string()}));
        }
        if round == 7 {
            return Err("Agent 工具执行轮数达到上限，请缩小任务范围后重试".into());
        }
    }
    Err("Agent 执行结束".into())
}

#[derive(Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    username: String,
    role: String,
    department_id: Option<String>,
    #[serde(default)]
    api_key_id: Option<String>,
    exp: usize,
}

#[derive(Deserialize)]
struct LoginInput {
    #[serde(alias = "username")]
    account: String,
    password: String,
    captcha_id: String,
    captcha: String,
}
#[derive(Deserialize)]
struct ForgotPasswordInput {
    account: String,
}
#[derive(Deserialize)]
struct ResetPasswordInput {
    token: String,
    new_password: String,
}
#[derive(Deserialize)]
struct EmailTestInput {
    recipient: String,
}
#[derive(Deserialize)]
struct ApiKeyInput {
    name: String,
    monthly_limit_cents: i64,
}

#[derive(FromRow, Serialize)]
struct Department {
    id: String,
    name: String,
    monthly_limit_cents: i64,
    member_limit_cap_cents: i64,
    created_at: String,
}

#[derive(FromRow, Serialize)]
struct UserRow {
    id: String,
    username: String,
    display_name: String,
    phone: String,
    email: String,
    role: String,
    department_id: Option<String>,
    personal_limit_cents: i64,
    active: i64,
    used: i64,
}

#[derive(FromRow, Serialize)]
struct UsageRow {
    id: String,
    request_id: String,
    username: String,
    display_name: String,
    department_name: Option<String>,
    model: String,
    protocol: String,
    mode: String,
    status: String,
    input_tokens: i64,
    output_tokens: i64,
    cache_tokens: i64,
    cost_micros: i64,
    latency_ms: i64,
    error_code: Option<String>,
    created_at: String,
}

#[derive(FromRow, Serialize)]
struct PriceRow {
    id: String,
    model: String,
    mode: String,
    input_per_million_micros: i64,
    output_per_million_micros: i64,
    cache_per_million_micros: i64,
    night_input_per_million_micros: i64,
    night_output_per_million_micros: i64,
    night_cache_per_million_micros: i64,
    input_image_1k_micros: i64,
    input_image_2k_micros: i64,
    output_image_1k_micros: i64,
    output_image_2k_micros: i64,
    effective_from: String,
    active: i64,
}

#[derive(FromRow, Serialize)]
struct ProtocolRow {
    id: String,
    model: String,
    protocol: String,
    base_url: String,
    upstream_model: String,
    enabled: i64,
}

#[derive(FromRow, Serialize)]
struct ModelRouteRow {
    id: String,
    display_name: String,
    source: String,
    model_key: String,
    upstream_model: String,
    protocol: String,
    endpoint: String,
    billing_mode: String,
    enabled: i64,
    has_credential: bool,
}

fn default_department_limit_cents() -> i64 {
    80_000
}
fn default_member_limit_cents() -> i64 {
    10_000
}
#[derive(Deserialize)]
struct DepartmentInput {
    name: String,
    #[serde(default = "default_department_limit_cents")]
    monthly_limit_cents: i64,
    #[serde(default = "default_member_limit_cents")]
    member_limit_cap_cents: i64,
}
#[derive(Deserialize)]
struct UserInput {
    username: String,
    display_name: String,
    #[serde(default)]
    phone: String,
    #[serde(default)]
    email: String,
    role: String,
    department_id: Option<String>,
    #[serde(default = "default_member_limit_cents")]
    personal_limit_cents: i64,
}
#[derive(Deserialize)]
struct BatchUsersInput {
    users: Vec<UserInput>,
}
#[derive(Deserialize)]
struct LimitInput {
    amount_cents: i64,
}
#[derive(Deserialize)]
struct UserDepartmentInput {
    department_id: String,
}
#[derive(Deserialize)]
struct UserContactInput {
    phone: String,
    email: String,
}
#[derive(Deserialize)]
struct SettingsInput {
    workspace_name: String,
    #[serde(default = "default_time_zone")]
    time_zone: String,
    #[serde(default = "default_department_limit_cents")]
    default_department_limit_cents: i64,
    #[serde(default = "default_member_limit_cents")]
    default_member_limit_cents: i64,
    #[serde(default = "default_expected_users")]
    expected_users: i64,
    #[serde(default = "default_peak_concurrency")]
    peak_concurrency: i64,
    #[serde(default = "default_target_rps")]
    target_rps: i64,
    #[serde(default = "default_latency_target_ms")]
    latency_target_ms: i64,
    #[serde(default)]
    email_smtp_host: String,
    #[serde(default = "default_smtp_port")]
    email_smtp_port: i64,
    #[serde(default)]
    email_smtp_username: String,
    #[serde(default)]
    email_smtp_password: String,
    #[serde(default)]
    email_from_address: String,
    #[serde(default)]
    email_from_name: String,
    #[serde(default)]
    email_smtp_enabled: bool,
    #[serde(default)]
    deepseek_holiday_dates: String,
}
fn default_smtp_port() -> i64 {
    587
}
fn default_expected_users() -> i64 {
    10_000
}
fn default_peak_concurrency() -> i64 {
    100
}
fn default_target_rps() -> i64 {
    100
}
fn default_latency_target_ms() -> i64 {
    10
}
fn default_time_zone() -> String {
    "Asia/Shanghai".to_string()
}
#[derive(Deserialize)]
struct PriceInput {
    model: String,
    mode: String,
    input_per_million_micros: i64,
    output_per_million_micros: i64,
    cache_per_million_micros: i64,
    #[serde(default = "default_input_image_price_micros")]
    input_image_1k_micros: i64,
    #[serde(default = "default_input_image_price_micros")]
    input_image_2k_micros: i64,
    #[serde(default = "default_output_image_price_micros")]
    output_image_1k_micros: i64,
    #[serde(default = "default_output_image_price_micros")]
    output_image_2k_micros: i64,
    effective_from: String,
}
fn default_input_image_price_micros() -> i64 { 20_000 }
fn default_output_image_price_micros() -> i64 { 180_000 }
#[derive(Deserialize)]
struct ProtocolInput {
    model: String,
    protocol: String,
    base_url: String,
    upstream_model: String,
    enabled: bool,
}
#[derive(Deserialize)]
struct ModelRouteInput {
    display_name: String,
    source: String,
    model_key: String,
    upstream_model: String,
    protocol: String,
    endpoint: String,
    billing_mode: String,
    enabled: bool,
    #[serde(default)]
    api_key: Option<String>,
}
#[derive(Deserialize, Default)]
struct UsageFilter {
    department_id: Option<String>,
    status: Option<String>,
    model: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

fn fail(status: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({"error": message})))
}

fn encrypt_credential(key: &[u8; 32], secret: &str) -> anyhow::Result<String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid credentials key"))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), secret.as_bytes())
        .map_err(|_| anyhow::anyhow!("credential encryption failed"))?;
    let mut combined = nonce_bytes.to_vec();
    combined.extend(encrypted);
    Ok(BASE64.encode(combined))
}
fn decrypt_credential(key: &[u8; 32], encoded: &str) -> anyhow::Result<String> {
    let bytes = BASE64.decode(encoded)?;
    anyhow::ensure!(bytes.len() > 12, "invalid encrypted credential");
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid credentials key"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
        .map_err(|_| anyhow::anyhow!("credential decryption failed"))?;
    Ok(String::from_utf8(plain)?)
}

fn actor(headers: &HeaderMap, secret: &str) -> Result<Claims, (StatusCode, Json<Value>)> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "请先登录"))?;
    jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    )
    .map(|d| d.claims)
    .map_err(|_| fail(StatusCode::UNAUTHORIZED, "登录状态无效或已过期"))
}
async fn api_actor(headers: &HeaderMap, s: &AppState) -> Result<Claims, (StatusCode, Json<Value>)> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let raw = bearer
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "请提供平台登录令牌或 API 密钥"))?;
    if !raw.starts_with("lrk_") {
        return actor(headers, &s.jwt_secret);
    }
    let hash = format!("{:x}", Sha256::digest(raw.as_bytes()));
    let row=sqlx::query("SELECT k.id,u.id AS user_id,u.username,u.role,u.department_id FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.key_hash=? AND k.active=1 AND u.active=1").bind(hash).fetch_optional(&s.db).await.map_err(|_|fail(StatusCode::SERVICE_UNAVAILABLE,"API 密钥校验暂不可用"))?.ok_or_else(||fail(StatusCode::UNAUTHORIZED,"API 密钥无效或已撤销"))?;
    let id: String = sqlx::Row::try_get(&row, "id").unwrap_or_default();
    let user_id: String = sqlx::Row::try_get(&row, "user_id").unwrap_or_default();
    let username: String = sqlx::Row::try_get(&row, "username").unwrap_or_default();
    let role: String = sqlx::Row::try_get(&row, "role").unwrap_or_default();
    let department_id: Option<String> = sqlx::Row::try_get(&row, "department_id").unwrap_or(None);
    Ok(Claims {
        sub: user_id,
        username,
        role,
        department_id,
        api_key_id: Some(id),
        exp: (Utc::now().timestamp() + 12 * 3600) as usize,
    })
}
fn hash_api_key(key: &str) -> String {
    format!("{:x}", Sha256::digest(key.as_bytes()))
}

fn resolve_chat_endpoint(endpoint: &str) -> String {
    let base = endpoint.trim().trim_end_matches('/');
    if base.ends_with("/chat/completions") {
        base.to_string()
    } else {
        format!("{base}/chat/completions")
    }
}

fn admin(headers: &HeaderMap, secret: &str) -> Result<Claims, (StatusCode, Json<Value>)> {
    let c = actor(headers, secret)?;
    if c.role != "platform_admin" {
        return Err(fail(StatusCode::FORBIDDEN, "需要平台管理员权限"));
    }
    Ok(c)
}

async fn get_settings(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let me = actor(&headers, &s.jwt_secret)?;
    let rows = sqlx::query("SELECT key,value FROM app_settings ORDER BY key")
        .fetch_all(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "系统设置读取失败"))?;
    let mut settings = serde_json::Map::new();
    for row in rows {
        let key: String = sqlx::Row::try_get(&row, "key").unwrap_or_default();
        let value: String = sqlx::Row::try_get(&row, "value").unwrap_or_default();
        if key != "email_smtp_password"
            && (me.role == "platform_admin" || !key.starts_with("email_"))
        {
            settings.insert(key, Value::String(value));
        }
    }
    if me.role == "platform_admin" {
        let configured = sqlx::query_scalar::<_, Option<String>>(
            "SELECT value FROM app_settings WHERE key='email_smtp_password'",
        )
        .fetch_optional(&s.db)
        .await
        .ok()
        .flatten()
        .flatten()
        .is_some();
        settings.insert("email_smtp_password_configured".into(), json!(configured));
    }
    Ok(Json(Value::Object(settings)))
}
async fn put_settings(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SettingsInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let admin = admin(&headers, &s.jwt_secret)?;
    let name = input.workspace_name.trim();
    let tz = input.time_zone.trim();
    let holiday_dates = input
        .deepseek_holiday_dates
        .lines()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .collect::<Vec<_>>();
    if name.is_empty()
        || name.chars().count() > 80
        || tz != "Asia/Shanghai"
        || input.default_department_limit_cents < 0
        || input.default_department_limit_cents > 100_000_000
        || input.default_member_limit_cents < 0
        || input.default_member_limit_cents > 10_000_000
        || !(1..=10_000_000).contains(&input.expected_users)
        || !(1..=100_000).contains(&input.peak_concurrency)
        || !(1..=1_000_000).contains(&input.target_rps)
        || !(1..=60_000).contains(&input.latency_target_ms)
        || !(1..=65_535).contains(&input.email_smtp_port)
        || input.email_smtp_host.chars().count() > 255
        || input.email_smtp_username.chars().count() > 255
        || input.email_from_address.chars().count() > 254
        || input.email_from_name.chars().count() > 100
        || input.deepseek_holiday_dates.len() > 40_000
        || holiday_dates.len() > 366
        || holiday_dates
            .iter()
            .any(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").is_err())
        || (!input.email_from_address.trim().is_empty()
            && input.email_from_address.trim().parse::<Mailbox>().is_err())
        || (input.email_smtp_enabled
            && (input.email_smtp_host.trim().is_empty()
                || input.email_from_address.trim().is_empty()))
    {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "设置内容无效，请检查工作空间名称、额度和性能目标范围",
        ));
    }
    let values = [
        ("workspace_name", name.to_string()),
        ("time_zone", tz.to_string()),
        (
            "default_department_limit_cents",
            input.default_department_limit_cents.to_string(),
        ),
        (
            "default_member_limit_cents",
            input.default_member_limit_cents.to_string(),
        ),
        ("expected_users", input.expected_users.to_string()),
        ("peak_concurrency", input.peak_concurrency.to_string()),
        ("target_rps", input.target_rps.to_string()),
        ("latency_target_ms", input.latency_target_ms.to_string()),
    ];
    for (key, value) in values {
        sqlx::query("INSERT INTO app_settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP").bind(key).bind(&value).execute(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"系统设置保存失败"))?;
    }
    let smtp_values = [
        ("email_smtp_host", input.email_smtp_host.trim().to_string()),
        ("email_smtp_port", input.email_smtp_port.to_string()),
        (
            "email_smtp_username",
            input.email_smtp_username.trim().to_string(),
        ),
        (
            "email_from_address",
            input.email_from_address.trim().to_string(),
        ),
        ("email_from_name", input.email_from_name.trim().to_string()),
        ("email_smtp_enabled", input.email_smtp_enabled.to_string()),
    ];
    for (key, value) in smtp_values {
        sqlx::query("INSERT INTO app_settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP")
            .bind(key).bind(value).execute(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"邮箱设置保存失败"))?;
    }
    let holiday_dates = holiday_dates.join("\n");
    sqlx::query("INSERT INTO app_settings(key,value,updated_at) VALUES('deepseek_holiday_dates',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP")
        .bind(&holiday_dates).execute(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"节假日配置保存失败"))?;
    if !input.email_smtp_password.trim().is_empty() {
        let encrypted = encrypt_credential(&s.credentials_key, input.email_smtp_password.trim())
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "邮箱密码加密失败"))?;
        sqlx::query("INSERT INTO app_settings(key,value,updated_at) VALUES('email_smtp_password',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP")
            .bind(encrypted).execute(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"邮箱密码保存失败"))?;
    }
    let email_password_configured = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM app_settings WHERE key='email_smtp_password' AND value<>''",
    )
    .fetch_one(&s.db)
    .await
    .unwrap_or(0)
        > 0;
    audit(
        &s.db,
        &admin.sub,
        "settings.update",
        "workspace",
        json!({"workspace_name":name,"time_zone":tz,"default_department_limit_cents":input.default_department_limit_cents,"default_member_limit_cents":input.default_member_limit_cents,"expected_users":input.expected_users,"peak_concurrency":input.peak_concurrency,"target_rps":input.target_rps,"latency_target_ms":input.latency_target_ms,"email_smtp_host":input.email_smtp_host,"email_smtp_port":input.email_smtp_port,"email_smtp_username":input.email_smtp_username,"email_from_address":input.email_from_address,"email_from_name":input.email_from_name,"email_smtp_enabled":input.email_smtp_enabled,"deepseek_holiday_dates":holiday_dates,"email_smtp_password_updated":!input.email_smtp_password.trim().is_empty()}),
    )
    .await;
    Ok(Json(
        json!({"workspace_name":name,"time_zone":tz,"default_department_limit_cents":input.default_department_limit_cents,"default_member_limit_cents":input.default_member_limit_cents,"expected_users":input.expected_users,"peak_concurrency":input.peak_concurrency,"target_rps":input.target_rps,"latency_target_ms":input.latency_target_ms,"email_smtp_host":input.email_smtp_host,"email_smtp_port":input.email_smtp_port,"email_smtp_username":input.email_smtp_username,"email_from_address":input.email_from_address,"email_from_name":input.email_from_name,"email_smtp_enabled":input.email_smtp_enabled,"deepseek_holiday_dates":holiday_dates,"email_smtp_password_configured":email_password_configured}),
    ))
}

async fn email_setting(db: &SqlitePool, key: &str) -> anyhow::Result<String> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT value FROM app_settings WHERE key=?")
            .bind(key)
            .fetch_optional(db)
            .await?
            .unwrap_or_default(),
    )
}

async fn send_system_email(
    s: &AppState,
    recipient: &str,
    subject: &str,
    body: &str,
) -> anyhow::Result<()> {
    let enabled = email_setting(&s.db, "email_smtp_enabled").await? == "true";
    anyhow::ensure!(enabled, "邮件发送未启用");
    let host = email_setting(&s.db, "email_smtp_host").await?;
    let port = email_setting(&s.db, "email_smtp_port")
        .await?
        .parse::<u16>()?;
    let username = email_setting(&s.db, "email_smtp_username").await?;
    let from_address = email_setting(&s.db, "email_from_address").await?;
    let from_name = email_setting(&s.db, "email_from_name").await?;
    let encrypted_password = email_setting(&s.db, "email_smtp_password").await?;
    anyhow::ensure!(
        !host.is_empty() && !from_address.is_empty(),
        "邮箱发送配置不完整"
    );
    let password = if encrypted_password.is_empty() {
        String::new()
    } else {
        decrypt_credential(&s.credentials_key, &encrypted_password)?
    };
    anyhow::ensure!(
        username.is_empty() || !password.is_empty(),
        "SMTP 密码未配置"
    );
    let from: Mailbox = if from_name.trim().is_empty() {
        from_address.parse()?
    } else {
        format!(
            "{} <{}>",
            from_name.replace(['<', '>', '\r', '\n'], ""),
            from_address
        )
        .parse()?
    };
    let to: Mailbox = recipient.parse()?;
    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .body(body.to_string())?;
    let mut transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)?
        .port(port)
        .timeout(Some(std::time::Duration::from_secs(20)));
    if !username.is_empty() {
        transport = transport.credentials(Credentials::new(username, password));
    }
    transport.build().send(message).await?;
    Ok(())
}

async fn test_email_settings(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<EmailTestInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let admin = admin(&headers, &s.jwt_secret)?;
    let recipient = input.recipient.trim();
    if recipient.parse::<Mailbox>().is_err() {
        return Err(fail(StatusCode::BAD_REQUEST, "请输入有效的收件邮箱"));
    }
    send_system_email(
        &s,
        recipient,
        "汇智 AI Gateway 邮件配置测试",
        "这是一封系统邮件发送测试。如果你收到此邮件，邮箱发送设置已生效。",
    )
    .await
    .map_err(|e| {
        tracing::error!(error=%e, "SMTP test email failed");
        fail(
            StatusCode::BAD_GATEWAY,
            "邮件发送失败，请检查 SMTP 配置和服务商日志",
        )
    })?;
    audit(
        &s.db,
        &admin.sub,
        "settings.email_test",
        recipient,
        json!({"ok":true}),
    )
    .await;
    Ok(Json(json!({"ok":true})))
}

async fn forgot_password(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ForgotPasswordInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let generic = || Json(json!({"message":"如果账号和邮箱匹配，重置链接将发送到账号绑定邮箱。"}));
    let account = input.account.trim();
    if account.is_empty() || account.chars().count() > 254 {
        return Ok(generic());
    }
    let row = sqlx::query("SELECT id,email FROM users WHERE active=1 AND (username=? COLLATE NOCASE OR email=? COLLATE NOCASE) LIMIT 1")
        .bind(account).bind(account).fetch_optional(&s.db).await
        .map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"密码重置请求暂不可用"))?;
    let Some(row) = row else {
        return Ok(generic());
    };
    let user_id: String = sqlx::Row::try_get(&row, "id").unwrap_or_default();
    let email: String = sqlx::Row::try_get(&row, "email").unwrap_or_default();
    if email.is_empty() || email.parse::<Mailbox>().is_err() {
        return Ok(generic());
    }
    let recent = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM password_reset_tokens WHERE user_id=? AND created_at > datetime('now','-1 minute')")
        .bind(&user_id).fetch_one(&s.db).await.unwrap_or(0);
    if recent > 0 {
        return Ok(generic());
    }
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let token_id = Uuid::new_v4().to_string();
    let expires = (Utc::now() + chrono::Duration::minutes(30))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    sqlx::query("UPDATE password_reset_tokens SET used_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE user_id=? AND used_at IS NULL")
        .bind(&user_id).execute(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"密码重置请求暂不可用"))?;
    sqlx::query(
        "INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)",
    )
    .bind(&token_id)
    .bind(&user_id)
    .bind(&token_hash)
    .bind(&expires)
    .execute(&s.db)
    .await
    .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "密码重置请求暂不可用"))?;
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:7900");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");
    let base = env::var("PUBLIC_BASE_URL")
        .unwrap_or_else(|_| format!("{}://{}", scheme, host))
        .trim_end_matches('/')
        .to_string();
    let link = format!("{}/?reset_token={}", base, token);
    let body = format!(
        "您好，\n\n请通过下面的链接设置新密码。链接将在 30 分钟后失效，且只能使用一次：\n{}\n\n如果这不是你发起的请求，请忽略此邮件。",
        link
    );
    if let Err(e) = send_system_email(&s, &email, "汇智 AI Gateway 密码重置", &body).await {
        tracing::error!(error=%e, "password reset email failed");
        let _ = sqlx::query("DELETE FROM password_reset_tokens WHERE id=?")
            .bind(&token_id)
            .execute(&s.db)
            .await;
    }
    Ok(generic())
}

async fn reset_password(
    State(s): State<AppState>,
    Json(input): Json<ResetPasswordInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if input.new_password.chars().count() < 12 || input.new_password.chars().count() > 128 {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "新密码长度需为 12 至 128 个字符",
        ));
    }
    let token_hash = format!("{:x}", Sha256::digest(input.token.trim().as_bytes()));
    let mut tx =
        s.db.begin()
            .await
            .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "密码重置暂不可用"))?;
    let row = sqlx::query("SELECT id,user_id FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at > strftime('%Y-%m-%dT%H:%M:%SZ','now')")
        .bind(&token_hash).fetch_optional(&mut *tx).await.map_err(|_|fail(StatusCode::SERVICE_UNAVAILABLE,"密码重置暂不可用"))?
        .ok_or_else(||fail(StatusCode::BAD_REQUEST,"重置链接无效或已过期，请重新申请"))?;
    let token_id: String = sqlx::Row::try_get(&row, "id").unwrap_or_default();
    let user_id: String = sqlx::Row::try_get(&row, "user_id").unwrap_or_default();
    let updated = sqlx::query("UPDATE password_reset_tokens SET used_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=? AND used_at IS NULL")
        .bind(&token_id).execute(&mut *tx).await.map_err(|_|fail(StatusCode::SERVICE_UNAVAILABLE,"密码重置暂不可用"))?;
    if updated.rows_affected() != 1 {
        return Err(fail(StatusCode::BAD_REQUEST, "重置链接无效或已使用"));
    }
    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let password_hash = argon2::Argon2::default()
        .hash_password(input.new_password.as_bytes(), &salt)
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "新密码设置失败"))?
        .to_string();
    sqlx::query("UPDATE users SET password_hash=? WHERE id=? AND active=1")
        .bind(password_hash)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "新密码设置失败"))?;
    sqlx::query("UPDATE password_reset_tokens SET used_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE user_id=? AND used_at IS NULL").bind(&user_id).execute(&mut *tx).await.ok();
    tx.commit()
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "新密码设置失败"))?;
    audit(
        &s.db,
        &user_id,
        "user.password_reset",
        "self",
        json!({"method":"email"}),
    )
    .await;
    Ok(Json(json!({"message":"密码已重置，请使用新密码登录。"})))
}

async fn health(State(s): State<AppState>) -> Json<Value> {
    let redis_ok = if let Some(mut c) = s.redis.clone() {
        redis::cmd("PING")
            .query_async::<String>(&mut c)
            .await
            .is_ok()
    } else {
        false
    };
    Json(
        json!({"status":"ok","database":"connected","redis":if redis_ok {"connected"} else {"unavailable"},"time":Utc::now()}),
    )
}

fn login_bucket_key(scope: &str, value: &str) -> String {
    format!("auth:{}:{:x}", scope, Sha256::digest(value.as_bytes()))
}

async fn consume_login_attempt(
    db: &SqlitePool,
    key: &str,
    limit: i64,
    now: i64,
) -> Result<bool, (StatusCode, Json<Value>)> {
    if now % 300 == 0 {
        let _ = sqlx::query("DELETE FROM auth_rate_limits WHERE window_started_at < ?")
            .bind(now - 86_400)
            .execute(db)
            .await;
    }
    let row = sqlx::query_as::<_, (i64, i64)>(
        "INSERT INTO auth_rate_limits(bucket_key,attempts,window_started_at,blocked_until) VALUES(?,1,?,0) \
         ON CONFLICT(bucket_key) DO UPDATE SET \
           attempts=CASE WHEN blocked_until>? THEN attempts WHEN window_started_at<=? THEN 1 ELSE attempts+1 END, \
           window_started_at=CASE WHEN blocked_until>? THEN window_started_at WHEN window_started_at<=? THEN ? WHEN attempts+1>? THEN ? ELSE window_started_at END, \
           blocked_until=CASE WHEN blocked_until>? THEN blocked_until WHEN window_started_at<=? THEN 0 WHEN attempts+1>? THEN ?+900 ELSE 0 END \
         RETURNING attempts,blocked_until",
    )
    .bind(key).bind(now)
    .bind(now).bind(now-900)
    .bind(now).bind(now-900).bind(now).bind(limit)
    .bind(now)
    .bind(now).bind(now-900).bind(limit).bind(now)
    .fetch_one(db).await
    .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE,"登录保护暂不可用，请稍后重试"))?;
    Ok(row.1 > now)
}

async fn login_captcha(
    State(s): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let now = Utc::now().timestamp();
    let ip_key = login_bucket_key("captcha_ip", &remote.ip().to_string());
    if consume_login_attempt(&s.db, &ip_key, 60, now).await? {
        return Err(fail(StatusCode::TOO_MANY_REQUESTS, "验证码请求过多，请稍后重试"));
    }

    let id = Uuid::new_v4().to_string();
    let alphabet = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut random = [0u8; 5];
    OsRng.fill_bytes(&mut random);
    let answer: String = random
        .iter()
        .map(|byte| alphabet[(byte & 31) as usize] as char)
        .collect();
    let answer_hash = format!("{:x}", Sha256::digest(format!("{id}:{answer}").as_bytes()));
    sqlx::query("DELETE FROM login_captcha_challenges WHERE expires_at<=?")
        .bind(now)
        .execute(&s.db)
        .await
        .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "验证码服务暂不可用"))?;
    sqlx::query("INSERT INTO login_captcha_challenges(captcha_id,answer_hash,expires_at) VALUES(?,?,?)")
        .bind(&id)
        .bind(answer_hash)
        .bind(now + 300)
        .execute(&s.db)
        .await
        .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "验证码服务暂不可用"))?;

    let mut svg = String::from("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"160\" height=\"54\" viewBox=\"0 0 160 54\"><rect width=\"160\" height=\"54\" rx=\"7\" fill=\"#f4f6fb\"/>");
    for i in 0..7 {
        let x1 = (random[i % 5] as usize * 7 + i * 19) % 160;
        let y1 = (random[(i + 1) % 5] as usize * 3 + i * 11) % 54;
        let x2 = (random[(i + 2) % 5] as usize * 5 + i * 23) % 160;
        let y2 = (random[(i + 3) % 5] as usize * 9 + i * 5) % 54;
        svg.push_str(&format!("<path d=\"M{x1} {y1} L{x2} {y2}\" stroke=\"#cbd2e0\" stroke-width=\"1\"/>"));
    }
    let colors = ["#526be0", "#a05cb4", "#278b78", "#c36a47", "#48566b"];
    for (index, ch) in answer.chars().enumerate() {
        let x = 17 + index * 29;
        let y = 37 + (random[index] as i32 % 7) - 3;
        let angle = (random[(index + 1) % 5] as i32 % 25) - 12;
        svg.push_str(&format!("<text x=\"{x}\" y=\"{y}\" transform=\"rotate({angle} {x} {y})\" font-family=\"Arial,sans-serif\" font-size=\"29\" font-weight=\"700\" fill=\"{}\">{ch}</text>", colors[index]));
    }
    svg.push_str("</svg>");
    let image = format!("data:image/svg+xml;base64,{}", BASE64.encode(svg.as_bytes()));
    Ok(Json(json!({"captcha_id":id,"image":image,"expires_in":300})))
}

async fn consume_login_captcha(
    db: &SqlitePool,
    id: &str,
    answer: &str,
    now: i64,
) -> Result<bool, (StatusCode, Json<Value>)> {
    let row = sqlx::query_as::<_, (String, i64)>(
        "DELETE FROM login_captcha_challenges WHERE captcha_id=? RETURNING answer_hash,expires_at",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "验证码校验暂不可用"))?;
    let Some((expected_hash, expires_at)) = row else {
        return Ok(false);
    };
    let supplied_hash = format!("{:x}", Sha256::digest(format!("{id}:{}", answer.trim().to_ascii_uppercase()).as_bytes()));
    Ok(expires_at > now && expected_hash == supplied_hash)
}

async fn login(
    State(s): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(input): Json<LoginInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let account = input.account.trim();
    if account.is_empty()
        || account.len() > 254
        || input.password.is_empty()
        || input.password.len() > 1024
    {
        return Err(fail(StatusCode::UNAUTHORIZED, "账号或密码错误"));
    }
    let now = Utc::now().timestamp();
    let account_key = login_bucket_key("account", &account.to_lowercase());
    let ip_key = login_bucket_key("ip", &remote.ip().to_string());
    if consume_login_attempt(&s.db, &account_key, 5, now).await?
        || consume_login_attempt(&s.db, &ip_key, 300, now).await?
    {
        return Err(fail(
            StatusCode::TOO_MANY_REQUESTS,
            "登录尝试过多，请 15 分钟后重试",
        ));
    }
    if !consume_login_captcha(&s.db, &input.captcha_id, &input.captcha, now).await? {
        return Err(fail(StatusCode::UNAUTHORIZED, "验证码错误或已过期，请刷新验证码"));
    }
    let row = sqlx::query("SELECT id,username,display_name,password_hash,role,department_id,active FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE ORDER BY CASE WHEN username=? COLLATE NOCASE THEN 0 ELSE 1 END LIMIT 1")
        .bind(account).bind(account).bind(account).fetch_optional(&s.db).await.map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR,"账号查询失败"))?;
    let Some(row) = row else {
        return Err(fail(StatusCode::UNAUTHORIZED, "账号或密码错误"));
    };
    let id: String = sqlx::Row::try_get(&row, "id").unwrap_or_default();
    let username: String = sqlx::Row::try_get(&row, "username").unwrap_or_default();
    let name: String = sqlx::Row::try_get(&row, "display_name").unwrap_or_default();
    let hash: String = sqlx::Row::try_get(&row, "password_hash").unwrap_or_default();
    let role: String = sqlx::Row::try_get(&row, "role").unwrap_or_default();
    let department_id: Option<String> = sqlx::Row::try_get(&row, "department_id").unwrap_or(None);
    let active: i64 = sqlx::Row::try_get(&row, "active").unwrap_or(0);
    let valid = if hash == "dev-placeholder" {
        input.password == env::var("DEV_PASSWORD").unwrap_or_default()
    } else {
        argon2::Argon2::default()
            .verify_password(
                input.password.as_bytes(),
                &argon2::password_hash::PasswordHash::new(&hash)
                    .map_err(|_| fail(StatusCode::UNAUTHORIZED, "账号或密码错误"))?,
            )
            .is_ok()
    };
    if active == 0 || !valid {
        return Err(fail(StatusCode::UNAUTHORIZED, "账号或密码错误"));
    }
    let _ = sqlx::query("DELETE FROM auth_rate_limits WHERE bucket_key IN (?,?)")
        .bind(&account_key)
        .bind(&ip_key)
        .execute(&s.db)
        .await;
    let claims = Claims {
        sub: id.clone(),
        username: username.clone(),
        role: role.clone(),
        department_id: department_id.clone(),
        api_key_id: None,
        exp: (Utc::now().timestamp() + 12 * 3600) as usize,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(s.jwt_secret.as_bytes()),
    )
    .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "无法创建会话"))?;
    Ok(Json(
        json!({"token":token,"user":{"id":id,"username":username,"display_name":name,"role":role,"department_id":department_id}}),
    ))
}

fn apply_usage_scope<'a>(query: &mut sqlx::QueryBuilder<'a, sqlx::Sqlite>, me: &'a Claims) {
    if me.role == "department_admin" {
        query
            .push(" AND department_id=")
            .push_bind(me.department_id.as_deref().unwrap_or(""));
    } else if me.role != "platform_admin" {
        query.push(" AND user_id=").push_bind(&me.sub);
    }
}

async fn dashboard(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let me = actor(&headers, &s.jwt_secret)?;
    let month = Utc::now().format("%Y-%m").to_string();
    let mut summary = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT COUNT(*),COALESCE(SUM(CASE WHEN status='success' THEN cost_micros ELSE 0 END),0),SUM(CASE WHEN status!='success' THEN 1 ELSE 0 END),COALESCE(AVG(CASE WHEN status='success' THEN latency_ms END),0) FROM usage_records WHERE substr(created_at,1,7)=",
    );
    summary.push_bind(&month);
    apply_usage_scope(&mut summary, &me);
    let (calls, spend, errors, average_latency): (i64, i64, i64, f64) = summary
        .build_query_as()
        .fetch_one(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "统计数据读取失败"))?;
    let (departments, users): (i64, i64) = if me.role == "platform_admin" {
        (
            sqlx::query_scalar("SELECT COUNT(*) FROM departments")
                .fetch_one(&s.db)
                .await
                .unwrap_or(0),
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE active=1")
                .fetch_one(&s.db)
                .await
                .unwrap_or(0),
        )
    } else if let Some(dep) = me.department_id.as_deref() {
        (
            sqlx::query_scalar("SELECT COUNT(*) FROM departments WHERE id=?")
                .bind(dep)
                .fetch_one(&s.db)
                .await
                .unwrap_or(0),
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE active=1 AND department_id=?")
                .bind(dep)
                .fetch_one(&s.db)
                .await
                .unwrap_or(0),
        )
    } else {
        (0, 1)
    };
    let dep_rows = sqlx::query_as::<_, Department>("SELECT * FROM departments ORDER BY name")
        .fetch_all(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "部门查询失败"))?;
    let mut dep_view = Vec::new();
    for d in dep_rows {
        if me.role != "platform_admin" && me.department_id.as_deref() != Some(d.id.as_str()) {
            continue;
        }
        let used:i64=sqlx::query_scalar("SELECT COALESCE(SUM(cost_micros),0) FROM usage_records WHERE department_id=? AND substr(created_at,1,7)=? AND status='success'").bind(&d.id).bind(&month).fetch_one(&s.db).await.unwrap_or(0);
        let member_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE department_id=? AND active=1")
                .bind(&d.id)
                .fetch_one(&s.db)
                .await
                .unwrap_or(0);
        dep_view.push(json!({"id":d.id,"name":d.name,"monthly_limit_cents":d.monthly_limit_cents,"used_micros":used,"member_limit_cap_cents":d.member_limit_cap_cents,"member_count":member_count}));
    }
    let since = (Utc::now() - chrono::Duration::days(6))
        .format("%Y-%m-%d")
        .to_string();
    let mut trend_query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT substr(created_at,1,10) AS day,COALESCE(SUM(cost_micros),0) AS spend_micros,COUNT(*) AS calls FROM usage_records WHERE created_at>=",
    );
    trend_query.push_bind(&since).push(" AND status='success'");
    apply_usage_scope(&mut trend_query, &me);
    trend_query.push(" GROUP BY substr(created_at,1,10) ORDER BY day");
    let trend_rows = trend_query
        .build()
        .fetch_all(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "费用趋势读取失败"))?;
    let trend:Vec<Value>=trend_rows.iter().map(|r|json!({"day":sqlx::Row::try_get::<String,_>(r,"day").unwrap_or_default(),"spend_micros":sqlx::Row::try_get::<i64,_>(r,"spend_micros").unwrap_or(0),"calls":sqlx::Row::try_get::<i64,_>(r,"calls").unwrap_or(0)})).collect();
    let mut model_query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT model,COALESCE(SUM(cost_micros),0) AS spend_micros,COUNT(*) AS calls FROM usage_records WHERE substr(created_at,1,7)=",
    );
    model_query.push_bind(&month).push(" AND status='success'");
    apply_usage_scope(&mut model_query, &me);
    model_query.push(" GROUP BY model ORDER BY spend_micros DESC");
    let model_rows = model_query
        .build()
        .fetch_all(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "模型统计读取失败"))?;
    let model_usage:Vec<Value>=model_rows.iter().map(|r|json!({"model":sqlx::Row::try_get::<String,_>(r,"model").unwrap_or_default(),"spend_micros":sqlx::Row::try_get::<i64,_>(r,"spend_micros").unwrap_or(0),"calls":sqlx::Row::try_get::<i64,_>(r,"calls").unwrap_or(0)})).collect();
    Ok(Json(
        json!({"month":month,"department_count":departments,"user_count":users,"call_count":calls,"spend_micros":spend,"error_count":errors,"average_latency_ms":average_latency,"departments":dep_view,"trend":trend,"model_usage":model_usage}),
    ))
}

async fn departments(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Value>>, (StatusCode, Json<Value>)> {
    let me = actor(&headers, &s.jwt_secret)?;
    let rows = sqlx::query_as::<_, Department>("SELECT * FROM departments ORDER BY name")
        .fetch_all(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "部门查询失败"))?;
    let month = Utc::now().format("%Y-%m").to_string();
    let mut out = Vec::new();
    for d in rows {
        if me.role != "platform_admin" && me.department_id.as_deref() != Some(d.id.as_str()) {
            continue;
        }
        let used:i64=sqlx::query_scalar("SELECT COALESCE(SUM(cost_micros),0) FROM usage_records WHERE department_id=? AND substr(created_at,1,7)=? AND status='success'").bind(&d.id).bind(&month).fetch_one(&s.db).await.unwrap_or(0);
        let member_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE department_id=? AND active=1")
                .bind(&d.id)
                .fetch_one(&s.db)
                .await
                .unwrap_or(0);
        out.push(json!({"id":d.id,"name":d.name,"monthly_limit_cents":d.monthly_limit_cents,"member_limit_cap_cents":d.member_limit_cap_cents,"used_micros":used,"member_count":member_count,"created_at":d.created_at}));
    }
    Ok(Json(out))
}

async fn add_department(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(i): Json<DepartmentInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let a = admin(&headers, &s.jwt_secret)?;
    if i.name.trim().is_empty() || i.monthly_limit_cents < 0 || i.member_limit_cap_cents < 0 {
        return Err(fail(StatusCode::BAD_REQUEST, "请检查部门名称和额度"));
    }
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO departments(id,name,monthly_limit_cents,member_limit_cap_cents) VALUES(?,?,?,?)").bind(&id).bind(i.name.trim()).bind(i.monthly_limit_cents).bind(i.member_limit_cap_cents).execute(&s.db).await.map_err(|_|fail(StatusCode::CONFLICT,"部门名称已存在或保存失败"))?;
    audit(
        &s.db,
        &a.sub,
        "department.create",
        &id,
        json!({"name":i.name}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(json!({"id":id}))))
}
async fn update_department(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(i): Json<DepartmentInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let a = admin(&headers, &s.jwt_secret)?;
    if i.name.trim().is_empty() || i.monthly_limit_cents < 0 || i.member_limit_cap_cents < 0 {
        return Err(fail(StatusCode::BAD_REQUEST, "请检查部门名称和额度"));
    }
    let old = sqlx::query(
        "SELECT name,monthly_limit_cents,member_limit_cap_cents FROM departments WHERE id=?",
    )
    .bind(&id)
    .fetch_optional(&s.db)
    .await
    .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "部门查询失败"))?
    .ok_or_else(|| fail(StatusCode::NOT_FOUND, "部门不存在"))?;
    let before = json!({"name":sqlx::Row::try_get::<String,_>(&old,"name").unwrap_or_default(),"monthly_limit_cents":sqlx::Row::try_get::<i64,_>(&old,"monthly_limit_cents").unwrap_or(0),"member_limit_cap_cents":sqlx::Row::try_get::<i64,_>(&old,"member_limit_cap_cents").unwrap_or(0)});
    sqlx::query(
        "UPDATE departments SET name=?,monthly_limit_cents=?,member_limit_cap_cents=? WHERE id=?",
    )
    .bind(i.name.trim())
    .bind(i.monthly_limit_cents)
    .bind(i.member_limit_cap_cents)
    .bind(&id)
    .execute(&s.db)
    .await
    .map_err(|_| fail(StatusCode::CONFLICT, "部门名称已存在或保存失败"))?;
    audit(&s.db,&a.sub,"department.update",&id,json!({"before":before,"after":{"name":i.name,"monthly_limit_cents":i.monthly_limit_cents,"member_limit_cap_cents":i.member_limit_cap_cents}})).await;
    Ok(Json(json!({"ok":true})))
}
async fn users(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserRow>>, (StatusCode, Json<Value>)> {
    let me = actor(&headers, &s.jwt_secret)?;
    let month = Utc::now().format("%Y-%m").to_string();
    let rows=sqlx::query_as::<_,UserRow>("SELECT u.id,u.username,u.display_name,u.phone,u.email,u.role,u.department_id,u.personal_limit_cents,u.active,COALESCE((SELECT SUM(r.cost_micros) FROM usage_records r WHERE r.user_id=u.id AND r.status='success' AND substr(r.created_at,1,7)=?),0) AS used FROM users u ORDER BY u.display_name").bind(&month).fetch_all(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"用户查询失败"))?;
    if me.role == "platform_admin" {
        Ok(Json(rows))
    } else if me.role == "department_admin" {
        Ok(Json(
            rows.into_iter()
                .filter(|u| u.department_id == me.department_id || u.id == me.sub)
                .collect(),
        ))
    } else {
        Ok(Json(rows.into_iter().filter(|u| u.id == me.sub).collect()))
    }
}
async fn add_user(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(i): Json<UserInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let a = admin(&headers, &s.jwt_secret)?;
    if !["department_admin", "user"].contains(&i.role.as_str())
        || i.personal_limit_cents < 0
        || i.username.trim().is_empty()
        || i.display_name.trim().is_empty()
        || i.phone.chars().count() > 24
        || i.email.chars().count() > 254
        || (!i.email.trim().is_empty() && i.email.trim().parse::<Mailbox>().is_err())
        || i.phone
            .chars()
            .any(|c| !(c.is_ascii_digit() || matches!(c, '+' | ' ' | '-' | '(' | ')')))
    {
        return Err(fail(StatusCode::BAD_REQUEST, "用户信息或额度无效"));
    }
    let department_id = i.department_id.as_deref().unwrap_or("").trim();
    if department_id.is_empty()
        || sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM departments WHERE id=?")
            .bind(department_id)
            .fetch_one(&s.db)
            .await
            .unwrap_or(0)
            == 0
    {
        return Err(fail(StatusCode::BAD_REQUEST, "请选择有效的所属部门"));
    }
    let id = Uuid::new_v4().to_string();
    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let password_hash = argon2::Argon2::default()
        .hash_password(
            env::var("INITIAL_USER_PASSWORD")
                .unwrap_or_default()
                .as_bytes(),
            &salt,
        )
        .unwrap()
        .to_string();
    let email = i.email.trim().to_ascii_lowercase();
    sqlx::query("INSERT INTO users(id,username,display_name,phone,email,password_hash,role,department_id,personal_limit_cents) VALUES(?,?,?,?,?,?,?,?,?)").bind(&id).bind(i.username.trim()).bind(i.display_name.trim()).bind(i.phone.trim()).bind(&email).bind(password_hash).bind(&i.role).bind(department_id).bind(i.personal_limit_cents).execute(&s.db).await.map_err(|_|fail(StatusCode::CONFLICT,"用户名、手机号或邮箱已存在，或保存失败"))?;
    audit(
        &s.db,
        &a.sub,
        "user.create",
        &id,
        json!({"username":i.username,"role":i.role}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":id,"initial_password":"已由 INITIAL_USER_PASSWORD 配置"})),
    ))
}
async fn add_users_batch(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BatchUsersInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let admin = admin(&headers, &s.jwt_secret)?;
    if input.users.is_empty() || input.users.len() > 500 {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "批量导入需包含 1 至 500 名成员",
        ));
    }
    let mut results = Vec::with_capacity(input.users.len());
    for (index, i) in input.users.into_iter().enumerate() {
        let username = i.username.trim();
        let display_name = i.display_name.trim();
        let phone = i.phone.trim();
        let email = i.email.trim().to_ascii_lowercase();
        let department_id = i.department_id.as_deref().unwrap_or("").trim();
        let invalid = if username.is_empty() || display_name.is_empty() {
            Some("姓名和账号不能为空")
        } else if phone.chars().count() > 24
            || phone
                .chars()
                .any(|c| !(c.is_ascii_digit() || matches!(c, '+' | ' ' | '-' | '(' | ')')))
        {
            Some("手机号格式无效")
        } else if email.chars().count() > 254
            || (!email.is_empty() && email.parse::<Mailbox>().is_err())
        {
            Some("邮箱格式无效")
        } else if !["department_admin", "user"].contains(&i.role.as_str())
            || i.personal_limit_cents < 0
        {
            Some("角色或个人额度无效")
        } else if department_id.is_empty() {
            Some("所属部门不能为空")
        } else if sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM departments WHERE id=?")
            .bind(department_id)
            .fetch_one(&s.db)
            .await
            .unwrap_or(0)
            == 0
        {
            Some("所属部门不存在")
        } else {
            None
        };
        if let Some(error) = invalid {
            results.push(json!({"row":index+2,"username":username,"ok":false,"message":error}));
            continue;
        }
        let id = Uuid::new_v4().to_string();
        let salt = argon2::password_hash::SaltString::generate(
            &mut argon2::password_hash::rand_core::OsRng,
        );
        let hash = argon2::Argon2::default()
            .hash_password(
                env::var("INITIAL_USER_PASSWORD")
                    .unwrap_or_default()
                    .as_bytes(),
                &salt,
            )
            .unwrap()
            .to_string();
        let result=sqlx::query("INSERT INTO users(id,username,display_name,phone,email,password_hash,role,department_id,personal_limit_cents) VALUES(?,?,?,?,?,?,?,?,?)").bind(&id).bind(username).bind(display_name).bind(phone).bind(email).bind(hash).bind(&i.role).bind(department_id).bind(i.personal_limit_cents).execute(&s.db).await;
        match result {
            Ok(_) => {
                audit(
                    &s.db,
                    &admin.sub,
                    "user.create.batch",
                    &id,
                    json!({"username":username,"role":i.role,"department_id":department_id}),
                )
                .await;
                results.push(
                    json!({"row":index+2,"username":username,"ok":true,"message":"导入成功"}),
                );
            }
            Err(e) => {
                let message = if e.to_string().contains("users.phone") {
                    "手机号已存在"
                } else if e.to_string().contains("users.email") {
                    "邮箱已存在"
                } else {
                    "账号已存在或保存失败"
                };
                results
                    .push(json!({"row":index+2,"username":username,"ok":false,"message":message}));
            }
        }
    }
    Ok(Json(
        json!({"results":results,"succeeded":results.iter().filter(|x|x["ok"]==true).count(),"failed":results.iter().filter(|x|x["ok"]==false).count()}),
    ))
}

async fn set_user_limit(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(i): Json<LimitInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let a = actor(&headers, &s.jwt_secret)?;
    if i.amount_cents < 0 {
        return Err(fail(StatusCode::BAD_REQUEST, "额度不能为负数"));
    }
    let u = sqlx::query("SELECT department_id FROM users WHERE id=?")
        .bind(&id)
        .fetch_optional(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "用户查询失败"))?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "用户不存在"))?;
    let dep: Option<String> = sqlx::Row::try_get(&u, "department_id").unwrap_or(None);
    if a.role == "department_admin" {
        if dep != a.department_id {
            return Err(fail(StatusCode::FORBIDDEN, "只能调整本部门成员"));
        }
        let cap: i64 =
            sqlx::query_scalar("SELECT member_limit_cap_cents FROM departments WHERE id=?")
                .bind(dep)
                .fetch_one(&s.db)
                .await
                .unwrap_or(0);
        if i.amount_cents > cap {
            return Err(fail(StatusCode::BAD_REQUEST, "额度超过本部门配置上限"));
        }
    } else if a.role != "platform_admin" {
        return Err(fail(StatusCode::FORBIDDEN, "无权调整额度"));
    }
    let before: i64 = sqlx::query_scalar("SELECT personal_limit_cents FROM users WHERE id=?")
        .bind(&id)
        .fetch_one(&s.db)
        .await
        .unwrap_or(0);
    sqlx::query("UPDATE users SET personal_limit_cents=? WHERE id=?")
        .bind(i.amount_cents)
        .bind(&id)
        .execute(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "额度保存失败"))?;
    audit(
        &s.db,
        &a.sub,
        "user.limit.update",
        &id,
        json!({"before_cents":before,"after_cents":i.amount_cents}),
    )
    .await;
    Ok(Json(json!({"ok":true})))
}
async fn set_user_department(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(input): Json<UserDepartmentInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let admin = admin(&headers, &s.jwt_secret)?;
    let department_id = input.department_id.trim();
    let user = sqlx::query("SELECT department_id,personal_limit_cents,role FROM users WHERE id=?")
        .bind(&id)
        .fetch_optional(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "成员查询失败"))?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "成员不存在"))?;
    let old_department: Option<String> = sqlx::Row::try_get(&user, "department_id").unwrap_or(None);
    let limit: i64 = sqlx::Row::try_get(&user, "personal_limit_cents").unwrap_or(0);
    let role: String = sqlx::Row::try_get(&user, "role").unwrap_or_default();
    if role == "platform_admin" {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "系统管理员账号不支持调整所属部门",
        ));
    }
    let department = sqlx::query("SELECT name,member_limit_cap_cents FROM departments WHERE id=?")
        .bind(department_id)
        .fetch_optional(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "部门查询失败"))?
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "目标部门不存在"))?;
    let cap: i64 = sqlx::Row::try_get(&department, "member_limit_cap_cents").unwrap_or(0);
    if limit > cap {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "成员当前个人额度超过目标部门上限，请先调整额度后再变更所属部门",
        ));
    }
    sqlx::query("UPDATE users SET department_id=? WHERE id=?")
        .bind(department_id)
        .bind(&id)
        .execute(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "成员部门更新失败"))?;
    let name: String = sqlx::Row::try_get(&department, "name").unwrap_or_default();
    audit(&s.db,&admin.sub,"user.department.update",&id,json!({"before_department_id":old_department,"after_department_id":department_id,"after_department_name":name})).await;
    Ok(Json(
        json!({"ok":true,"department_id":department_id,"department_name":name}),
    ))
}

async fn update_user_contact(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(input): Json<UserContactInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let admin = admin(&headers, &s.jwt_secret)?;
    let phone = input.phone.trim();
    let email = input.email.trim().to_ascii_lowercase();
    if phone.chars().count() > 24
        || phone
            .chars()
            .any(|c| !(c.is_ascii_digit() || matches!(c, '+' | ' ' | '-' | '(' | ')')))
        || email.chars().count() > 254
        || (!email.is_empty() && email.parse::<Mailbox>().is_err())
    {
        return Err(fail(StatusCode::BAD_REQUEST, "手机号或邮箱格式无效"));
    }
    let old = sqlx::query("SELECT phone,email FROM users WHERE id=?")
        .bind(&id)
        .fetch_optional(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "成员查询失败"))?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "成员不存在"))?;
    let before = json!({"phone":sqlx::Row::try_get::<String,_>(&old,"phone").unwrap_or_default(),"email":sqlx::Row::try_get::<String,_>(&old,"email").unwrap_or_default()});
    sqlx::query("UPDATE users SET phone=?,email=? WHERE id=?")
        .bind(phone)
        .bind(&email)
        .bind(&id)
        .execute(&s.db)
        .await
        .map_err(|_| fail(StatusCode::CONFLICT, "手机号或邮箱已被其他成员使用"))?;
    audit(
        &s.db,
        &admin.sub,
        "user.contact.update",
        &id,
        json!({"before":before,"after":{"phone":phone,"email":email}}),
    )
    .await;
    Ok(Json(json!({"ok":true})))
}

async fn list_api_keys(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Value>>, (StatusCode, Json<Value>)> {
    let me = actor(&headers, &s.jwt_secret)?;
    let (month_start, month_end, _) = billing_window(Utc::now());
    let rows=sqlx::query("SELECT k.id,k.name,k.key_prefix,k.monthly_limit_cents,k.active,k.created_at,COALESCE((SELECT MAX(ur.created_at) FROM usage_records ur WHERE ur.api_key_id=k.id),k.last_used_at) AS last_used_at,COALESCE(SUM(CASE WHEN r.status='success' THEN r.cost_micros ELSE 0 END),0) AS used_micros,COUNT(r.id) AS call_count,COALESCE(SUM(r.input_tokens),0) AS input_tokens,COALESCE(SUM(r.output_tokens),0) AS output_tokens FROM api_keys k LEFT JOIN usage_records r ON r.api_key_id=k.id AND r.created_at>=? AND r.created_at<? WHERE k.user_id=? GROUP BY k.id ORDER BY k.created_at DESC").bind(month_start).bind(month_end).bind(&me.sub).fetch_all(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"API 密钥查询失败"))?;
    Ok(Json(rows.iter().map(|r|json!({"id":sqlx::Row::try_get::<String,_>(r,"id").unwrap_or_default(),"name":sqlx::Row::try_get::<String,_>(r,"name").unwrap_or_default(),"key_prefix":sqlx::Row::try_get::<String,_>(r,"key_prefix").unwrap_or_default(),"monthly_limit_cents":sqlx::Row::try_get::<i64,_>(r,"monthly_limit_cents").unwrap_or(0),"active":sqlx::Row::try_get::<i64,_>(r,"active").unwrap_or(0),"created_at":sqlx::Row::try_get::<String,_>(r,"created_at").unwrap_or_default(),"last_used_at":sqlx::Row::try_get::<Option<String>,_>(r,"last_used_at").unwrap_or(None),"used_micros":sqlx::Row::try_get::<i64,_>(r,"used_micros").unwrap_or(0),"call_count":sqlx::Row::try_get::<i64,_>(r,"call_count").unwrap_or(0),"input_tokens":sqlx::Row::try_get::<i64,_>(r,"input_tokens").unwrap_or(0),"output_tokens":sqlx::Row::try_get::<i64,_>(r,"output_tokens").unwrap_or(0)})).collect()))
}
async fn create_api_key(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ApiKeyInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let me = actor(&headers, &s.jwt_secret)?;
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 80 || input.monthly_limit_cents <= 0 {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "请填写密钥名称和大于零的月度额度",
        ));
    }
    let limits =
        sqlx::query("SELECT personal_limit_cents,department_id,active FROM users WHERE id=?")
            .bind(&me.sub)
            .fetch_optional(&s.db)
            .await
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "账号额度读取失败"))?
            .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "账号不存在"))?;
    let personal: i64 = sqlx::Row::try_get(&limits, "personal_limit_cents").unwrap_or(0);
    let dep: Option<String> = sqlx::Row::try_get(&limits, "department_id").unwrap_or(None);
    let active: i64 = sqlx::Row::try_get(&limits, "active").unwrap_or(0);
    if active == 0 {
        return Err(fail(StatusCode::FORBIDDEN, "账号已停用"));
    }
    if dep.is_none() {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "账号尚未分配部门，无法创建模型调用密钥",
        ));
    }
    if input.monthly_limit_cents > personal {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "密钥额度不能超过个人月度额度",
        ));
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE user_id=? AND active=1")
            .bind(&me.sub)
            .fetch_one(&s.db)
            .await
            .unwrap_or(0);
    if count >= 20 {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "每个账号最多保留 20 个有效 API 密钥",
        ));
    }
    let id = Uuid::new_v4().to_string();
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let secret = format!("lrk_{}", URL_SAFE_NO_PAD.encode(random));
    let prefix = secret.chars().take(12).collect::<String>();
    sqlx::query("INSERT INTO api_keys(id,user_id,name,key_hash,key_prefix,monthly_limit_cents) VALUES(?,?,?,?,?,?)").bind(&id).bind(&me.sub).bind(name).bind(hash_api_key(&secret)).bind(&prefix).bind(input.monthly_limit_cents).execute(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"API 密钥保存失败"))?;
    let created_at = sqlx::query_scalar::<_, String>("SELECT created_at FROM api_keys WHERE id=?")
        .bind(&id)
        .fetch_one(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "密钥创建时间读取失败"))?;
    audit(
        &s.db,
        &me.sub,
        "api_key.create",
        &id,
        json!({"name":name,"monthly_limit_cents":input.monthly_limit_cents}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"id":id,"name":name,"key":secret,"key_prefix":prefix,"monthly_limit_cents":input.monthly_limit_cents,"created_at":created_at}),
        ),
    ))
}
async fn revoke_api_key(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let me = actor(&headers, &s.jwt_secret)?;
    let result = sqlx::query("UPDATE api_keys SET active=0 WHERE id=? AND user_id=? AND active=1")
        .bind(&id)
        .bind(&me.sub)
        .execute(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "API 密钥撤销失败"))?;
    if result.rows_affected() == 0 {
        return Err(fail(StatusCode::NOT_FOUND, "密钥不存在或已撤销"));
    }
    audit(&s.db, &me.sub, "api_key.revoke", &id, json!({})).await;
    Ok(Json(json!({"ok":true})))
}
async fn api_key_stats(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let me = actor(&headers, &s.jwt_secret)?;
    let owns: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE id=? AND user_id=?")
        .bind(&id)
        .bind(&me.sub)
        .fetch_one(&s.db)
        .await
        .unwrap_or(0);
    if owns == 0 {
        return Err(fail(StatusCode::NOT_FOUND, "API 密钥不存在"));
    }
    let (month_start, month_end, _) = billing_window(Utc::now());
    let rows=sqlx::query("SELECT model,COUNT(*) AS calls,COALESCE(SUM(input_tokens),0) AS input_tokens,COALESCE(SUM(output_tokens),0) AS output_tokens,COALESCE(SUM(cache_tokens),0) AS cache_tokens,COALESCE(SUM(cost_micros),0) AS cost_micros FROM usage_records WHERE api_key_id=? AND created_at>=? AND created_at<? GROUP BY model ORDER BY cost_micros DESC").bind(&id).bind(month_start).bind(month_end).fetch_all(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"密钥调用统计查询失败"))?;
    Ok(Json(Value::Array(rows.iter().map(|r|json!({"model":sqlx::Row::try_get::<String,_>(r,"model").unwrap_or_default(),"calls":sqlx::Row::try_get::<i64,_>(r,"calls").unwrap_or(0),"input_tokens":sqlx::Row::try_get::<i64,_>(r,"input_tokens").unwrap_or(0),"output_tokens":sqlx::Row::try_get::<i64,_>(r,"output_tokens").unwrap_or(0),"cache_tokens":sqlx::Row::try_get::<i64,_>(r,"cache_tokens").unwrap_or(0),"cost_micros":sqlx::Row::try_get::<i64,_>(r,"cost_micros").unwrap_or(0)})).collect())))
}

async fn usage(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(f): Query<UsageFilter>,
) -> Result<Json<Vec<UsageRow>>, (StatusCode, Json<Value>)> {
    let me = actor(&headers, &s.jwt_secret)?;
    let rows=sqlx::query_as::<_,UsageRow>("SELECT r.id,r.request_id,u.username,u.display_name,d.name AS department_name,r.model,r.protocol,r.mode,r.status,r.input_tokens,r.output_tokens,r.cache_tokens,r.cost_micros,r.latency_ms,r.error_code,r.created_at FROM usage_records r JOIN users u ON u.id=r.user_id LEFT JOIN departments d ON d.id=r.department_id WHERE (? IS NULL OR r.department_id=?) AND (? IS NULL OR r.status=?) AND (? IS NULL OR r.model=?) AND (? IS NULL OR r.created_at>=?) AND (? IS NULL OR r.created_at<=?) ORDER BY r.created_at DESC LIMIT 500")
        .bind(if me.role=="department_admin" {me.department_id.clone()}else{f.department_id.clone()}).bind(if me.role=="department_admin" {me.department_id.clone()}else{f.department_id.clone()}).bind(&f.status).bind(&f.status).bind(&f.model).bind(&f.model).bind(&f.from).bind(&f.from).bind(&f.to).bind(&f.to).fetch_all(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"调用记录查询失败"))?;
    if me.role == "platform_admin" {
        Ok(Json(rows))
    } else if me.role == "department_admin" {
        Ok(Json(rows))
    } else {
        Ok(Json(
            rows.into_iter()
                .filter(|r| r.username == me.username)
                .collect(),
        ))
    }
}

fn billing_window(now: chrono::DateTime<Utc>) -> (String, String, bool) {
    let local = now.with_timezone(&Shanghai);
    let local_start = Shanghai
        .with_ymd_and_hms(local.year(), local.month(), 1, 0, 0, 0)
        .single()
        .expect("valid local month start");
    let next = if local.month() == 12 {
        Shanghai
            .with_ymd_and_hms(local.year() + 1, 1, 1, 0, 0, 0)
            .single()
            .unwrap()
    } else {
        Shanghai
            .with_ymd_and_hms(local.year(), local.month() + 1, 1, 0, 0, 0)
            .single()
            .unwrap()
    };
    (
        local_start
            .with_timezone(&Utc)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
        next.with_timezone(&Utc)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
        local.hour() < 8,
    )
}

fn deepseek_is_peak(now: chrono::DateTime<Utc>, holidays: &str) -> bool {
    let local = now.with_timezone(&Shanghai);
    let date = local.date_naive().format("%Y-%m-%d").to_string();
    if local.weekday().number_from_monday() > 5 || holidays.lines().any(|d| d.trim() == date) {
        return false;
    }
    let minute = local.hour() * 60 + local.minute();
    (540..720).contains(&minute) || (840..1080).contains(&minute)
}

async fn offpeak_for_model(
    db: &SqlitePool,
    model: &str,
    now: chrono::DateTime<Utc>,
    legacy_night: bool,
) -> bool {
    let source =
        sqlx::query_scalar::<_, String>("SELECT source FROM model_routes WHERE model_key=?")
            .bind(model)
            .fetch_optional(db)
            .await
            .unwrap_or_default()
            .unwrap_or_default();
    if source.to_ascii_lowercase().contains("deepseek")
        || model.to_ascii_lowercase().contains("deepseek")
    {
        let settings = sqlx::query_scalar::<_, String>("SELECT COALESCE((SELECT value FROM app_settings WHERE key='deepseek_holiday_dates'), '')")
            .fetch_one(db).await.unwrap_or_default();
        !deepseek_is_peak(now, &settings)
    } else {
        legacy_night
    }
}

fn amount_micros(tokens: i64, rate_micros_per_million: i64) -> i64 {
    ((tokens.max(0) as i128) * (rate_micros_per_million.max(0) as i128) / 1_000_000)
        .min(i64::MAX as i128) as i64
}

async fn reserve_quota(
    s: &AppState,
    claims: &Claims,
    request_id: &str,
    amount: i64,
    window_start: &str,
    window_end: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    let department_id = claims
        .department_id
        .as_deref()
        .ok_or_else(|| fail(StatusCode::FORBIDDEN, "账号尚未分配部门，不能调用模型"))?;
    let mut tx =
        s.db.begin()
            .await
            .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "额度服务暂不可用"))?;
    let user_limit: i64 =
        sqlx::query_scalar("SELECT personal_limit_cents FROM users WHERE id=? AND active=1")
            .bind(&claims.sub)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "个人额度读取失败"))?
            .ok_or_else(|| fail(StatusCode::FORBIDDEN, "账号已停用"))?;
    let department_limit: i64 =
        sqlx::query_scalar("SELECT monthly_limit_cents FROM departments WHERE id=?")
            .bind(department_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "部门额度读取失败"))?
            .ok_or_else(|| fail(StatusCode::FORBIDDEN, "部门不存在"))?;
    let user_used:i64=sqlx::query_scalar("SELECT COALESCE(SUM(amount_micros),0) FROM quota_ledger WHERE user_id=? AND entry_type='charge' AND created_at>=? AND created_at<?").bind(&claims.sub).bind(window_start).bind(window_end).fetch_one(&mut *tx).await.unwrap_or(0);
    let user_reserved:i64=sqlx::query_scalar("SELECT COALESCE(SUM(amount_micros),0) FROM quota_ledger WHERE user_id=? AND entry_type='reserve' AND created_at>=? AND created_at<?").bind(&claims.sub).bind(window_start).bind(window_end).fetch_one(&mut *tx).await.unwrap_or(0);
    let dep_used:i64=sqlx::query_scalar("SELECT COALESCE(SUM(amount_micros),0) FROM quota_ledger WHERE department_id=? AND entry_type='charge' AND created_at>=? AND created_at<?").bind(department_id).bind(window_start).bind(window_end).fetch_one(&mut *tx).await.unwrap_or(0);
    let dep_reserved:i64=sqlx::query_scalar("SELECT COALESCE(SUM(amount_micros),0) FROM quota_ledger WHERE department_id=? AND entry_type='reserve' AND created_at>=? AND created_at<?").bind(department_id).bind(window_start).bind(window_end).fetch_one(&mut *tx).await.unwrap_or(0);
    let user_budget = user_limit.saturating_mul(10_000);
    let department_budget = department_limit.saturating_mul(10_000);
    if amount < 0
        || user_used
            .saturating_add(user_reserved)
            .saturating_add(amount)
            > user_budget
    {
        tx.rollback().await.ok();
        return Err(fail(StatusCode::PAYMENT_REQUIRED, "个人月度金额额度不足"));
    }
    if dep_used.saturating_add(dep_reserved).saturating_add(amount) > department_budget {
        tx.rollback().await.ok();
        return Err(fail(StatusCode::PAYMENT_REQUIRED, "部门月度金额额度不足"));
    }
    if let Some(key_id) = claims.api_key_id.as_deref() {
        let key_limit: Option<i64> = sqlx::query_scalar(
            "SELECT monthly_limit_cents FROM api_keys WHERE id=? AND user_id=? AND active=1",
        )
        .bind(key_id)
        .bind(&claims.sub)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "API 密钥额度读取失败"))?;
        let Some(key_limit) = key_limit else {
            tx.rollback().await.ok();
            return Err(fail(StatusCode::UNAUTHORIZED, "API 密钥已撤销"));
        };
        let key_used:i64=sqlx::query_scalar("SELECT COALESCE(SUM(amount_micros),0) FROM quota_ledger WHERE api_key_id=? AND entry_type='charge' AND created_at>=? AND created_at<?").bind(key_id).bind(window_start).bind(window_end).fetch_one(&mut *tx).await.unwrap_or(0);
        let key_reserved:i64=sqlx::query_scalar("SELECT COALESCE(SUM(amount_micros),0) FROM quota_ledger WHERE api_key_id=? AND entry_type='reserve' AND created_at>=? AND created_at<?").bind(key_id).bind(window_start).bind(window_end).fetch_one(&mut *tx).await.unwrap_or(0);
        if key_used.saturating_add(key_reserved).saturating_add(amount)
            > key_limit.saturating_mul(10_000)
        {
            tx.rollback().await.ok();
            return Err(fail(StatusCode::PAYMENT_REQUIRED, "API 密钥月度额度不足"));
        }
    }
    sqlx::query("INSERT INTO quota_ledger(id,request_id,user_id,department_id,api_key_id,entry_type,amount_micros,idempotency_key) VALUES(?,?,?,?,?,?,?,?)").bind(Uuid::new_v4().to_string()).bind(request_id).bind(&claims.sub).bind(department_id).bind(&claims.api_key_id).bind("reserve").bind(amount).bind(format!("{request_id}:reserve")).execute(&mut *tx).await.map_err(|_|fail(StatusCode::SERVICE_UNAVAILABLE,"额度预留失败，请重试"))?;
    tx.commit()
        .await
        .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "额度预留提交失败，请重试"))?;
    Ok(())
}

async fn close_reservation(
    s: &AppState,
    claims: &Claims,
    request_id: &str,
    reserved: i64,
    actual: i64,
    release_only: bool,
) {
    let Ok(mut tx) = s.db.begin().await else {
        return;
    };
    let _=sqlx::query("INSERT OR IGNORE INTO quota_ledger(id,request_id,user_id,department_id,api_key_id,entry_type,amount_micros,idempotency_key) VALUES(?,?,?,?,?,?,?,?)").bind(Uuid::new_v4().to_string()).bind(request_id).bind(&claims.sub).bind(&claims.department_id).bind(&claims.api_key_id).bind("reserve").bind(-reserved).bind(format!("{request_id}:release")).execute(&mut *tx).await;
    if !release_only {
        let _=sqlx::query("INSERT OR IGNORE INTO quota_ledger(id,request_id,user_id,department_id,api_key_id,entry_type,amount_micros,idempotency_key) VALUES(?,?,?,?,?,?,?,?)").bind(Uuid::new_v4().to_string()).bind(request_id).bind(&claims.sub).bind(&claims.department_id).bind(&claims.api_key_id).bind("charge").bind(actual).bind(format!("{request_id}:charge")).execute(&mut *tx).await;
    }
    let _ = tx.commit().await;
}

async fn record_failed_call(
    s: &AppState,
    claims: &Claims,
    request_id: &str,
    model: &str,
    protocol: &str,
    mode: &str,
    price_id: &str,
    latency: i64,
    error: &str,
) {
    let _=sqlx::query("INSERT OR IGNORE INTO usage_records(id,request_id,user_id,department_id,api_key_id,model,protocol,mode,status,price_id,latency_ms,error_code) VALUES(?,?,?,?,?,?,?, ?,'failed',?,?,?)")
        .bind(Uuid::new_v4().to_string()).bind(request_id).bind(&claims.sub).bind(&claims.department_id).bind(&claims.api_key_id).bind(model).bind(protocol).bind(mode).bind(price_id).bind(latency).bind(error).execute(&s.db).await;
}

async fn openai_chat(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let claims = api_actor(&headers, &s).await?;
    if body.get("stream").and_then(Value::as_bool).unwrap_or(false) {
        return stream_openai_chat(s, claims, body, None).await;
    }
    let requested_model = body
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "请求缺少 model 字段"))?;
    let route=sqlx::query("SELECT id,model_key,upstream_model,protocol,endpoint,billing_mode,enabled,credential_ciphertext FROM model_routes WHERE model_key=?").bind(requested_model).fetch_optional(&s.db).await.map_err(|_|fail(StatusCode::SERVICE_UNAVAILABLE,"模型路由读取失败"))?.ok_or_else(||fail(StatusCode::NOT_FOUND,"请求的模型未配置"))?;
    let model_key: String = sqlx::Row::try_get(&route, "model_key").unwrap_or_default();
    let upstream_model: String = sqlx::Row::try_get(&route, "upstream_model").unwrap_or_default();
    let protocol: String = sqlx::Row::try_get(&route, "protocol").unwrap_or_default();
    let endpoint: String = sqlx::Row::try_get(&route, "endpoint").unwrap_or_default();
    let mode: String = sqlx::Row::try_get(&route, "billing_mode").unwrap_or_default();
    let enabled: i64 = sqlx::Row::try_get(&route, "enabled").unwrap_or(0);
    let encrypted_key: Option<String> =
        sqlx::Row::try_get(&route, "credential_ciphertext").unwrap_or(None);
    if enabled == 0 {
        return Err(fail(StatusCode::NOT_FOUND, "该模型当前已停用"));
    }
    if protocol != "openai" {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "该模型配置的协议暂不可由 OpenAI Chat Completions 网关调用",
        ));
    }
    if mode != "pay_as_you_go" {
        return Err(fail(
            StatusCode::NOT_IMPLEMENTED,
            "当前网关仅支持按量计费模型调用",
        ));
    }
    let upstream_key = match encrypted_key {
        Some(k) => decrypt_credential(&s.credentials_key, &k).map_err(|_| {
            fail(
                StatusCode::SERVICE_UNAVAILABLE,
                "模型密钥无法解密，请检查凭证加密密钥配置",
            )
        })?,
        None => s.upstream_key.as_str().to_string(),
    };
    let now = Utc::now();
    let (window_start, window_end, legacy_night) = billing_window(now);
    let is_night = offpeak_for_model(&s.db, &model_key, now, legacy_night).await;
    let price=sqlx::query_as::<_,PriceRow>("SELECT * FROM model_prices WHERE model=? AND mode=? AND active=1 AND julianday(effective_from)<=julianday(?) ORDER BY julianday(effective_from) DESC LIMIT 1").bind(&model_key).bind(&mode).bind(now.to_rfc3339()).fetch_optional(&s.db).await.map_err(|_|fail(StatusCode::SERVICE_UNAVAILABLE,"计价配置读取失败"))?.ok_or_else(||fail(StatusCode::SERVICE_UNAVAILABLE,"该模型尚未配置有效价格"))?;
    let max_tokens = body
        .get("max_completion_tokens")
        .or_else(|| body.get("max_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(8192)
        .clamp(1, 131072);
    if body.get("max_tokens").is_none() && body.get("max_completion_tokens").is_none() {
        body["max_tokens"] = json!(max_tokens);
    }
    body["model"] = json!(upstream_model);
    let estimated_input = (body.to_string().len() as i64).max(1);
    let in_rate = if is_night {
        price.night_input_per_million_micros
    } else {
        price.input_per_million_micros
    };
    let out_rate = if is_night {
        price.night_output_per_million_micros
    } else {
        price.output_per_million_micros
    };
    let reserve = amount_micros(estimated_input, in_rate)
        .saturating_add(amount_micros(max_tokens, out_rate))
        .saturating_add(2);
    let request_id = Uuid::new_v4().to_string();
    reserve_quota(
        &s,
        &claims,
        &request_id,
        reserve,
        &window_start,
        &window_end,
    )
    .await?;
    let start = std::time::Instant::now();
    let response = s
        .http
        .post(resolve_chat_endpoint(&endpoint))
        .bearer_auth(upstream_key)
        .json(&body)
        .send()
        .await;
    let response = match response {
        Ok(r) => r,
        Err(_) => {
            close_reservation(&s, &claims, &request_id, reserve, 0, true).await;
            record_failed_call(
                &s,
                &claims,
                &request_id,
                &model_key,
                &protocol,
                &mode,
                &price.id,
                start.elapsed().as_millis() as i64,
                "upstream_connection",
            )
            .await;
            return Err(fail(StatusCode::BAD_GATEWAY, "上游模型连接失败"));
        }
    };
    let status = response.status();
    let response_value = response.json::<Value>().await;
    let value = match response_value {
        Ok(v) => v,
        Err(_) => {
            close_reservation(&s, &claims, &request_id, reserve, 0, true).await;
            record_failed_call(
                &s,
                &claims,
                &request_id,
                &model_key,
                &protocol,
                &mode,
                &price.id,
                start.elapsed().as_millis() as i64,
                "invalid_upstream_response",
            )
            .await;
            return Err(fail(StatusCode::BAD_GATEWAY, "上游响应格式无效"));
        }
    };
    let latency = start.elapsed().as_millis().min(i64::MAX as u128) as i64;
    if !status.is_success() {
        close_reservation(&s, &claims, &request_id, reserve, 0, true).await;
        record_failed_call(
            &s,
            &claims,
            &request_id,
            &model_key,
            &protocol,
            &mode,
            &price.id,
            latency,
            &format!("upstream_http_{}", status.as_u16()),
        )
        .await;
        return Ok((status, Json(value)).into_response());
    }
    let Some(usage) = value.get("usage") else {
        let _=sqlx::query("INSERT INTO usage_records(id,request_id,user_id,department_id,api_key_id,model,protocol,mode,status,price_id,latency_ms,error_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").bind(Uuid::new_v4().to_string()).bind(&request_id).bind(&claims.sub).bind(&claims.department_id).bind(&claims.api_key_id).bind(&model_key).bind(&protocol).bind(&mode).bind("pending_usage").bind(&price.id).bind(latency).bind("usage_missing").execute(&s.db).await;
        return Ok((status, Json(value)).into_response());
    };
    let input = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .max(0);
    let output = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .max(0);
    let cached = usage
        .pointer("prompt_tokens_details.cached_tokens")
        .or_else(|| usage.pointer("input_tokens_details.cache_read_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .clamp(0, input);
    let billed_input = input - cached;
    let cache_rate = if is_night {
        price.night_cache_per_million_micros
    } else {
        price.cache_per_million_micros
    };
    let actual = amount_micros(billed_input, in_rate)
        .saturating_add(amount_micros(cached, cache_rate))
        .saturating_add(amount_micros(output, out_rate));
    close_reservation(&s, &claims, &request_id, reserve, actual, false).await;
    let _=sqlx::query("INSERT INTO usage_records(id,request_id,user_id,department_id,api_key_id,model,protocol,mode,status,input_tokens,output_tokens,cache_tokens,cost_micros,price_id,latency_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(Uuid::new_v4().to_string()).bind(&request_id).bind(&claims.sub).bind(&claims.department_id).bind(&claims.api_key_id).bind(&model_key).bind(&protocol).bind(&mode).bind("success").bind(input).bind(output).bind(cached).bind(actual).bind(&price.id).bind(latency).execute(&s.db).await;
    Ok((status, Json(value)).into_response())
}

async fn openai_image_generation(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let claims = api_actor(&headers, &s).await?;
    let requested_model = body
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "请求缺少 model 字段"))?;
    let route = sqlx::query("SELECT model_key,upstream_model,protocol,endpoint,billing_mode,enabled,credential_ciphertext FROM model_routes WHERE model_key=?")
        .bind(requested_model).fetch_optional(&s.db).await.map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE,"模型路由读取失败"))?.ok_or_else(|| fail(StatusCode::NOT_FOUND,"请求的模型未配置"))?;
    let model_key: String = sqlx::Row::try_get(&route, "model_key").unwrap_or_default();
    let upstream_model: String = sqlx::Row::try_get(&route, "upstream_model").unwrap_or_default();
    let protocol: String = sqlx::Row::try_get(&route, "protocol").unwrap_or_default();
    let endpoint: String = sqlx::Row::try_get(&route, "endpoint").unwrap_or_default();
    let mode: String = sqlx::Row::try_get(&route, "billing_mode").unwrap_or_default();
    let enabled: i64 = sqlx::Row::try_get(&route, "enabled").unwrap_or(0);
    let encrypted_key: Option<String> =
        sqlx::Row::try_get(&route, "credential_ciphertext").unwrap_or(None);
    if enabled == 0 {
        return Err(fail(StatusCode::NOT_FOUND, "该模型当前已停用"));
    }
    if protocol != "openai" {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "图像生成当前需要 OpenAI Images 兼容模型",
        ));
    }
    if mode != "pay_as_you_go" {
        return Err(fail(
            StatusCode::NOT_IMPLEMENTED,
            "当前网关仅支持按量计费模型调用",
        ));
    }
    let credential = match encrypted_key {
        Some(k) => decrypt_credential(&s.credentials_key, &k)
            .map_err(|_| fail(StatusCode::SERVICE_UNAVAILABLE, "模型密钥无法解密"))?,
        None => s.upstream_key.as_str().to_string(),
    };
    let now = Utc::now();
    let (window_start, window_end, legacy_night) = billing_window(now);
    let is_night = offpeak_for_model(&s.db, &model_key, now, legacy_night).await;
    let price=sqlx::query_as::<_,PriceRow>("SELECT * FROM model_prices WHERE model=? AND mode=? AND active=1 AND julianday(effective_from)<=julianday(?) ORDER BY julianday(effective_from) DESC LIMIT 1").bind(&model_key).bind(&mode).bind(now.to_rfc3339()).fetch_optional(&s.db).await.map_err(|_|fail(StatusCode::SERVICE_UNAVAILABLE,"计价配置读取失败"))?.ok_or_else(||fail(StatusCode::SERVICE_UNAVAILABLE,"该模型尚未配置有效价格"))?;
    let estimate = (body.to_string().len() as i64).max(1);
    let reserve = amount_micros(
        estimate,
        if is_night {
            price.night_input_per_million_micros
        } else {
            price.input_per_million_micros
        },
    )
    .saturating_add(
        price
            .output_per_million_micros
            .max(price.night_output_per_million_micros),
    );
    let request_id = Uuid::new_v4().to_string();
    reserve_quota(
        &s,
        &claims,
        &request_id,
        reserve,
        &window_start,
        &window_end,
    )
    .await?;
    body["model"] = json!(upstream_model);
    let url = if endpoint.ends_with("/images/generations") {
        endpoint.clone()
    } else {
        format!("{}/images/generations", endpoint.trim_end_matches('/'))
    };
    let started = std::time::Instant::now();
    let response = s
        .http
        .post(url)
        .bearer_auth(credential)
        .json(&body)
        .send()
        .await
        .map_err(|_| fail(StatusCode::BAD_GATEWAY, "图像模型上游连接失败"))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| fail(StatusCode::BAD_GATEWAY, "读取图像模型响应失败"))?;
    let latency = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
    if !status.is_success() {
        close_reservation(&s, &claims, &request_id, reserve, 0, true).await;
        let _=sqlx::query("INSERT INTO usage_records(id,request_id,user_id,department_id,api_key_id,model,protocol,mode,status,price_id,latency_ms,error_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").bind(Uuid::new_v4().to_string()).bind(&request_id).bind(&claims.sub).bind(&claims.department_id).bind(&claims.api_key_id).bind(&model_key).bind("openai").bind(&mode).bind("failed").bind(&price.id).bind(latency).bind(format!("upstream_http_{}",status.as_u16())).execute(&s.db).await;
        return Ok((status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response());
    }
    let actual = amount_micros(
        estimate,
        if is_night {
            price.night_input_per_million_micros
        } else {
            price.input_per_million_micros
        },
    )
    .saturating_add(
        price
            .output_per_million_micros
            .max(price.night_output_per_million_micros),
    );
    close_reservation(&s, &claims, &request_id, reserve, actual, false).await;
    let _=sqlx::query("INSERT INTO usage_records(id,request_id,user_id,department_id,api_key_id,model,protocol,mode,status,input_tokens,output_tokens,cost_micros,price_id,latency_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(Uuid::new_v4().to_string()).bind(&request_id).bind(&claims.sub).bind(&claims.department_id).bind(&claims.api_key_id).bind(&model_key).bind("openai").bind(&mode).bind("success").bind(estimate).bind(1_i64).bind(actual).bind(&price.id).bind(latency).execute(&s.db).await;
    Ok((status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}

fn messages_to_openai(body: Value, protocol: &str) -> Value {
    let model = body.get("model").cloned().unwrap_or(Value::Null);
    let stream = body.get("stream").cloned().unwrap_or(json!(false));
    let mut messages = body
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if protocol == "anthropic" {
        if let Some(system) = body.get("system") {
            messages.insert(0, json!({"role":"system","content":anthropic_text(system)}));
        }
        for message in &mut messages {
            if let Some(content) = message.get_mut("content") {
                *content = anthropic_content(content);
            }
        }
    } else if protocol == "dashscope" {
        messages = body
            .pointer("input.messages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for message in &mut messages {
            if let Some(content) = message.get_mut("content") {
                *content = dashscope_content(content);
            }
        }
    }
    let mut out = json!({"model":model,"messages":messages,"stream":stream});
    let params = if protocol == "dashscope" {
        body.get("parameters").cloned().unwrap_or(json!({}))
    } else {
        body.clone()
    };
    for (src, dst) in [
        ("max_tokens", "max_tokens"),
        ("max_completion_tokens", "max_completion_tokens"),
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("stop", "stop"),
        ("tools", "tools"),
        ("tool_choice", "tool_choice"),
    ] {
        if let Some(v) = params.get(src) {
            out[dst] = v.clone();
        }
    }
    out
}
fn anthropic_text(value: &Value) -> Value {
    if let Some(blocks) = value.as_array() {
        Value::String(
            blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    } else {
        value.clone()
    }
}

fn anthropic_content(value: &Value) -> Value {
    let Some(blocks) = value.as_array() else {
        return value.clone();
    };
    Value::Array(
        blocks
            .iter()
            .filter_map(|block| match block.get("type").and_then(Value::as_str) {
                Some("text") => block
                    .get("text")
                    .cloned()
                    .map(|text| json!({"type":"text","text":text})),
                Some("image_url") => {
                    let url = block.pointer("image_url.url").and_then(Value::as_str)?;
                    if let Some((header, data)) = url.split_once(",") {
                        let media_type = header
                            .strip_prefix("data:")
                            .and_then(|s| s.split(';').next())
                            .unwrap_or("image/jpeg");
                        Some(json!({"type":"image","source":{"type":"base64","media_type":media_type,"data":data}}))
                    } else {
                        Some(json!({"type":"image","source":{"type":"url","url":url}}))
                    }
                }
                _ => None,
            })
            .collect(),
    )
}

fn dashscope_content(value: &Value) -> Value {
    let Some(blocks) = value.as_array() else {
        return value.clone();
    };
    Value::Array(
        blocks
            .iter()
            .filter_map(|block| match block.get("type").and_then(Value::as_str) {
                Some("text") => block.get("text").cloned().map(|text| json!({"text":text})),
                Some("image_url") => block
                    .pointer("image_url.url")
                    .cloned()
                    .map(|image| json!({"image":image})),
                _ => None,
            })
            .collect(),
    )
}

fn openai_to_protocol(value: Value, protocol: &str) -> Value {
    let choice = value.pointer("choices.0").cloned().unwrap_or(json!({}));
    let message = choice.get("message").cloned().unwrap_or(json!({}));
    let text = message.get("content").cloned().unwrap_or(json!(""));
    let usage = value.get("usage").cloned().unwrap_or(json!({}));
    let input = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .cloned()
        .unwrap_or(json!(0));
    let output = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .cloned()
        .unwrap_or(json!(0));
    let model = value.get("model").cloned().unwrap_or(Value::Null);
    match protocol {
        "anthropic" => {
            json!({"id":value.get("id").cloned().unwrap_or(json!("msg_gateway")),"type":"message","role":"assistant","model":model,"content":[{"type":"text","text":text}],"stop_reason":if choice.pointer("finish_reason")==Some(&json!("length")){"max_tokens"}else{"end_turn"},"stop_sequence":null,"usage":{"input_tokens":input,"output_tokens":output}})
        }
        "dashscope" => {
            json!({"request_id":value.get("id").cloned().unwrap_or(Value::Null),"output":{"choices":[{"finish_reason":choice.get("finish_reason").cloned().unwrap_or(Value::Null),"message":{"role":"assistant","content":text}}]},"usage":{"input_tokens":input,"output_tokens":output,"total_tokens":input.as_i64().unwrap_or(0)+output.as_i64().unwrap_or(0)}})
        }
        _ => value,
    }
}

async fn protocol_chat(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
    protocol: &'static str,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let mut openai = messages_to_openai(body, protocol);
    let claims = api_actor(&headers, &s).await?;
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(s.jwt_secret.as_bytes()),
    )
    .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "认证状态生成失败"))?;
    let mut internal_headers = HeaderMap::new();
    internal_headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    let stream = openai
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let result = openai_chat(State(s.clone()), internal_headers, Json(openai.take())).await?;
    let response = result.into_response();
    if !stream {
        let status = response.status();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap_or_default();
        let value = serde_json::from_slice::<Value>(&bytes)
            .unwrap_or_else(|_| json!({"error":{"message":"模型响应无法解析"}}));
        if !status.is_success() {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        }
        return Ok((status, Json(openai_to_protocol(value, protocol))).into_response());
    }
    if protocol == "openai" || !response.status().is_success() {
        return Ok(response);
    }
    let (parts, body) = response.into_parts();
    let protocol = protocol.to_string();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    tokio::spawn(async move {
        let mut source = body.into_data_stream();
        let mut pending = String::new();
        let mut started = false;
        while let Some(Ok(chunk)) = futures_util::StreamExt::next(&mut source).await {
            pending.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(pos) = pending.find('\n') {
                let line = pending[..pos].trim_end_matches('\r').to_string();
                pending.drain(..=pos);
                let Some(data) = line
                    .strip_prefix("data: ")
                    .or_else(|| line.strip_prefix("data:"))
                else {
                    continue;
                };
                let data = data.trim();
                let mut out = String::new();
                if data == "[DONE]" {
                    if protocol == "anthropic" {
                        if started {
                            out.push_str("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n");
                        }
                        out.push_str("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":0}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
                    } else {
                        out.push_str("data: [DONE]\n\n");
                    }
                } else if let Ok(v) = serde_json::from_str::<Value>(data) {
                    let delta = v.pointer("choices.0.delta").cloned().unwrap_or(json!({}));
                    let text = delta.get("content").and_then(Value::as_str).unwrap_or("");
                    if protocol == "anthropic" {
                        if !started {
                            out.push_str(&format!("event: message_start\ndata: {}\n\nevent: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n",json!({"type":"message_start","message":{"id":v.get("id").unwrap_or(&json!("msg_gateway")),"type":"message","role":"assistant","model":v.get("model"),"content":[],"stop_reason":null,"usage":{"input_tokens":0,"output_tokens":0}}})));
                            started = true;
                        }
                        if !text.is_empty() {
                            out.push_str(&format!("event: content_block_delta\ndata: {}\n\n",json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":text}})));
                        }
                    } else if protocol == "dashscope" {
                        if !text.is_empty() {
                            out.push_str(&format!("data: {}\n\n",json!({"output":{"choices":[{"message":{"role":"assistant","content":text},"finish_reason":null}]}})));
                        }
                    }
                }
                if !out.is_empty() && tx.send(Ok(Bytes::from(out))).await.is_err() {
                    return;
                }
            }
        }
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async {
        rx.recv().await.map(|item| (item, rx))
    });
    Ok(Response::from_parts(parts, Body::from_stream(stream)))
}

async fn anthropic_messages(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    protocol_chat(State(s), headers, Json(body), "anthropic").await
}
async fn dashscope_generation(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    protocol_chat(State(s), headers, Json(body), "dashscope").await
}

async fn stream_openai_chat(
    s: AppState,
    claims: Claims,
    mut body: Value,
    cancellation: Option<Arc<tokio::sync::Notify>>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let requested_model = body
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "请求缺少 model 字段"))?
        .to_string();
    let route=sqlx::query("SELECT model_key,upstream_model,protocol,endpoint,billing_mode,enabled,credential_ciphertext FROM model_routes WHERE model_key=?").bind(&requested_model).fetch_optional(&s.db).await.map_err(|_|fail(StatusCode::SERVICE_UNAVAILABLE,"模型路由读取失败"))?.ok_or_else(||fail(StatusCode::NOT_FOUND,"请求的模型未配置"))?;
    let model_key: String = sqlx::Row::try_get(&route, "model_key").unwrap_or_default();
    let upstream_model: String = sqlx::Row::try_get(&route, "upstream_model").unwrap_or_default();
    let protocol: String = sqlx::Row::try_get(&route, "protocol").unwrap_or_default();
    let endpoint: String = sqlx::Row::try_get(&route, "endpoint").unwrap_or_default();
    let mode: String = sqlx::Row::try_get(&route, "billing_mode").unwrap_or_default();
    let enabled: i64 = sqlx::Row::try_get(&route, "enabled").unwrap_or(0);
    let encrypted_key: Option<String> =
        sqlx::Row::try_get(&route, "credential_ciphertext").unwrap_or(None);
    if enabled == 0 {
        return Err(fail(StatusCode::NOT_FOUND, "该模型当前已停用"));
    }
    if protocol != "openai" {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "该模型配置的协议暂不可由 OpenAI Chat Completions 网关调用",
        ));
    }
    if mode != "pay_as_you_go" {
        return Err(fail(
            StatusCode::NOT_IMPLEMENTED,
            "当前网关仅支持按量计费模型调用",
        ));
    }
    let upstream_key = match encrypted_key {
        Some(k) => decrypt_credential(&s.credentials_key, &k).map_err(|_| {
            fail(
                StatusCode::SERVICE_UNAVAILABLE,
                "模型密钥无法解密，请检查凭证加密密钥配置",
            )
        })?,
        None => s.upstream_key.as_str().to_string(),
    };
    let now = Utc::now();
    let (window_start, window_end, legacy_night) = billing_window(now);
    let is_night = offpeak_for_model(&s.db, &model_key, now, legacy_night).await;
    let price=sqlx::query_as::<_,PriceRow>("SELECT * FROM model_prices WHERE model=? AND mode=? AND active=1 AND julianday(effective_from)<=julianday(?) ORDER BY julianday(effective_from) DESC LIMIT 1").bind(&model_key).bind(&mode).bind(now.to_rfc3339()).fetch_optional(&s.db).await.map_err(|_|fail(StatusCode::SERVICE_UNAVAILABLE,"计价配置读取失败"))?.ok_or_else(||fail(StatusCode::SERVICE_UNAVAILABLE,"该模型尚未配置有效价格"))?;
    let max_tokens = body
        .get("max_completion_tokens")
        .or_else(|| body.get("max_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(8192)
        .clamp(1, 131072);
    if body.get("max_tokens").is_none() && body.get("max_completion_tokens").is_none() {
        body["max_tokens"] = json!(max_tokens);
    }
    body["model"] = json!(upstream_model);
    body["stream"] = json!(true);
    body["stream_options"] = json!({"include_usage":true});
    let estimated_input = (body.to_string().len() as i64).max(1);
    let in_rate = if is_night {
        price.night_input_per_million_micros
    } else {
        price.input_per_million_micros
    };
    let out_rate = if is_night {
        price.night_output_per_million_micros
    } else {
        price.output_per_million_micros
    };
    let reserve = amount_micros(estimated_input, in_rate)
        .saturating_add(amount_micros(max_tokens, out_rate))
        .saturating_add(2);
    let request_id = Uuid::new_v4().to_string();
    reserve_quota(
        &s,
        &claims,
        &request_id,
        reserve,
        &window_start,
        &window_end,
    )
    .await?;
    let start = std::time::Instant::now();
    let request = s
        .http
        .post(resolve_chat_endpoint(&endpoint))
        .bearer_auth(upstream_key)
        .json(&body)
        .send();
    let upstream_result = if let Some(cancel) = cancellation.as_ref() {
        tokio::select! {
            result = request => result,
            _ = cancel.notified() => {
                close_reservation(&s, &claims, &request_id, reserve, 0, true).await;
                record_failed_call(&s, &claims, &request_id, &model_key, &protocol, &mode, &price.id, start.elapsed().as_millis() as i64, "client_cancelled").await;
                return Err(fail(StatusCode::REQUEST_TIMEOUT, "Agent 执行已中断"));
            }
        }
    } else {
        request.await
    };
    let upstream = match upstream_result {
        Ok(r) => r,
        Err(_) => {
            close_reservation(&s, &claims, &request_id, reserve, 0, true).await;
            record_failed_call(
                &s,
                &claims,
                &request_id,
                &model_key,
                &protocol,
                &mode,
                &price.id,
                start.elapsed().as_millis() as i64,
                "upstream_connection",
            )
            .await;
            return Err(fail(StatusCode::BAD_GATEWAY, "上游模型连接失败"));
        }
    };
    let status = upstream.status();
    if !status.is_success() {
        let value = upstream
            .json::<Value>()
            .await
            .unwrap_or_else(|_| json!({"error":"上游模型请求失败"}));
        close_reservation(&s, &claims, &request_id, reserve, 0, true).await;
        record_failed_call(
            &s,
            &claims,
            &request_id,
            &model_key,
            &protocol,
            &mode,
            &price.id,
            start.elapsed().as_millis() as i64,
            &format!("upstream_http_{}", status.as_u16()),
        )
        .await;
        return Ok((status, Json(value)).into_response());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    let app = s.clone();
    let stream_cancellation = cancellation.clone();
    tokio::spawn(async move {
        let mut byte_stream = upstream.bytes_stream();
        let mut pending = String::new();
        let mut usage: Option<Value> = None;
        let mut upstream_error: Option<String> = None;
        loop {
            let item = match stream_cancellation.as_ref() {
                Some(cancel) => tokio::select! {
                    item = futures_util::StreamExt::next(&mut byte_stream) => item,
                    _ = cancel.notified() => {
                        upstream_error = Some("client_cancelled".into());
                        break;
                    }
                },
                None => futures_util::StreamExt::next(&mut byte_stream).await,
            };
            let Some(item) = item else {
                break;
            };
            match item {
                Ok(chunk) => {
                    pending.push_str(&String::from_utf8_lossy(&chunk));
                    let mut lines = pending.split('\n').map(str::to_string).collect::<Vec<_>>();
                    pending = lines.pop().unwrap_or_default();
                    for line in lines {
                        let line = line.trim_end_matches('\r');
                        if let Some(data) = line.strip_prefix("data:") {
                            let data = data.trim();
                            if data != "[DONE]" {
                                if let Ok(event) = serde_json::from_str::<Value>(data) {
                                    if let Some(u) = event.get("usage") {
                                        usage = Some(u.clone());
                                    }
                                    if let Some(err) = event.get("error") {
                                        upstream_error = Some(
                                            err.as_str()
                                                .map(str::to_string)
                                                .unwrap_or_else(|| err.to_string()),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    if tx.send(Ok(chunk)).await.is_err() {
                        upstream_error = Some("client_cancelled".into());
                        break;
                    }
                }
                Err(_) => {
                    upstream_error = Some("上游流式响应中断".into());
                    break;
                }
            }
        }
        if !pending.trim().is_empty() {
            for line in pending.lines() {
                if let Some(data) = line.trim_end_matches('\r').strip_prefix("data:") {
                    let data = data.trim();
                    if data != "[DONE]" {
                        if let Ok(event) = serde_json::from_str::<Value>(data) {
                            if let Some(u) = event.get("usage") {
                                usage = Some(u.clone());
                            }
                            if let Some(err) = event.get("error") {
                                upstream_error = Some(
                                    err.as_str()
                                        .map(str::to_string)
                                        .unwrap_or_else(|| err.to_string()),
                                );
                            }
                        }
                    }
                }
            }
        }
        let latency = start.elapsed().as_millis().min(i64::MAX as u128) as i64;
        if let Some(error) = upstream_error {
            close_reservation(&app, &claims, &request_id, reserve, 0, true).await;
            record_failed_call(
                &app,
                &claims,
                &request_id,
                &model_key,
                &protocol,
                &mode,
                &price.id,
                latency,
                if error == "client_cancelled" {
                    "client_cancelled"
                } else {
                    "upstream_stream_error"
                },
            )
            .await;
            let frame = format!("data: {}\n\n", json!({"error":{"message":error}}));
            let _ = tx.send(Ok(Bytes::from(frame))).await;
            let _ = tx.send(Ok(Bytes::from_static(b"data: [DONE]\n\n"))).await;
            return;
        }
        if let Some(u) = usage {
            let input = u
                .get("prompt_tokens")
                .or_else(|| u.get("input_tokens"))
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .max(0);
            let output = u
                .get("completion_tokens")
                .or_else(|| u.get("output_tokens"))
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .max(0);
            let cached = u
                .pointer("prompt_tokens_details.cached_tokens")
                .or_else(|| u.pointer("input_tokens_details.cache_read_tokens"))
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .clamp(0, input);
            let cache_rate = if is_night {
                price.night_cache_per_million_micros
            } else {
                price.cache_per_million_micros
            };
            let actual = amount_micros(input - cached, in_rate)
                .saturating_add(amount_micros(cached, cache_rate))
                .saturating_add(amount_micros(output, out_rate));
            close_reservation(&app, &claims, &request_id, reserve, actual, false).await;
            let _=sqlx::query("INSERT INTO usage_records(id,request_id,user_id,department_id,api_key_id,model,protocol,mode,status,input_tokens,output_tokens,cache_tokens,cost_micros,price_id,latency_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(Uuid::new_v4().to_string()).bind(&request_id).bind(&claims.sub).bind(&claims.department_id).bind(&claims.api_key_id).bind(&model_key).bind(&protocol).bind(&mode).bind("success").bind(input).bind(output).bind(cached).bind(actual).bind(&price.id).bind(latency).execute(&app.db).await;
        } else {
            // Keep the reservation when the provider omits usage so a completed
            // but unmetered stream cannot bypass the user's monthly quota.
            let _=sqlx::query("INSERT INTO usage_records(id,request_id,user_id,department_id,api_key_id,model,protocol,mode,status,price_id,latency_ms,error_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").bind(Uuid::new_v4().to_string()).bind(&request_id).bind(&claims.sub).bind(&claims.department_id).bind(&claims.api_key_id).bind(&model_key).bind(&protocol).bind(&mode).bind("pending_usage").bind(&price.id).bind(latency).bind("stream_usage_missing").execute(&app.db).await;
        }
    });
    let stream = futures_util::stream::unfold(rx, |mut receiver| async {
        receiver.recv().await.map(|item| (item, receiver))
    });
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache, no-transform")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
        .into_response())
}

async fn openai_models(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _ = api_actor(&headers, &s).await?;
    let rows=sqlx::query_as::<_,(String,String)>("SELECT model_key,source FROM model_routes WHERE enabled=1 AND protocol='openai' ORDER BY model_key").fetch_all(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"模型目录查询失败"))?;
    let data: Vec<Value> = rows
        .into_iter()
        .map(|(id, source)| json!({"id":id,"object":"model","owned_by":source}))
        .collect();
    Ok(Json(json!({"object":"list","data":data})))
}
async fn prices(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PriceRow>>, (StatusCode, Json<Value>)> {
    let _ = actor(&headers, &s.jwt_secret)?;
    let r =
        sqlx::query_as::<_, PriceRow>("SELECT * FROM model_prices ORDER BY effective_from DESC")
            .fetch_all(&s.db)
            .await
            .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "价格查询失败"))?;
    Ok(Json(r))
}
async fn add_price(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(i): Json<PriceInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let a = admin(&headers, &s.jwt_secret)?;
    if i.model.trim().is_empty()
        || i.mode != "pay_as_you_go"
        || [
            i.input_per_million_micros,
            i.output_per_million_micros,
            i.cache_per_million_micros,
        ]
        .iter()
        .any(|x| *x < 0)
        || [i.input_image_1k_micros,i.input_image_2k_micros,i.output_image_1k_micros,i.output_image_2k_micros].iter().any(|x|*x<0)
    {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "价格模型、计费模式或数值无效",
        ));
    }
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM model_routes WHERE model_key=?")
        .bind(&i.model)
        .fetch_one(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "模型配置查询失败"))?;
    if exists == 0 {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "请先配置该模型的来源和接入信息",
        ));
    }
    let effective = chrono::DateTime::parse_from_rfc3339(&i.effective_from)
        .map_err(|_| fail(StatusCode::BAD_REQUEST, "生效时间必须为 RFC3339 时间"))?
        .with_timezone(&Utc)
        .to_rfc3339();
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO model_prices(id,model,mode,input_per_million_micros,output_per_million_micros,cache_per_million_micros,night_input_per_million_micros,night_output_per_million_micros,night_cache_per_million_micros,input_image_1k_micros,input_image_2k_micros,output_image_1k_micros,output_image_2k_micros,effective_from) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(&id).bind(&i.model).bind(&i.mode).bind(i.input_per_million_micros).bind(i.output_per_million_micros).bind(i.cache_per_million_micros).bind(i.input_per_million_micros / 2).bind(i.output_per_million_micros / 2).bind(i.cache_per_million_micros / 2).bind(i.input_image_1k_micros).bind(i.input_image_2k_micros).bind(i.output_image_1k_micros).bind(i.output_image_2k_micros).bind(effective).execute(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"价格保存失败"))?;
    audit(
        &s.db,
        &a.sub,
        "model.price.create",
        &id,
        json!({"model":i.model,"effective_from":i.effective_from}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(json!({"id":id}))))
}
async fn protocols(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProtocolRow>>, (StatusCode, Json<Value>)> {
    let _ = actor(&headers, &s.jwt_secret)?;
    let r=sqlx::query_as::<_,ProtocolRow>("SELECT id,model,protocol,base_url,upstream_model,enabled FROM model_protocols ORDER BY protocol").fetch_all(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"协议查询失败"))?;
    Ok(Json(r))
}
async fn put_protocol(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(i): Json<ProtocolInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let a = admin(&headers, &s.jwt_secret)?;
    if !["openai", "anthropic", "dashscope"].contains(&i.protocol.as_str()) {
        return Err(fail(StatusCode::BAD_REQUEST, "协议类型无效"));
    }
    sqlx::query("INSERT INTO model_protocols(id,model,protocol,base_url,upstream_model,enabled) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET model=excluded.model,protocol=excluded.protocol,base_url=excluded.base_url,upstream_model=excluded.upstream_model,enabled=excluded.enabled").bind(&id).bind(&i.model).bind(&i.protocol).bind(&i.base_url).bind(&i.upstream_model).bind(i.enabled as i64).execute(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"协议配置失败"))?;
    audit(
        &s.db,
        &a.sub,
        "model.protocol.update",
        &id,
        json!({"protocol":i.protocol}),
    )
    .await;
    Ok(Json(json!({"ok":true})))
}
async fn model_routes(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ModelRouteRow>>, (StatusCode, Json<Value>)> {
    let _ = actor(&headers, &s.jwt_secret)?;
    let rows=sqlx::query_as::<_,ModelRouteRow>("SELECT id,display_name,source,model_key,upstream_model,protocol,endpoint,billing_mode,enabled,(credential_ciphertext IS NOT NULL) AS has_credential FROM model_routes ORDER BY display_name").fetch_all(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"模型来源查询失败"))?;
    Ok(Json(rows))
}
async fn save_model_route(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(i): Json<ModelRouteInput>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let a = admin(&headers, &s.jwt_secret)?;
    if i.display_name.trim().is_empty()
        || i.source.trim().is_empty()
        || i.model_key.trim().is_empty()
        || i.upstream_model.trim().is_empty()
        || i.endpoint.trim().is_empty()
    {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "模型名称、来源、模型标识和接入地址均为必填",
        ));
    }
    if !["openai", "anthropic", "dashscope"].contains(&i.protocol.as_str())
        || !["pay_as_you_go", "subscription"].contains(&i.billing_mode.as_str())
    {
        return Err(fail(StatusCode::BAD_REQUEST, "协议或计费模式无效"));
    }
    let credential=match i.api_key.as_deref().filter(|k|!k.trim().is_empty()){Some(k)=>Some(encrypt_credential(&s.credentials_key,k).map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"模型密钥加密失败"))?),None=>sqlx::query_scalar::<_,String>("SELECT credential_ciphertext FROM model_routes WHERE source=? AND credential_ciphertext IS NOT NULL ORDER BY created_at LIMIT 1").bind(i.source.trim()).fetch_optional(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"来源凭证查询失败"))?};
    let existing = sqlx::query_scalar::<_, String>("SELECT id FROM model_routes WHERE id=?")
        .bind(&id)
        .fetch_optional(&s.db)
        .await
        .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "模型配置查询失败"))?;
    if existing.is_some() {
        sqlx::query("UPDATE model_routes SET display_name=?,source=?,model_key=?,upstream_model=?,protocol=?,endpoint=?,billing_mode=?,enabled=?,credential_ciphertext=COALESCE(?,credential_ciphertext) WHERE id=?").bind(i.display_name.trim()).bind(i.source.trim()).bind(i.model_key.trim()).bind(i.upstream_model.trim()).bind(&i.protocol).bind(i.endpoint.trim()).bind(&i.billing_mode).bind(i.enabled as i64).bind(credential).bind(&id).execute(&s.db).await.map_err(|_|fail(StatusCode::CONFLICT,"模型标识重复或配置保存失败"))?;
    } else {
        sqlx::query("INSERT INTO model_routes(id,display_name,source,model_key,upstream_model,protocol,endpoint,billing_mode,enabled,credential_ciphertext) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(&id).bind(i.display_name.trim()).bind(i.source.trim()).bind(i.model_key.trim()).bind(i.upstream_model.trim()).bind(&i.protocol).bind(i.endpoint.trim()).bind(&i.billing_mode).bind(i.enabled as i64).bind(credential).execute(&s.db).await.map_err(|_|fail(StatusCode::CONFLICT,"模型标识重复或配置保存失败"))?;
    }
    let shared_credential = sqlx::query_scalar::<_, Option<String>>(
        "SELECT credential_ciphertext FROM model_routes WHERE id=?",
    )
    .bind(&id)
    .fetch_one(&s.db)
    .await
    .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "来源凭证读取失败"))?;
    sqlx::query("UPDATE model_routes SET protocol=?,endpoint=?,credential_ciphertext=COALESCE(?,credential_ciphertext) WHERE source=? AND id<>?").bind(&i.protocol).bind(i.endpoint.trim()).bind(shared_credential).bind(i.source.trim()).bind(&id).execute(&s.db).await.map_err(|_|fail(StatusCode::INTERNAL_SERVER_ERROR,"来源配置同步失败"))?;
    audit(&s.db,&a.sub,"model.route.save",&id,json!({"model":i.model_key,"source":i.source,"protocol":i.protocol,"enabled":i.enabled,"credential_changed":i.api_key.as_deref().is_some_and(|v|!v.is_empty())})).await;
    Ok(Json(json!({"ok":true})))
}
async fn audit(db: &SqlitePool, actor: &str, action: &str, target: &str, detail: Value) {
    let _ = sqlx::query(
        "INSERT INTO audit_log(id,actor_id,action,target,detail_json) VALUES(?,?,?,?,?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(detail.to_string())
    .execute(db)
    .await;
}

async fn purge_expired_usage_records(db: &SqlitePool) {
    match sqlx::query(
        "DELETE FROM usage_records WHERE datetime(created_at) < datetime('now','-6 months')",
    )
    .execute(db)
    .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            tracing::info!(deleted = result.rows_affected(), "purged expired usage records");
        }
        Ok(_) => {}
        Err(error) => tracing::error!(%error, "failed to purge expired usage records"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::from_filename("../.env").or_else(|_| dotenvy::dotenv());
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be configured");
    anyhow::ensure!(
        jwt_secret.len() >= 32,
        "JWT_SECRET must contain at least 32 characters"
    );
    let dev_password = env::var("DEV_PASSWORD")
        .expect("DEV_PASSWORD must be configured for the seeded administrator");
    anyhow::ensure!(
        dev_password.len() >= 12 && dev_password != "change-me-now",
        "DEV_PASSWORD must be unique and at least 12 characters"
    );
    let initial_password =
        env::var("INITIAL_USER_PASSWORD").expect("INITIAL_USER_PASSWORD must be configured");
    anyhow::ensure!(
        initial_password.len() >= 12 && initial_password != "change-me-now",
        "INITIAL_USER_PASSWORD must be unique and at least 12 characters"
    );
    let upstream_key = env::var("UPSTREAM_API_KEY").expect("UPSTREAM_API_KEY must be configured");
    let credentials_key: [u8; 32] = BASE64
        .decode(
            env::var("CREDENTIALS_ENCRYPTION_KEY")
                .expect("CREDENTIALS_ENCRYPTION_KEY must be configured"),
        )?
        .try_into()
        .map_err(|_| {
            anyhow::anyhow!("CREDENTIALS_ENCRYPTION_KEY must decode to exactly 32 bytes")
        })?;
    let database_url =
        env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://data/llmroute.db?mode=rwc".into());
    if let Some(path) = database_url
        .strip_prefix("sqlite://")
        .and_then(|s| s.split('?').next())
    {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let sqlite_options = database_url
        .parse::<SqliteConnectOptions>()?
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));
    let db = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(sqlite_options)
        .await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    if env::var("APP_ENV").as_deref() == Ok("production") {
        sqlx::query(
            "DELETE FROM users WHERE username!='admin' AND password_hash='dev-placeholder'",
        )
        .execute(&db)
        .await?;
    }
    let redis = if let Ok(url) = env::var("REDIS_URL") {
        match redis::Client::open(url) {
            Ok(c) => c.get_connection_manager().await.ok(),
            Err(_) => None,
        }
    } else {
        None
    };
    let http = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(120))
        .pool_max_idle_per_host(128)
        .build()?;
    let state = AppState {
        db,
        redis,
        jwt_secret: Arc::new(jwt_secret),
        upstream_key: Arc::new(upstream_key),
        http,
        credentials_key: Arc::new(credentials_key),
        sandbox_url: Arc::new(
            env::var("AGENT_SANDBOX_URL").unwrap_or_else(|_| "http://agent-sandbox:8090".into()),
        ),
        sandbox_secret: Arc::new(env::var("AGENT_SANDBOX_SECRET").unwrap_or_default()),
    };
    let retention_db = state.db.clone();
    tokio::spawn(async move {
        loop {
            purge_expired_usage_records(&retention_db).await;
            tokio::time::sleep(std::time::Duration::from_secs(24 * 60 * 60)).await;
        }
    });
    let web_dist = env::var("WEB_DIST").unwrap_or_else(|_| "../web/dist".into());
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/agent/sandbox/execute", post(execute_agent_sandbox))
        .route("/api/agent/chat", post(agent_chat))
        .route("/api/auth/captcha", get(login_captcha))
        .route("/api/auth/login", post(login))
        .route("/api/auth/forgot-password", post(forgot_password))
        .route("/api/auth/reset-password", post(reset_password))
        .route("/api/dashboard", get(dashboard))
        .route("/api/settings", get(get_settings).put(put_settings))
        .route("/api/settings/email-test", post(test_email_settings))
        .route("/v1/models", get(openai_models))
        .route("/v1/chat/completions", post(openai_chat))
        .route("/v1/images/generations", post(openai_image_generation))
        .route("/v1/messages", post(anthropic_messages))
        .route(
            "/api/v1/services/aigc/text-generation/generation",
            post(dashscope_generation),
        )
        .route("/api/departments", get(departments).post(add_department))
        .route("/api/departments/{id}", put(update_department))
        .route("/api/users", get(users).post(add_user))
        .route("/api/users/batch", post(add_users_batch))
        .route("/api/users/{id}/limit", put(set_user_limit))
        .route("/api/users/{id}/department", put(set_user_department))
        .route("/api/users/{id}/contact", put(update_user_contact))
        .route("/api/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api/api-keys/{id}", axum::routing::delete(revoke_api_key))
        .route("/api/api-keys/{id}/stats", get(api_key_stats))
        .route("/api/usage", get(usage))
        .route("/api/prices", get(prices).post(add_price))
        .route("/api/protocols", get(protocols))
        .route("/api/protocols/{id}", put(put_protocol))
        .route("/api/models", get(model_routes))
        .route("/api/models/{id}", put(save_model_route))
        .fallback_service(
            ServeDir::new(&web_dist)
                .not_found_service(ServeFile::new(format!("{web_dist}/index.html"))),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(
            CorsLayer::new()
                .allow_origin("http://localhost:5173".parse::<HeaderValue>().unwrap())
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
        )
        .layer(TraceLayer::new_for_http());
    let port = env::var("PORT").unwrap_or_else(|_| "7900".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    tracing::info!("llmroute server listening on {port}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
