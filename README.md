# LLMRoute

**Language:** English | [简体中文](README.zh-CN.md)

LLMRoute is a self-hosted AI model gateway for teams. It combines model routing, access control, quotas, usage-based billing, and audit metadata in one service.

> **Project status:** Early-stage and evolving. Review the security notes before exposing an instance to the internet.

## Features

- Route requests to configured providers using OpenAI Chat Completions, Anthropic Messages, or DashScope Generation APIs.
- Support streaming and non-streaming text requests, plus image generation where the selected provider and model support it.
- Manage users, departments, API keys, monthly quotas, model prices, and usage records.
- Store usage and audit metadata without storing prompt or model response bodies.
- Run locally or deploy with Docker Compose; SQLite is used for persistent application data and Redis is optional for caching.

## Quick start (development)

Requirements: Rust stable, Node.js 22+, npm, and (optionally) Redis.

```sh
cp .env.example .env
# Set strong, unique secrets in .env. See Configuration below.
# Load repository-root environment variables before starting the API.
set -a && . ./.env && set +a
cd server && cargo run
# In another terminal:
cd web && npm ci && npm run dev
```

The Vite development server is available at <http://localhost:5173>; the API listens on port `7900`. The application interface is currently Simplified Chinese. Initial administrator credentials are configured locally; do not use example or weak credentials in a reachable deployment.

## Configuration

Start from [.env.example](.env.example). At minimum, set unique random values for `JWT_SECRET`, `INITIAL_USER_PASSWORD`, `UPSTREAM_API_KEY`, `CREDENTIALS_ENCRYPTION_KEY`, and `AGENT_SANDBOX_SECRET` as required by the Compose configuration. Generate a 32-byte encryption key and encode it as Base64, for example:

```sh
openssl rand -base64 32
```

Keep `.env` and backups of `CREDENTIALS_ENCRYPTION_KEY` private. Losing the encryption key can make stored provider credentials unrecoverable. Never commit secrets, production databases, or user data.

## Docker deployment

1. Copy `.env.example` to `.env` and fill in strong secrets and provider credentials.
2. Put a TLS-enabled reverse proxy in front of the service, restrict direct access to port `7900`, and configure `PUBLIC_BASE_URL` to the public HTTPS URL when password-reset links are used.
3. Start the stack:

   ```sh
   docker compose up -d --build
   ```

4. Check health at `https://your-host/api/health` and verify that the named data volumes are backed up.

The Compose setup mounts `/var/run/docker.sock` into the Agent sandbox to create isolated workspaces. Access to the Docker socket is effectively host-level control. Only enable this deployment for trusted administrators on a host dedicated to the service; do not expose the socket or sandbox control API to users or the public internet. Review and adapt the sandbox limits and host security controls before enabling Agent features.

SQLite data is persisted in the `llmroute-data` volume. Back up the database and the credentials encryption key together. Usage records are retained for six months and automatically purged; quota ledger entries and administrator audit logs are not covered by that retention window.

## Gateway example

Obtain a platform API key from the application, then send requests using the model identifier configured by an administrator.

```sh
curl https://your-host/v1/chat/completions \
  -H 'Authorization: Bearer <API_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"model":"<MODEL_ID>","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

Supported routes include `GET /v1/models`, `POST /v1/chat/completions`, `POST /v1/messages`, and `POST /api/v1/services/aigc/text-generation/generation`. Provider availability and request compatibility depend on the configured upstream channel and model.

## Development checks

```sh
cd server && cargo check
cd web && npm run build
```

## Documentation and community

- [简体中文 documentation](README.zh-CN.md)
- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Product requirements (Chinese)](需求说明书.md)

Please report security issues privately as described in [SECURITY.md](SECURITY.md). A license has not yet been selected; until a `LICENSE` file is added, no permission to use, modify, or redistribute this code is granted by this repository.
