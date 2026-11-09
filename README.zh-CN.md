# 汇智 AI Gateway

**语言：** [English](README.md) | 简体中文

本项目采用 [MIT License](LICENSE)。

Rust + SQLite + Redis 的企业大模型转发管理平台。平台使用本地账号体系，按 Token 价格对模型调用计费，并提供部门额度、个人额度、统计与审计。

## 本地开发

要求 Rust stable、Node.js 22+、npm。Redis 用于缓存与减轻管理读取压力；未配置时服务可降级运行。

```sh
cp .env.example .env
# 配置 JWT_SECRET、INITIAL_USER_PASSWORD、UPSTREAM_API_KEY
# 设置独立的 CREDENTIALS_ENCRYPTION_KEY（base64 编码的 32 字节随机值）
cd server && cargo run
# 新开终端
cd web && npm install && npm run dev
```

Web 开发地址为 http://localhost:5173，API 端口为 7900。管理员账号及初始化密码以本地 `.env` 配置为准。新建成员的初始密码使用 `INITIAL_USER_PASSWORD`。系统管理员可在系统设置的“邮箱发送”中配置 SMTP STARTTLS；成员邮箱用于密码重置邮件。开发迁移中的初始组织数据只用于初始化；控制台统计读取 SQLite 中真实的调用记录，无调用时显示零值和空状态。

## 额度与计费

- 新建部门默认月度总额度 ¥800，成员个人月度额度默认 ¥100；部门管理员个人额度调整上限由系统管理员按部门配置，默认 ¥100。
- 额度按自然月使用，每月自动重置，未使用金额不结转。
- 模型价格以元 / 百万 Tokens 配置，管理员只需设置高峰价格，空闲价格由系统按 50% 自动计算。DeepSeek 按量调用在北京时间周一至周五（中国法定节假日除外）09:00–12:00、14:00–18:00按高峰价，其余时段（含周末和中国法定节假日）按半价。系统管理员需在系统设置中按国务院年度安排维护法定节假日日期；跨时段请求按请求开始时间确定费率。
- 调用费用、Token 数、请求状态和耗时保存为统计/审计元数据。服务端不保存提示词与模型响应正文。Playground 历史只保存在当前浏览器的本地存储中。

## 渠道与模型

系统管理员可配置多个渠道，每个渠道可接入多个模型；各模型单独维护价格。渠道保存上游协议、地址和加密后的凭据。

创建渠道时可一键读取上游模型目录，并手动移除不需要接入的模型；已接入渠道也可再次拉取目录，勾选新增模型。也支持手动填写模型标识。

网关支持 OpenAI Chat Completions、Anthropic Messages 和 DashScope 原生 Generation 三种客户端协议，均支持流式与非流式响应。使用同一 API 密钥和平台模型标识；协议适配共用额度检查、用量统计和计费。模型如通过 OpenAI 兼容流式数据返回 `reasoning_content`，Playground 会显示思考内容。

## 网关调用

登录页会先请求 `GET /api/auth/captcha` 获取 5 分钟有效的一次性图像验证码。登录时提交 `captcha_id` 和 `captcha`，账号/IP 限流仍会继续生效。登录接口示例：

```sh
curl -sS http://localhost:7900/api/auth/captcha
# 浏览器登录页会展示 CAPTCHA.image，并提交对应 CAPTCHA.captcha_id 和用户输入。
curl -X POST http://localhost:7900/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"account":"admin","password":"<本地配置的初始密码>","captcha_id":"<captcha_id>","captcha":"<图中字符>"}'
```

使用返回的 token 调用已启用模型：

```sh
curl -N http://localhost:7900/v1/chat/completions \
  -H 'Authorization: Bearer <JWT>' \
  -H 'Content-Type: application/json' \
  -d '{"model":"DeepSeek-V4-Flash","messages":[{"role":"user","content":"你好"}],"stream":true}'
```

同一个模型也可通过 Anthropic Messages 或 DashScope 原生 Generation 格式调用，支持 `stream: true/false`：

```sh
# Anthropic Messages（可使用 Authorization: Bearer 或 x-api-key）
curl -N http://localhost:7900/v1/messages \
  -H 'x-api-key: <API_KEY>' -H 'anthropic-version: 2023-06-01' \
  -H 'Content-Type: application/json' \
  -d '{"model":"DeepSeek-V4-Flash","max_tokens":512,"messages":[{"role":"user","content":"你好"}],"stream":true}'

# DashScope 原生 Generation（Bearer 认证）
curl -N http://localhost:7900/api/v1/services/aigc/text-generation/generation \
  -H 'Authorization: Bearer <API_KEY>' -H 'Content-Type: application/json' \
  -d '{"model":"DeepSeek-V4-Flash","input":{"messages":[{"role":"user","content":"你好"}]},"parameters":{"result_format":"message","incremental_output":true},"stream":true}'
```

网关提供 OpenAI `GET /v1/models`、`POST /v1/chat/completions`，Anthropic `POST /v1/messages`，以及 DashScope `POST /api/v1/services/aigc/text-generation/generation`。三种协议都支持流式和非流式；请求使用平台配置的模型标识。DeepSeek-V4-Flash 默认渠道已预置，填写上游 API Key 后即可使用。除平台登录 JWT 外，也可创建多把用户 API 密钥；密钥调用同时受密钥、个人和部门额度限制，密钥详情可按模型查看调用次数、Token 与费用，撤销后立即失效。服务端仅保存统计与审计元数据。调用记录保留六个月，服务启动时及之后每 24 小时自动清理超期记录；额度流水和管理员审计日志不受此清理策略影响。

## 管理 API

- `POST /api/auth/login`
- `GET /api/health`
- `GET /api/dashboard`
- `GET|POST /api/departments`
- `PUT /api/departments/{id}`
- `GET|POST /api/users`
- `PUT /api/users/{id}/contact`
- `POST /api/auth/forgot-password`、`POST /api/auth/reset-password`
- `POST /api/settings/email-test`
- `PUT /api/users/{id}/limit`
- `GET /api/usage`
- `GET|POST /api/prices`
- `GET /api/protocols`、`PUT /api/protocols/{id}`
- `GET /api/models`、`PUT /api/models/{id}`

管理 API 使用 `Authorization: Bearer <JWT>`。统计和导出按当前登录用户权限范围返回，不对统计字段脱敏。

## Ubuntu 部署

可使用 Docker Compose：设置强随机 `JWT_SECRET`、管理员初始密码、上游模型密钥与凭据加密密钥后运行 `docker compose up -d --build`。服务监听 TCP 7900。对外开放端口前配置 TLS 反向代理和防火墙策略。

重置密码链接默认使用请求的访问域名生成；通过反向代理部署时可配置 `PUBLIC_BASE_URL` 为外部 HTTPS 地址。也提供 `deploy/llmroute.service` systemd 模板。SQLite 数据必须放在持久卷并定期备份，同时妥善备份凭据加密密钥。项目预期目标为 10,000 用户、峰值并发 100、100 RPS；高并发验收和 SQLite 写入能力需在目标机器上压测确认，10 ms 目标需明确统计口径。
