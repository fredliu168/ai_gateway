CREATE TABLE IF NOT EXISTS model_routes (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  source TEXT NOT NULL,
  model_key TEXT NOT NULL UNIQUE,
  upstream_model TEXT NOT NULL,
  protocol TEXT NOT NULL CHECK(protocol IN ('openai','anthropic','dashscope')),
  endpoint TEXT NOT NULL,
  credential_ciphertext TEXT,
  billing_mode TEXT NOT NULL DEFAULT 'pay_as_you_go',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO model_routes(id,display_name,source,model_key,upstream_model,protocol,endpoint,billing_mode,enabled)
VALUES('route-deepseek-v4-flash','DeepSeek-V4-Flash','中国移动云','DeepSeek-V4-Flash','DeepSeek-V4-Flash','openai','https://moma.cmecloud.cn/tokenplan-personal/v1/chat/completions','pay_as_you_go',1);
