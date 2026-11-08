PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS departments (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  monthly_limit_cents INTEGER NOT NULL DEFAULT 0,
  member_limit_cap_cents INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('platform_admin','department_admin','user')),
  department_id TEXT REFERENCES departments(id),
  personal_limit_cents INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS model_prices (
  id TEXT PRIMARY KEY,
  model TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'pay_as_you_go',
  input_per_million_micros INTEGER NOT NULL,
  output_per_million_micros INTEGER NOT NULL,
  cache_per_million_micros INTEGER NOT NULL,
  night_input_per_million_micros INTEGER NOT NULL,
  night_output_per_million_micros INTEGER NOT NULL,
  night_cache_per_million_micros INTEGER NOT NULL,
  effective_from TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS model_protocols (
  id TEXT PRIMARY KEY,
  model TEXT NOT NULL,
  protocol TEXT NOT NULL CHECK(protocol IN ('openai','anthropic','dashscope')),
  base_url TEXT NOT NULL DEFAULT '',
  upstream_model TEXT NOT NULL DEFAULT '',
  api_key_ciphertext TEXT,
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS usage_records (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id),
  department_id TEXT REFERENCES departments(id),
  model TEXT NOT NULL,
  protocol TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  cache_tokens INTEGER NOT NULL DEFAULT 0,
  cost_micros INTEGER NOT NULL DEFAULT 0,
  price_id TEXT,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  error_code TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS quota_ledger (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  department_id TEXT,
  entry_type TEXT NOT NULL,
  amount_micros INTEGER NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  actor_id TEXT,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO departments(id,name,monthly_limit_cents,member_limit_cap_cents) VALUES
('dept-platform','平台研发部',5000000,1000000),('dept-product','产品设计部',3000000,600000),('dept-sales','市场运营部',2400000,500000);
INSERT OR IGNORE INTO users(id,username,display_name,password_hash,role,department_id,personal_limit_cents) VALUES
('user-admin','admin','平台管理员','dev-placeholder','platform_admin',NULL,0),
('user-lin','linxia','林夏','dev-placeholder','department_admin','dept-platform',1000000),
('user-chen','chenyu','陈宇','dev-placeholder','user','dept-platform',300000),
('user-zhou','zhouyi','周怡','dev-placeholder','user','dept-product',200000);
INSERT OR IGNORE INTO model_prices(id,model,mode,input_per_million_micros,output_per_million_micros,cache_per_million_micros,night_input_per_million_micros,night_output_per_million_micros,night_cache_per_million_micros,effective_from)
VALUES('price-dsv41f-001','DeepSeek-V4.1-Flash','pay_as_you_go',2000000,8000000,40000,1000000,4000000,20000,'2026-11-07T00:00:00+08:00');
INSERT OR IGNORE INTO model_protocols(id,model,protocol,base_url,upstream_model,enabled) VALUES
('proto-openai','DeepSeek-V4.1-Flash','openai','https://api.example.invalid/v1','deepseek-v4.1-flash',1),
('proto-anthropic','DeepSeek-V4.1-Flash','anthropic','https://api.example.invalid/anthropic','deepseek-v4.1-flash',1),
('proto-dashscope','DeepSeek-V4.1-Flash','dashscope','https://api.example.invalid/compatible-mode/v1','deepseek-v4.1-flash',1);
