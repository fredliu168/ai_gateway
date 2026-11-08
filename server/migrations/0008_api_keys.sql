CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    monthly_limit_cents INTEGER NOT NULL CHECK(monthly_limit_cents >= 0),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_active ON api_keys(user_id, active);
ALTER TABLE usage_records ADD COLUMN api_key_id TEXT REFERENCES api_keys(id);
ALTER TABLE quota_ledger ADD COLUMN api_key_id TEXT REFERENCES api_keys(id);
CREATE INDEX IF NOT EXISTS idx_usage_api_key_month ON usage_records(api_key_id, created_at, status);
CREATE INDEX IF NOT EXISTS idx_ledger_api_key_window ON quota_ledger(api_key_id, entry_type, created_at);
