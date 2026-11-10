ALTER TABLE usage_records ADD COLUMN video_duration_seconds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_records ADD COLUMN video_resolution TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS video_tasks (
  task_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  upstream_task_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id),
  department_id TEXT REFERENCES departments(id),
  api_key_id TEXT REFERENCES api_keys(id),
  model TEXT NOT NULL,
  upstream_endpoint TEXT NOT NULL,
  credential_ciphertext TEXT,
  duration_seconds INTEGER NOT NULL,
  resolution TEXT NOT NULL,
  rate_micros_per_second INTEGER NOT NULL,
  reserved_micros INTEGER NOT NULL,
  price_id TEXT NOT NULL,
  task_status TEXT NOT NULL DEFAULT 'PENDING',
  settled INTEGER NOT NULL DEFAULT 0,
  response_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_video_tasks_owner ON video_tasks(user_id,api_key_id,created_at);
