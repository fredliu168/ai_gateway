CREATE TABLE IF NOT EXISTS login_captcha_challenges (
  captcha_id TEXT PRIMARY KEY,
  answer_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_captcha_expires_at
  ON login_captcha_challenges(expires_at);
