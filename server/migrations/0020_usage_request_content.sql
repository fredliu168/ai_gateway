ALTER TABLE usage_records ADD COLUMN request_content TEXT;
ALTER TABLE usage_records ADD COLUMN request_content_truncated INTEGER NOT NULL DEFAULT 0;
