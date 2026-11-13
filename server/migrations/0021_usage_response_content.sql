ALTER TABLE usage_records ADD COLUMN response_content TEXT;
ALTER TABLE usage_records ADD COLUMN response_content_truncated INTEGER NOT NULL DEFAULT 0;
