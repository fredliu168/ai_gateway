CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO app_settings(key, value) VALUES ('workspace_name', '启明科技');
INSERT OR IGNORE INTO app_settings(key, value) VALUES ('time_zone', 'Asia/Shanghai');
