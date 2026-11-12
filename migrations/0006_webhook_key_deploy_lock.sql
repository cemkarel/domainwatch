CREATE TABLE webhook_key_deploy_lock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  holder TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
