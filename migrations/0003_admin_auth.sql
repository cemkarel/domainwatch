CREATE TABLE admin_credentials (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE admin_sessions (
  token_hash TEXT PRIMARY KEY,
  password_version INTEGER NOT NULL,
  expires INTEGER NOT NULL
);
CREATE INDEX admin_sessions_expiration ON admin_sessions(expires);
