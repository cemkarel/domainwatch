CREATE TABLE users (
  id TEXT PRIMARY KEY,
  login TEXT NOT NULL
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires INTEGER NOT NULL
);
CREATE INDEX sessions_expiration ON sessions(expires);

CREATE TABLE targets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  domain TEXT NOT NULL,
  domain_status TEXT NOT NULL DEFAULT 'pending',
  domain_expiry TEXT,
  tls_status TEXT NOT NULL DEFAULT 'pending',
  tls_expiry TEXT,
  checked_at INTEGER,
  next_check INTEGER NOT NULL DEFAULT 0,
  lease TEXT,
  UNIQUE (user_id, hostname)
);
CREATE INDEX targets_schedule ON targets(next_check);

CREATE TABLE notifications (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  encrypted_url TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  thresholds TEXT NOT NULL,
  version TEXT NOT NULL
);

CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('domain', 'tls')),
  expiry TEXT NOT NULL,
  threshold INTEGER NOT NULL,
  settings_version TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt INTEGER NOT NULL,
  last_result TEXT,
  updated_at INTEGER NOT NULL,
  claim TEXT,
  UNIQUE(target_id, kind, expiry, threshold)
);
CREATE INDEX alerts_schedule ON alerts(state, next_attempt);
CREATE INDEX alerts_target ON alerts(target_id);
