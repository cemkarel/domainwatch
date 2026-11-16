ALTER TABLE targets ADD COLUMN tls_next_check INTEGER NOT NULL DEFAULT 0;
ALTER TABLE targets ADD COLUMN tls_checked_at INTEGER;
ALTER TABLE targets ADD COLUMN lease_until INTEGER NOT NULL DEFAULT 0;

UPDATE targets SET tls_next_check = next_check,
  tls_checked_at = CASE WHEN tls_status != 'pending' THEN checked_at END
WHERE tls_enabled = 1;

UPDATE targets SET lease_until = next_check WHERE lease IS NOT NULL;

CREATE INDEX targets_tls_schedule ON targets(tls_next_check) WHERE tls_enabled = 1;
