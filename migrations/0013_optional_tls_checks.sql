ALTER TABLE targets ADD COLUMN tls_enabled INTEGER NOT NULL DEFAULT 0 CHECK (tls_enabled IN (0, 1));

UPDATE targets SET tls_enabled = 1 WHERE tls_expiry IS NOT NULL;

UPDATE targets
SET tls_status = 'disabled',
    next_check = CASE WHEN lease IS NOT NULL THEN 0 ELSE next_check END,
    lease = NULL
WHERE tls_enabled = 0;
