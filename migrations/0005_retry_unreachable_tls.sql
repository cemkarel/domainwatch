UPDATE targets
SET next_check = 0, lease = NULL
WHERE tls_status = 'tls_unreachable' AND tls_expiry IS NULL;
