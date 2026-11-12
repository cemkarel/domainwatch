UPDATE targets
SET next_check = 0, lease = NULL
WHERE tls_expiry IS NULL
  AND tls_status IN ('no_public_address', 'tls_certificate_unavailable');
