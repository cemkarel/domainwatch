UPDATE targets
SET next_check = 0, lease = NULL
WHERE tls_expiry IS NULL
  AND tls_status IN ('tls_unreachable', 'tls_certificate_unavailable', 'tls_untrusted');
