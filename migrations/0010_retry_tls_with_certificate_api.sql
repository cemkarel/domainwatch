UPDATE targets
SET next_check = 0, lease = NULL
WHERE tls_expiry IS NULL
  AND tls_status IN ('scanner_unconfigured', 'scanner_error', 'scanner_timeout', 'tls_unreachable',
                     'tls_certificate_unavailable', 'tls_untrusted', 'no_public_address');
