UPDATE targets
SET next_check = 0, lease = NULL
WHERE tls_status IN ('scanner_unconfigured', 'scanner_configuration_error', 'scanner_error');
