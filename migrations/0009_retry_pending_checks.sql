UPDATE targets
SET next_check = 0, lease = NULL
WHERE checked_at IS NULL OR tls_status = 'pending';
