UPDATE targets
SET next_check = 0
WHERE domain LIKE '%.tr'
  AND domain_expiry IS NULL
  AND domain_status IN ('unsupported', 'bootstrap_unavailable', 'rdap_error')
  AND lease IS NULL;
