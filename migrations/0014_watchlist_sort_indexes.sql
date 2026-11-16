CREATE INDEX targets_domain_expiry ON targets (user_id, domain_expiry, hostname);
CREATE INDEX targets_tls_expiry ON targets (user_id, tls_expiry, hostname);
