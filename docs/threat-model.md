# Threat Model

## Assets
- User credentials and MFA secrets
- Session tokens
- Transfer payloads and metadata
- Audit logs, security alerts, and backup artifacts
- Share-link tokens and optional link passwords

## Trust boundaries
- Browser/client <-> Flask server
- Flask app <-> SQLite DB
- Flask app <-> local filesystem (uploads/chunks/backups)
- Flask app <-> SMTP provider (optional)

## Primary threat scenarios
1. Credential attacks (brute force / weak passwords)
2. Session theft / stale session reuse
3. Transfer tampering or invalid decrypt attempts
4. Replay-like metadata reuse attempts
5. Abuse spikes (high-frequency requests / DDoS behavior)
6. Unauthorized share-link use
7. Data retention risk from expired transfers not purged

## Implemented mitigations
- Password policy requirements and salted iterative hashing
- Session expiry with renewal and session revocation controls
- MFA with TOTP and backup codes
- Encrypted transfer path + integrity verification on receive
- Security event + alert capture with admin visibility
- IP-based progressive blocking and unblock controls
- Share-link controls: token + optional password + expiry + max uses
- Transfer TTL + cleanup support in worker/admin flow
- Audit logging for key actions (login, transfer, admin actions)

## Residual risks
- If deployed without TLS, network metadata remains exposed.
- Host compromise can expose stored encrypted payloads and DB.
- Shared transfer secret distribution is out-of-band and user-dependent.
- SQLite concurrency/scaling limits in high-load distributed deployments.

## Recommended future controls
- Enforce HTTPS-only deployment and secure cookie flags behind proxy.
- Move secrets and encryption controls to managed key system.
- Adopt external database and queue for scale and durability.
- Add anomaly detection around repeated decrypt/share failures.
