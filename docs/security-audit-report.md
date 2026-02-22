# Security Audit Report

## Scope
Audit covered authentication, session handling, transfer confidentiality/integrity, replay protections, route connectivity, messaging behavior, and operational controls.

## Verification results
- Unit tests: `4 passed`
- Integration check: register/login/send/receive/inbox/history and key endpoint connectivity passed
- Static checks: no compile/lint errors on modified Python/template files

## Implemented controls
- Password policy enforcement at registration
- Session expiry + sliding renewal
- MFA (TOTP + backup codes + QR enrollment)
- Transfer encryption (AES-256-CBC with PBKDF2-derived key)
- Integrity check on decrypt
- Replay-oriented metadata validation
- Progressive IP blocking + security alerts
- Audit logging and CSV export
- Quota enforcement for send path
- Transfer TTL expiration with cleanup logic
- Share link expiry/password/usage enforcement

## Findings from this audit pass
1. Async send flow could mask backend errors for XHR submissions.
	- Fixed: send route now returns explicit JSON on async calls; frontend displays server message.
2. Receive flow did not proactively clear expired queued transfer before decrypt.
	- Fixed: expired pending transfer is marked deleted and shown with clear message.
3. Startup DB lock risk in admin bootstrap due nested connection writes.
	- Fixed: admin bootstrap now reuses initialization connection.

## Remaining risk / production notes
- Current deployment uses Flask dev server; production should use WSGI server.
- SMTP is optional and environment-dependent; notification delivery depends on mail config.
- SQLite is suitable for low-scale/single-instance usage; multi-instance should use external DB.
- API docs iframe depends on external Swagger viewer availability.

## Recommendations
- Enforce HTTPS/TLS termination in deployment.
- Add automated integration tests to CI pipeline.
- Add structured logging and alert forwarding (SIEM) for security events.
- Move long-running worker operations to dedicated process queue.
