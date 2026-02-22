# Developer Guide

## Architecture overview
- Framework: Flask + Jinja templates
- Storage: SQLite (`src/sfts/db.py`) with WAL + busy timeout
- Crypto path: `src/sfts/crypto.py`, `src/sfts/client.py`, `src/sfts/server.py`
- Security and upgrades: `src/sfts/upgrades.py`, `src/sfts/features.py`
- Auth/session: `src/sfts/auth.py`, MFA in `src/sfts/mfa.py`

## Important modules
- `webapp.py`: route handlers, UI/API integration, request guards
- `db.py`: schema creation/migrations and connection factory
- `features.py`: quotas, compression helpers, share links, notifications, metrics, backup helpers, email helper logic
- `upgrades.py`: worker, blocking, audit, multipart operations, health checks

## Request flow highlights

### Send flow
1. Validate session and recipient.
2. Optional batch/folder zip packaging.
3. Optional compression.
4. Quota validation.
5. Encrypt + metadata generation.
6. Persist transfer row and enqueue worker job.
7. Add audit + notification + optional share link.

### Receive flow
1. Resolve earliest queued transfer.
2. Reject/mark expired transfer.
3. Decrypt and integrity-verify.
4. Optional decompression.
5. Update transfer status + notifications + audit.

### Inbox/history flow
- Query-backed search/filter/sort over transfer state.
- Joined views include sender/recipient names for proper sorting labels.

## Connectivity map (key routes)
- Auth/UI: `/`, `/register`, `/login`, `/logout`, `/dashboard`
- MFA: `/mfa/setup`, `/mfa/verify`
- Transfers: `/send`, `/receive`, `/inbox`, `/history`, `/share/<token>`
- Sessions: `/sessions`, `/sessions/revoke`, `/sessions/revoke-others`
- Live channels: `/events`, `/notifications/read`, `/api/session-status`
- API: `/api/transfers/init`, `/api/transfers/<transfer_id>/chunk/<chunk_no>`, `/api/transfers/<transfer_id>/finalize`
- Docs/health: `/api/docs`, `/api/openapi.json`, `/health`
- Admin: `/admin` and associated admin action routes

## Front-end behavior notes
- Base template owns:
	- dark/light theme persistence
	- flash-to-toast conversion
	- SSE subscription and notification rendering
	- session-expiry warning polling
- Send page owns:
	- drag/drop + multi-file preview
	- XHR progress meter
	- explicit JSON-based success/failure handling

## Data consistency and lock avoidance
- Connection reuse is used for multi-write request sections.
- Nested writes accept optional existing connection to prevent SQLite lock contention.
- `init_db` uses in-connection admin bootstrap to avoid startup write races.

## Testing
- Unit tests: `pytest -q`
- Integration sanity:
	- register/login
	- send/receive
	- inbox/history visibility
	- health/docs/session endpoint reachability

## Extension recommendations
- Move backup execution and heavy tasks to dedicated background worker process.
- Add integration tests to CI for route-link and template-action validation.
- Replace SQLite with PostgreSQL for multi-instance deployments.
