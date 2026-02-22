# Secure File Transfer System (SFTS)

SFTS is a Flask-based secure file transfer application with authentication, MFA, encrypted transfer workflows, operational dashboards, and admin/security tooling.

## Core capabilities

### Authentication and security
- User registration/login with password policy enforcement
- Session token management with sliding expiration
- MFA (TOTP + backup codes) with QR-based enrollment
- Security event logging, alerts, and progressive IP blocking
- Replay/integrity protections in transfer metadata pipeline

### Secure transfer workflow
- AES-256-CBC encryption with PBKDF2-derived key material
- Per-transfer secret workflow (no account-password sharing required)
- Encrypted transfer notes
- Transfer expiration (TTL) with automated cleanup
- Optional compression before encryption
- File + folder/batch upload (folder upload is zipped then encrypted)

### Real-time UI and usability
- Live updates with Server-Sent Events (SSE)
- Upload progress metrics (percent, bytes, speed, ETA)
- Toast notifications for success/error/info states
- Search/filter/sort for inbox and transfer history
- Session management page (view and revoke active sessions)
- Dark/light theme toggle with local persistence and OS preference detection

### Sharing and APIs
- Share links with optional password, expiry, and usage limits
- Multipart transfer API endpoints
- OpenAPI JSON and in-app API docs page

### Admin and operations
- Admin dashboard with transfer/security metrics and heatmap
- DDoS/frequency visibility and blocked IP management
- Transfer worker trigger and cleanup execution
- Audit CSV export
- Per-user quota controls (daily/monthly/storage)
- Database backup creation + restore workflow
- Email template management for operational notifications

## Project structure
- src/sfts: application modules
- src/sfts/templates: Jinja templates
- tests: unit tests
- docs: user, developer, threat model, and audit docs

## Quick start
1. Create and activate a Python virtual environment.
2. Install dependencies:
	- `pip install -r requirements.txt`
3. Run the app:
	- `set PYTHONPATH=src` (Windows cmd) or `$env:PYTHONPATH='src'` (PowerShell)
	- `python -m sfts.webapp`
4. Open `http://127.0.0.1:5000`

## Key routes
- UI: `/`, `/register`, `/login`, `/dashboard`, `/send`, `/receive`, `/inbox`, `/history`, `/sessions`, `/admin`
- MFA: `/mfa/setup`, `/mfa/verify`
- Sharing: `/share/<token>`
- API docs: `/api/docs`, `/api/openapi.json`
- Multipart API:
  - `POST /api/transfers/init`
  - `POST /api/transfers/<transfer_id>/chunk/<chunk_no>`
  - `POST /api/transfers/<transfer_id>/finalize`
- Health: `GET /health`

## Default admin bootstrap
- Username: `admin`
- Password: `Admin!123456`

Override with environment variables before first run:
- `SFTS_ADMIN_USERNAME`
- `SFTS_ADMIN_PASSWORD`

## Connectivity and data integrity notes
- All UI navigation and form actions are route-linked via `url_for(...)`.
- Send -> History, Receive -> Inbox/Status, and audit/notification pipelines are connected and validated.
- Expired transfers are removed from active receive flow and marked deleted.
- Worker execution includes queued-job completion + cleanup + reminder checks.

## Verification status
- Unit tests: passing (`4 passed`)
- Integration flow check: register/login/send/receive/inbox/history/API connectivity validated

## Attribution
This project was made by Sudharsan M with the help of AI Assisted Coding.
