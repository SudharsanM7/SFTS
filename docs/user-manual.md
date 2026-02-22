# User Manual

## 1) Setup
- Create virtual environment and install `requirements.txt`.
- Start app with `PYTHONPATH=src` and `python -m sfts.webapp`.
- Open `http://127.0.0.1:5000`.

## 2) Account creation and login
- Register with username, strong password, and optional email.
- Login with username/password.
- If MFA is enabled, complete `/mfa/verify` with TOTP or backup code.

## 3) MFA enablement
- Open **MFA Setup**.
- Click **Generate MFA Secret**.
- Scan displayed QR code in authenticator app.
- Enter one valid code and click **Enable MFA**.
- Store backup codes securely.

## 4) Sending files
1. Open **Send**.
2. Enter recipient username.
3. Select file or drag/drop multiple files/folder.
4. Set transfer TTL (1h / 24h / 7d / 30d).
5. Optionally add encrypted note.
6. Choose compression on/off.
7. Optionally enable share link, password, and max uses.
8. Enter transfer secret and submit.

### Send results and messages
- Success: transfer queued and visible in **History**.
- Validation errors: shown as toasts (recipient not found, quota exceeded, missing file, etc).
- Upload progress card shows percent, speed, ETA, and bytes sent.

## 5) Receiving files
1. Open **Receive**.
2. Confirm pending filename.
3. Enter transfer secret and output filename.
4. Click decrypt.

### Receive outcomes
- Success: status set to `received`, success message shown, note displayed if present.
- Integrity/decryption failure: status set to `failed` with error message.
- Expired transfer: marked deleted and removed from pending receive flow.

## 6) Inbox and history

### Inbox
- Shows incoming transfers with sender, size, status, created time, and expiry.
- Supports search, status filter, and sort.

### History
- Shows sent transfers with recipient, size, status, created time, and expiry.
- Supports search, recipient filter, and sort.

## 7) Live notifications and sessions
- Real-time updates via SSE update unread count and inbox counters.
- Toast notifications surface new events and errors.
- Session warning appears before timeout.
- Session management page allows revoking single session or all other sessions.

## 8) Share links
- Sender can create share links at send-time.
- Receiver of link opens `/share/<token>`, enters link password (if set) and transfer secret.
- Link expiry and usage limits are enforced.

## 9) Admin usage
- Open **Admin** as admin role user.
- Available functions:
	- Run worker
	- View transfer/security metrics and activity heatmap
	- Manage blocked IPs
	- Export audit CSV
	- Generate user keypairs
	- Set per-user quotas
	- Create backup and restore from backup file
	- Manage email templates

## 10) API and docs
- API docs UI: `/api/docs`
- OpenAPI JSON: `/api/openapi.json`
- Health endpoint: `/health`
- Multipart APIs:
	- `POST /api/transfers/init`
	- `POST /api/transfers/<transfer_id>/chunk/<chunk_no>`
	- `POST /api/transfers/<transfer_id>/finalize`

## Troubleshooting quick list
- Login loops: verify session cookie and server time sync.
- File send errors: check recipient validity, quotas, and transfer secret.
- Receive failures: verify exact transfer secret and transfer is not expired.
- Database locks: ensure single SQLite file path and app-level connection reuse (already implemented).
