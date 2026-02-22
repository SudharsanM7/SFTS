from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from flask import (
    Flask,
    flash,
    jsonify,
    Response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .auth import (
    get_user_by_username,
    is_admin,
    login_user,
    register_user,
    validate_session,
)
from .db import get_connection, get_db_path, init_db
from .client import prepare_transfer
from .config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    DB_PATH,
    DEFAULT_TRANSFER_TTL_HOURS,
    DDOS_CRITICAL_REQUESTS_PER_WINDOW,
    DDOS_SUSPECT_REQUESTS_PER_WINDOW,
    ENABLE_COMPRESSION_DEFAULT,
    EVENT_STREAM_POLL_SECONDS,
    FREQUENCY_LOOKBACK_MINUTES,
    MAX_BATCH_FILES,
    MAX_SHARE_LINK_DOWNLOADS,
    PASSWORD_HASH_ITERATIONS,
    PBKDF2_ITERATIONS,
    REQUEST_WINDOW_SECONDS,
    SECURITY_EVENTS_LIMIT,
    SESSION_WARNING_SECONDS,
    SESSION_TTL,
)
from .crypto import derive_key
from .features import (
    add_notification,
    check_quota_allowance,
    cleanup_expired_transfers,
    consume_share_link,
    create_backup_file,
    create_share_link,
    decrypt_note,
    encrypt_note,
    expires_at_from_ttl,
    mark_notifications_read,
    maybe_compress_file,
    maybe_decompress_file,
    openapi_spec,
    parse_ttl_hours,
    render_email_template,
    revoke_other_sessions,
    revoke_session,
    send_email_if_configured,
    send_security_email,
    session_details,
    summarize_metrics,
    unread_notifications,
    validate_share_link,
    zip_files_for_upload,
)
from .mitm import MitmSimulator
from .mfa import (
    enable_mfa,
    is_mfa_enabled,
    qr_code_data_uri,
    setup_mfa_for_user,
    totp_uri,
    verify_mfa_code,
)
from .server import TransferReceiver
from .transfer import TransferMetadata
from .upgrades import (
    append_audit_log,
    apply_progressive_block,
    create_security_alert,
    export_audit_report,
    finalize_transfer,
    generate_user_keypair,
    health_check,
    init_multipart_transfer,
    is_request_allowed,
    queue_transfer_job,
    run_transfer_worker,
    upload_chunk,
)


UPLOAD_DIR = Path(os.getenv("SFTS_UPLOAD_DIR", tempfile.gettempdir())) / "sfts_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("SFTS_SECRET_KEY", "dev-change-me")

    init_db()

    @app.before_request
    def _validate_session() -> None:
        ip_address = _get_client_ip(request)
        allowed, reason = is_request_allowed(ip_address, None)
        if not allowed and not _is_block_bypass_path(request.path):
            _log_security_event(None, "request_blocked", f"ip={ip_address}, reason={reason}")
            return (
                "Too many requests. Your IP is temporarily blocked. Contact the administrator.",
                429,
            )

        _track_request_frequency(request, ip_address)
        token = session.get("session_token")
        if not token:
            return
        ok, _ = validate_session(token)
        if not ok:
            session.clear()

    @app.route("/")
    def index():
        if "session_token" in session:
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            email = request.form.get("email", "").strip() or None
            ok, msg = register_user(username, password, email=email)
            if ok:
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
            flash(msg, "error")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            ok, token_or_msg = login_user(
                username,
                password,
                ip_address=_get_client_ip(request),
                user_agent=request.headers.get("User-Agent", "unknown")[:255],
            )
            if ok:
                user = get_user_by_username(username)
                if user and is_mfa_enabled(user["id"]):
                    session["pending_username"] = username
                    session["pending_token"] = token_or_msg
                    flash("Enter MFA code to complete login.", "success")
                    return redirect(url_for("mfa_verify"))

                session["username"] = username
                session["session_token"] = token_or_msg
                append_audit_log(user["id"] if user else None, "login_success", username, {"mfa": False})
                if user:
                    with get_connection() as conn:
                        send_security_email(conn, user["id"], "new_login", f"login from ip={_get_client_ip(request)}")
                flash("Logged in.", "success")
                return redirect(url_for("dashboard"))
            _log_security_event(None, "login_failed", f"username={username}")
            create_security_alert("login_failed", "medium", f"username={username}")
            flash(token_or_msg, "error")
        return render_template("login.html")

    @app.route("/mfa/verify", methods=["GET", "POST"])
    def mfa_verify():
        pending_username = session.get("pending_username")
        pending_token = session.get("pending_token")
        if not pending_username or not pending_token:
            return redirect(url_for("login"))

        if request.method == "POST":
            code = request.form.get("code", "")
            user = get_user_by_username(pending_username)
            if not user:
                session.pop("pending_username", None)
                session.pop("pending_token", None)
                flash("User not found.", "error")
                return redirect(url_for("login"))

            if verify_mfa_code(user["id"], code):
                session["username"] = pending_username
                session["session_token"] = pending_token
                session.pop("pending_username", None)
                session.pop("pending_token", None)
                append_audit_log(user["id"], "login_success", pending_username, {"mfa": True})
                with get_connection() as conn:
                    send_security_email(conn, user["id"], "new_login_mfa", f"login with mfa from ip={_get_client_ip(request)}")
                flash("MFA verified.", "success")
                return redirect(url_for("dashboard"))

            _log_security_event(user["id"], "mfa_failed", pending_username)
            create_security_alert("mfa_failed", "high", f"username={pending_username}")
            flash("Invalid MFA code.", "error")

        return render_template("mfa_verify.html")

    @app.route("/mfa/setup", methods=["GET", "POST"])
    def mfa_setup():
        if "session_token" not in session:
            return redirect(url_for("login"))

        user = get_user_by_username(session.get("username", ""))
        if not user:
            return redirect(url_for("logout"))

        secret = session.get("mfa_setup_secret")
        uri = session.get("mfa_setup_uri")
        backup_codes = session.get("mfa_setup_backup_codes")
        qr_data_uri = session.get("mfa_setup_qr")

        if request.method == "POST":
            action = request.form.get("action", "init")
            if action == "init":
                secret, backup_codes = setup_mfa_for_user(user["id"])
                uri = totp_uri(user["username"], secret)
                qr_data_uri = qr_code_data_uri(uri)
                session["mfa_setup_secret"] = secret
                session["mfa_setup_uri"] = uri
                session["mfa_setup_qr"] = qr_data_uri
                session["mfa_setup_backup_codes"] = backup_codes
                flash("MFA secret generated. Add it to your authenticator and confirm with a code.", "success")
            elif action == "enable":
                code = request.form.get("code", "")
                if verify_mfa_code(user["id"], code):
                    enable_mfa(user["id"])
                    append_audit_log(user["id"], "mfa_enabled", user["username"], {})
                    with get_connection() as conn:
                        send_security_email(conn, user["id"], "mfa_enabled", "MFA was enabled on your account")
                    session.pop("mfa_setup_secret", None)
                    session.pop("mfa_setup_uri", None)
                    session.pop("mfa_setup_qr", None)
                    session.pop("mfa_setup_backup_codes", None)
                    flash("MFA enabled.", "success")
                    return redirect(url_for("dashboard"))
                flash("Invalid MFA code.", "error")

        return render_template(
            "mfa_setup.html",
            enabled=is_mfa_enabled(user["id"]),
            secret=secret,
            uri=uri,
            qr_data_uri=qr_data_uri,
            backup_codes=backup_codes,
        )

    @app.route("/logout")
    def logout():
        user = get_user_by_username(session.get("username", "")) if session.get("username") else None
        append_audit_log(user["id"] if user else None, "logout", session.get("username", "anonymous"), {})
        session.clear()
        flash("Logged out.", "success")
        return redirect(url_for("index"))

    @app.route("/dashboard")
    def dashboard():
        if "session_token" not in session:
            return redirect(url_for("login"))
        user = get_user_by_username(session.get("username", ""))
        if not user:
            return redirect(url_for("logout"))
        with get_connection() as conn:
            notices = unread_notifications(conn, user["id"])
        return render_template(
            "dashboard.html",
            username=session.get("username"),
            notices=notices,
            session_warning_seconds=SESSION_WARNING_SECONDS,
        )

    @app.route("/events")
    def events():
        if "session_token" not in session:
            return Response("", status=401)
        user = get_user_by_username(session.get("username", ""))
        if not user:
            return Response("", status=401)

        def event_stream():
            while True:
                with get_connection() as conn:
                    unread = unread_notifications(conn, user["id"])
                    inbox_pending = conn.execute(
                        "SELECT COUNT(*) AS total FROM transfers WHERE receiver_id = ? AND status = 'queued'",
                        (user["id"],),
                    ).fetchone()["total"]
                payload = {
                    "unread": len(unread),
                    "pending_inbox": int(inbox_pending or 0),
                    "notifications": [dict(row) for row in unread],
                    "time": datetime.now(timezone.utc).isoformat(),
                }
                yield f"data: {json.dumps(payload)}\n\n"
                time.sleep(EVENT_STREAM_POLL_SECONDS)

        return Response(event_stream(), mimetype="text/event-stream")

    @app.route("/notifications/read", methods=["POST"])
    def notifications_read():
        if "session_token" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        user = get_user_by_username(session.get("username", ""))
        if not user:
            return jsonify({"error": "Invalid user"}), 400
        with get_connection() as conn:
            count = mark_notifications_read(conn, user["id"])
        return jsonify({"ok": True, "count": count})

    @app.route("/api/session-status")
    def api_session_status():
        token = session.get("session_token")
        if not token:
            return jsonify({"error": "Unauthorized"}), 401
        with get_connection() as conn:
            row = conn.execute(
                "SELECT expires_at FROM sessions WHERE session_token = ?",
                (token,),
            ).fetchone()
        if not row:
            return jsonify({"error": "Invalid session"}), 401
        expires = datetime.fromisoformat(row["expires_at"])
        remaining = int((expires - datetime.now(timezone.utc)).total_seconds())
        return jsonify({"remaining_seconds": max(0, remaining)})

    @app.route("/send", methods=["GET", "POST"])
    def send():
        if "session_token" not in session:
            return redirect(url_for("login"))

        wants_json = request.headers.get("X-Requested-With", "").lower() in {"fetch", "xmlhttprequest"}

        def _send_error(message: str):
            if wants_json:
                return jsonify({"ok": False, "message": message}), 400
            flash(message, "error")
            return redirect(url_for("send"))

        if request.method == "POST":
            transfer_secret = request.form.get("transfer_secret", "")
            recipient = request.form.get("recipient", "").strip()
            ttl_hours = request.form.get("ttl_hours", str(DEFAULT_TRANSFER_TTL_HOURS))
            note = request.form.get("note", "")
            share_enabled = request.form.get("share_enabled") == "on"
            share_password = request.form.get("share_password", "").strip() or None
            share_max_uses = int(request.form.get("share_max_uses", "1") or "1")
            compress_enabled = request.form.get("compress", "1") == "1"

            uploaded = request.files.get("file")
            batch_files = request.files.getlist("files")

            valid_batch = [f for f in batch_files if f and f.filename]
            use_batch = len(valid_batch) > 0

            if not use_batch and (not uploaded or not uploaded.filename):
                return _send_error("Select a file or folder files.")
            recipient_row = get_user_by_username(recipient)
            if not recipient_row:
                _log_security_event(None, "invalid_recipient", recipient)
                return _send_error("Recipient user ID not found.")
            if recipient_row.get("locked_until"):
                _log_security_event(recipient_row.get("id"), "recipient_locked", recipient)
                return _send_error("Recipient user is locked.")

            sender = get_user_by_username(session.get("username", ""))
            if not sender:
                return redirect(url_for("logout"))

            ttl = parse_ttl_hours(ttl_hours)
            expires_at = expires_at_from_ttl(ttl)

            file_path: Path
            display_name: str
            folder_upload = 0
            if use_batch:
                if len(valid_batch) > MAX_BATCH_FILES:
                    return _send_error(f"Too many files. Max {MAX_BATCH_FILES}.")
                file_path = zip_files_for_upload(UPLOAD_DIR, valid_batch)
                display_name = file_path.name
                folder_upload = 1
            else:
                file_path = UPLOAD_DIR / uploaded.filename
                uploaded.save(file_path)
                display_name = file_path.name

            source_for_encrypt, compressed, original_size = maybe_compress_file(file_path, compress_enabled)

            with get_connection() as conn:
                allowed, reason, _quota = check_quota_allowance(conn, sender["id"], original_size)
                if not allowed:
                    return _send_error(reason)

            try:
                result = prepare_transfer(
                    session.get("username", ""),
                    transfer_secret,
                    str(source_for_encrypt),
                    session.get("session_token", ""),
                )
            except Exception as exc:
                _log_security_event(None, "transfer_failed", str(exc))
                return _send_error(str(exc))

            metadata = result["metadata"]
            with get_connection() as conn:
                note_ciphertext, note_iv = encrypt_note(note, transfer_secret, result["salt"])
                cursor = conn.execute(
                    "INSERT INTO transfers (sender_id, receiver_id, filename, file_size, encrypted_size, original_hash, iv, metadata_json, encrypted_path, sender_salt, status, transfer_expires_at, max_downloads, note_ciphertext, note_iv, note_is_encrypted, compressed, original_path, folder_upload) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, 1, ?, ?, ?, ?, ?, ?)",
                    (
                        sender["id"],
                        recipient_row["id"],
                        display_name,
                        original_size,
                        Path(result["encrypted_path"]).stat().st_size,
                        metadata.original_hash,
                        metadata.iv,
                        json.dumps(asdict(metadata)),
                        result["encrypted_path"],
                        result["salt"],
                        expires_at.isoformat(),
                        note_ciphertext if note_ciphertext else None,
                        note_iv if note_iv else None,
                        1 if note_ciphertext else 0,
                        1 if compressed else 0,
                        str(file_path),
                        folder_upload,
                    ),
                )
                transfer_id = cursor.lastrowid
                if share_enabled:
                    link = create_share_link(
                        conn,
                        transfer_id,
                        expires_at,
                        max(1, min(share_max_uses, MAX_SHARE_LINK_DOWNLOADS)),
                        share_password,
                    )
                    if wants_json:
                        pass
                    else:
                        flash(f"Share link created: /share/{link['token']}", "success")

                add_notification(
                    conn,
                    recipient_row["id"],
                    "incoming_transfer",
                    "New transfer received",
                    f"{display_name} from {sender['username']}",
                )
                receiver_email_row = conn.execute("SELECT email FROM users WHERE id = ?", (recipient_row["id"],)).fetchone()
                template = conn.execute(
                    "SELECT subject, body_html, enabled FROM email_templates WHERE name = 'file_arrived'"
                ).fetchone()
                if template and int(template["enabled"]) == 1 and receiver_email_row and receiver_email_row["email"]:
                    subject, body = render_email_template(
                        template["subject"],
                        template["body_html"],
                        {"filename": display_name, "sender": sender["username"]},
                    )
                    send_email_if_configured(receiver_email_row["email"], subject, body)

                append_audit_log(
                    sender["id"],
                    "transfer_queued",
                    metadata.filename,
                    {"receiver_id": recipient_row["id"], "transfer_id": transfer_id, "ttl_hours": ttl, "compressed": compressed},
                    conn=conn,
                )
                queue_transfer_job(transfer_id, conn=conn)
            flash("File encrypted and queued for recipient.", "success")
            if wants_json:
                return jsonify({"ok": True, "redirect": url_for("history"), "message": "File encrypted and queued for recipient."})
            return redirect(url_for("history"))

        return render_template("send.html", default_ttl=DEFAULT_TRANSFER_TTL_HOURS, default_compress=ENABLE_COMPRESSION_DEFAULT)

    @app.route("/receive", methods=["GET", "POST"])
    def receive():
        if "session_token" not in session:
            return redirect(url_for("login"))

        user = get_user_by_username(session.get("username", ""))
        if not user:
            return redirect(url_for("logout"))

        with get_connection() as conn:
            row = conn.execute(
                "SELECT id, metadata_json, encrypted_path, sender_salt, compressed, filename, note_ciphertext, note_iv, transfer_expires_at, status FROM transfers "
                "WHERE receiver_id = ? AND status = 'queued' ORDER BY created_at ASC LIMIT 1",
                (user["id"],),
            ).fetchone()

        if not row:
            flash("No pending transfer.", "error")
            return render_template("receive.html", pending=False)

        if row["transfer_expires_at"]:
            expires_at = datetime.fromisoformat(row["transfer_expires_at"])
            if expires_at < datetime.now(timezone.utc):
                with get_connection() as conn:
                    conn.execute(
                        "UPDATE transfers SET status = 'deleted', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (row["id"],),
                    )
                flash("Pending transfer expired and was removed.", "error")
                return render_template("receive.html", pending=False)

        metadata = TransferMetadata(**json.loads(row["metadata_json"]))
        encrypted_path = row["encrypted_path"]
        sender_salt = row["sender_salt"]
        if not sender_salt:
            flash("Transfer missing sender salt.", "error")
            return render_template("receive.html", pending=False)
        receiver = TransferReceiver()

        if request.method == "POST":
            transfer_secret = request.form.get("transfer_secret", "")
            output_name = request.form.get("output_name", metadata.filename)
            transfer_id = int(request.form.get("transfer_id", row["id"]))
            output_path = UPLOAD_DIR / output_name

            ok = receiver.receive(
                metadata=metadata,
                encrypted_path=encrypted_path,
                output_path=str(output_path),
                transfer_secret=transfer_secret,
                salt_hex=sender_salt,
            )

            if ok:
                if int(row["compressed"] or 0) == 1:
                    maybe_decompress_file(output_path, True, output_path)
                note_text = ""
                try:
                    note_text = decrypt_note(row["note_ciphertext"], row["note_iv"], transfer_secret, sender_salt)
                except Exception:
                    note_text = ""
                with get_connection() as conn:
                    conn.execute(
                        "UPDATE transfers SET status = 'received', downloaded_at = CURRENT_TIMESTAMP, download_count = download_count + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (transfer_id,),
                    )
                    add_notification(conn, user["id"], "transfer_downloaded", "Transfer decrypted", f"{metadata.filename} ready")
                append_audit_log(user["id"], "transfer_received", metadata.filename, {"transfer_id": transfer_id})
                flash(f"File decrypted to {output_path}", "success")
                if note_text:
                    flash(f"Secure note: {note_text}", "success")
            else:
                with get_connection() as conn:
                    conn.execute(
                        "UPDATE transfers SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (transfer_id,),
                    )
                _log_security_event(None, "decrypt_failed", metadata.filename)
                create_security_alert("decrypt_failed", "high", metadata.filename)
                flash("Integrity check failed.", "error")
            return redirect(url_for("receive"))

        return render_template(
            "receive.html",
            pending=True,
            filename=metadata.filename,
            transfer_id=row["id"],
            expires_at=row["transfer_expires_at"],
        )

    @app.route("/inbox")
    def inbox():
        if "session_token" not in session:
            return redirect(url_for("login"))
        user = get_user_by_username(session.get("username", ""))
        if not user:
            return redirect(url_for("logout"))
        search = request.args.get("q", "").strip()
        status_filter = request.args.get("status", "all").strip().lower()
        sort_by = request.args.get("sort", "date_desc").strip().lower()

        where = ["t.receiver_id = ?"]
        params: list = [user["id"]]

        if search:
            where.append("(t.filename LIKE ? OR t.created_at LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        if status_filter in {"pending", "received", "failed", "expired", "deleted", "queued"}:
            where.append("t.status = ?")
            params.append(status_filter)

        order_map = {
            "date_desc": "t.created_at DESC",
            "date_asc": "t.created_at ASC",
            "size_desc": "t.file_size DESC",
            "size_asc": "t.file_size ASC",
            "sender": "u.username ASC",
        }
        order_by = order_map.get(sort_by, "t.created_at DESC")

        with get_connection() as conn:
            rows = conn.execute(
                f"SELECT t.id, t.filename, t.file_size, t.status, t.created_at, t.transfer_expires_at, u.username AS sender_name "
                f"FROM transfers t JOIN users u ON u.id = t.sender_id WHERE {' AND '.join(where)} ORDER BY {order_by}",
                params,
            ).fetchall()
        return render_template("inbox.html", transfers=rows, q=search, status_filter=status_filter, sort_by=sort_by)

    @app.route("/history")
    def history():
        if "session_token" not in session:
            return redirect(url_for("login"))
        user = get_user_by_username(session.get("username", ""))
        if not user:
            return redirect(url_for("logout"))
        search = request.args.get("q", "").strip()
        recipient = request.args.get("recipient", "").strip()
        sort_by = request.args.get("sort", "date_desc").strip().lower()

        where = ["t.sender_id = ?"]
        params: list = [user["id"]]
        if search:
            where.append("(t.filename LIKE ? OR t.created_at LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        if recipient:
            where.append("u.username LIKE ?")
            params.append(f"%{recipient}%")

        order_map = {
            "date_desc": "t.created_at DESC",
            "date_asc": "t.created_at ASC",
            "size_desc": "t.file_size DESC",
            "size_asc": "t.file_size ASC",
            "sender": "u.username ASC",
        }
        order_by = order_map.get(sort_by, "t.created_at DESC")

        with get_connection() as conn:
            rows = conn.execute(
                f"SELECT t.id, t.filename, t.file_size, t.status, t.created_at, u.username AS recipient_name, t.transfer_expires_at "
                f"FROM transfers t JOIN users u ON u.id = t.receiver_id WHERE {' AND '.join(where)} ORDER BY {order_by}",
                params,
            ).fetchall()
        return render_template("history.html", transfers=rows, q=search, recipient=recipient, sort_by=sort_by)

    @app.route("/share/<token>", methods=["GET", "POST"])
    def share_download(token: str):
        password = request.form.get("password", "") if request.method == "POST" else None
        with get_connection() as conn:
            ok, msg, link_row = validate_share_link(conn, token, password)
            if not ok or not link_row:
                flash(msg, "error")
                return render_template("share.html", token=token, valid=False)

            transfer = conn.execute(
                "SELECT id, metadata_json, encrypted_path, sender_salt, filename, compressed, note_ciphertext, note_iv FROM transfers WHERE id = ?",
                (link_row["transfer_id"],),
            ).fetchone()
            if not transfer:
                flash("Transfer not found", "error")
                return render_template("share.html", token=token, valid=False)

            if request.method == "POST":
                transfer_secret = request.form.get("transfer_secret", "")
                output_name = request.form.get("output_name", transfer["filename"])
                metadata = TransferMetadata(**json.loads(transfer["metadata_json"]))
                output_path = UPLOAD_DIR / output_name
                receiver = TransferReceiver()
                ok = receiver.receive(
                    metadata=metadata,
                    encrypted_path=transfer["encrypted_path"],
                    output_path=str(output_path),
                    transfer_secret=transfer_secret,
                    salt_hex=transfer["sender_salt"],
                )
                if not ok:
                    flash("Invalid secret or integrity failure", "error")
                    return render_template("share.html", token=token, valid=True)

                if int(transfer["compressed"] or 0) == 1:
                    maybe_decompress_file(output_path, True, output_path)
                consume_share_link(conn, link_row["id"])
                flash(f"Downloaded to {output_path}", "success")
                return render_template("share.html", token=token, valid=True)

        return render_template("share.html", token=token, valid=True)

    @app.route("/api/transfers/init", methods=["POST"])
    def api_init_transfer():
        if "session_token" not in session:
            return jsonify({"error": "Unauthorized"}), 401

        sender = get_user_by_username(session.get("username", ""))
        if not sender:
            return jsonify({"error": "Invalid sender"}), 400

        recipient_username = request.form.get("recipient", "").strip()
        filename = request.form.get("filename", "").strip()
        total_chunks = int(request.form.get("total_chunks", "0"))
        receiver = get_user_by_username(recipient_username)

        if not receiver:
            return jsonify({"error": "Recipient not found"}), 404

        transfer_id = init_multipart_transfer(sender["id"], receiver["id"], filename, total_chunks)
        append_audit_log(sender["id"], "multipart_init", filename, {"transfer_id": transfer_id, "receiver_id": receiver["id"]})
        return jsonify({"transfer_id": transfer_id})

    @app.route("/api/transfers/<transfer_id>/chunk/<int:chunk_no>", methods=["POST"])
    def api_upload_chunk(transfer_id: str, chunk_no: int):
        if "session_token" not in session:
            return jsonify({"error": "Unauthorized"}), 401

        chunk = request.files.get("chunk")
        chunk_hash = request.form.get("chunk_hash", "")
        if not chunk:
            return jsonify({"error": "Chunk file is required"}), 400

        ok = upload_chunk(transfer_id, chunk_no, chunk.read(), chunk_hash)
        if not ok:
            create_security_alert("chunk_hash_mismatch", "high", f"transfer_id={transfer_id}, chunk_no={chunk_no}")
            return jsonify({"error": "Chunk hash mismatch"}), 400

        return jsonify({"ok": True})

    @app.route("/api/transfers/<transfer_id>/finalize", methods=["POST"])
    def api_finalize_transfer(transfer_id: str):
        if "session_token" not in session:
            return jsonify({"error": "Unauthorized"}), 401

        try:
            result = finalize_transfer(transfer_id)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

        append_audit_log(None, "multipart_finalize", transfer_id, result)
        return jsonify(result)

    @app.route("/admin")
    def admin():
        if "session_token" not in session:
            return redirect(url_for("login"))
        ok, user_id_or_msg = validate_session(session.get("session_token", ""))
        if not ok or not isinstance(user_id_or_msg, int) or not is_admin(user_id_or_msg):
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))

        with get_connection() as conn:
            cleanup_result = cleanup_expired_transfers(conn)
            totals = conn.execute(
                "SELECT COUNT(*) AS total, SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed FROM transfers"
            ).fetchone()
            failed_logins = conn.execute(
                "SELECT COUNT(*) AS total FROM users WHERE failed_attempts > 0"
            ).fetchone()
            events = conn.execute(
                "SELECT event_type, COUNT(*) AS total FROM security_events GROUP BY event_type ORDER BY total DESC"
            ).fetchall()
            recent_events = conn.execute(
                "SELECT event_type, details, created_at FROM security_events ORDER BY created_at DESC LIMIT ?",
                (SECURITY_EVENTS_LIMIT,),
            ).fetchall()
            frequency_stats, ddos_stats = _get_frequency_and_ddos_stats(conn)
            blocked_ips = conn.execute(
                "SELECT ip_address, blocked_until, reason, updated_at FROM blocked_ips "
                "WHERE blocked_until >= ? ORDER BY blocked_until DESC",
                (datetime.now(timezone.utc).isoformat(),),
            ).fetchall()
            alerts = conn.execute(
                "SELECT id, event_type, severity, details, status, created_at FROM security_alerts ORDER BY created_at DESC LIMIT ?",
                (SECURITY_EVENTS_LIMIT,),
            ).fetchall()
            audit_count = conn.execute("SELECT COUNT(*) AS total FROM audit_logs").fetchone()
            metrics = summarize_metrics(conn)
            backup_jobs = conn.execute(
                "SELECT id, status, output_path, error, created_at, completed_at FROM backup_jobs ORDER BY created_at DESC LIMIT 10"
            ).fetchall()
            templates = conn.execute(
                "SELECT name, subject, body_html, enabled, updated_at FROM email_templates ORDER BY name ASC"
            ).fetchall()

        mitm = MitmSimulator()
        mitm_results = [
            mitm.passive_eavesdropping(),
            mitm.active_modification(),
            mitm.certificate_spoofing(),
            mitm.session_hijacking(),
        ]
        vulnerabilities = _run_vulnerability_checks(app)

        return render_template(
            "admin.html",
            totals=totals,
            failed_logins=failed_logins,
            events=events,
            recent_events=recent_events,
            frequency_stats=frequency_stats,
            ddos_stats=ddos_stats,
            blocked_ips=blocked_ips,
            alerts=alerts,
            audit_count=audit_count,
            metrics=metrics,
            backup_jobs=backup_jobs,
            cleanup_result=cleanup_result,
            templates=templates,
            mitm_results=mitm_results,
            vulnerabilities=vulnerabilities,
        )

    @app.route("/admin/backup", methods=["POST"])
    def admin_backup():
        if "session_token" not in session:
            return redirect(url_for("login"))
        ok, user_id_or_msg = validate_session(session.get("session_token", ""))
        if not ok or not isinstance(user_id_or_msg, int) or not is_admin(user_id_or_msg):
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))

        with get_connection() as conn:
            job = conn.execute("INSERT INTO backup_jobs (status) VALUES ('queued')").lastrowid
            try:
                output = create_backup_file(get_db_path())
                conn.execute(
                    "UPDATE backup_jobs SET status = 'completed', output_path = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (str(output), job),
                )
                append_audit_log(user_id_or_msg, "backup_created", "database", {"path": str(output)}, conn=conn)
                flash(f"Backup created: {output}", "success")
            except Exception as exc:
                conn.execute(
                    "UPDATE backup_jobs SET status = 'failed', error = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (str(exc), job),
                )
                flash(f"Backup failed: {exc}", "error")
        return redirect(url_for("admin"))

    @app.route("/admin/restore-backup", methods=["POST"])
    def admin_restore_backup():
        if "session_token" not in session:
            return redirect(url_for("login"))
        ok, user_id_or_msg = validate_session(session.get("session_token", ""))
        if not ok or not isinstance(user_id_or_msg, int) or not is_admin(user_id_or_msg):
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))

        path = request.form.get("backup_path", "").strip()
        if not path or not Path(path).exists():
            flash("Backup path is invalid", "error")
            return redirect(url_for("admin"))

        try:
            Path(get_db_path()).write_bytes(Path(path).read_bytes())
            flash("Backup restored", "success")
        except Exception as exc:
            flash(f"Restore failed: {exc}", "error")
        return redirect(url_for("admin"))

    @app.route("/admin/email-template", methods=["POST"])
    def admin_email_template():
        if "session_token" not in session:
            return redirect(url_for("login"))
        ok, user_id_or_msg = validate_session(session.get("session_token", ""))
        if not ok or not isinstance(user_id_or_msg, int) or not is_admin(user_id_or_msg):
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))

        name = request.form.get("name", "").strip()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body_html", "").strip()
        enabled = 1 if request.form.get("enabled") == "on" else 0

        with get_connection() as conn:
            conn.execute(
                "UPDATE email_templates SET subject = ?, body_html = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                (subject, body, enabled, name),
            )
        flash(f"Template updated: {name}", "success")
        return redirect(url_for("admin"))

    @app.route("/admin/set-quota", methods=["POST"])
    def admin_set_quota():
        if "session_token" not in session:
            return redirect(url_for("login"))
        ok, user_id_or_msg = validate_session(session.get("session_token", ""))
        if not ok or not isinstance(user_id_or_msg, int) or not is_admin(user_id_or_msg):
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))

        username = request.form.get("username", "").strip()
        user = get_user_by_username(username)
        if not user:
            flash("User not found", "error")
            return redirect(url_for("admin"))

        try:
            daily = int(request.form.get("daily_quota_bytes", "0") or "0")
            monthly = int(request.form.get("monthly_quota_bytes", "0") or "0")
            storage = int(request.form.get("storage_quota_bytes", "0") or "0")
        except ValueError:
            flash("Invalid quota values", "error")
            return redirect(url_for("admin"))

        with get_connection() as conn:
            conn.execute(
                "UPDATE users SET daily_quota_bytes = ?, monthly_quota_bytes = ?, storage_quota_bytes = ? WHERE id = ?",
                (max(0, daily), max(0, monthly), max(0, storage), user["id"]),
            )
        flash(f"Updated quotas for {username}", "success")
        return redirect(url_for("admin"))

    @app.route("/sessions")
    def sessions_page():
        if "session_token" not in session:
            return redirect(url_for("login"))
        user = get_user_by_username(session.get("username", ""))
        if not user:
            return redirect(url_for("logout"))
        with get_connection() as conn:
            items = session_details(conn, user["id"])
        return render_template("sessions.html", sessions=items, current_token=session.get("session_token", ""))

    @app.route("/sessions/revoke", methods=["POST"])
    def sessions_revoke():
        if "session_token" not in session:
            return redirect(url_for("login"))
        user = get_user_by_username(session.get("username", ""))
        if not user:
            return redirect(url_for("logout"))
        session_id = int(request.form.get("session_id", "0") or "0")
        with get_connection() as conn:
            deleted = revoke_session(conn, user["id"], session_id)
        flash("Session revoked." if deleted else "Session not found.", "success" if deleted else "error")
        return redirect(url_for("sessions_page"))

    @app.route("/sessions/revoke-others", methods=["POST"])
    def sessions_revoke_others():
        if "session_token" not in session:
            return redirect(url_for("login"))
        user = get_user_by_username(session.get("username", ""))
        if not user:
            return redirect(url_for("logout"))
        with get_connection() as conn:
            deleted = revoke_other_sessions(conn, user["id"], session.get("session_token", ""))
        flash(f"Revoked {deleted} other sessions.", "success")
        return redirect(url_for("sessions_page"))

    @app.route("/api/openapi.json")
    def api_openapi():
        base_url = request.url_root.rstrip("/")
        return jsonify(openapi_spec(base_url))

    @app.route("/api/docs")
    def api_docs():
        examples = {
            "init": "curl -X POST -F recipient=bob -F filename=big.dat -F total_chunks=12 http://127.0.0.1:5000/api/transfers/init",
            "chunk": "curl -X POST -F chunk=@part1.bin -F chunk_hash=<sha256> http://127.0.0.1:5000/api/transfers/<id>/chunk/1",
            "finalize": "curl -X POST http://127.0.0.1:5000/api/transfers/<id>/finalize",
        }
        return render_template("api_docs.html", examples=examples)

    @app.route("/admin/unblock-ip", methods=["POST"])
    def admin_unblock_ip():
        if "session_token" not in session:
            return redirect(url_for("login"))

        ok, user_id_or_msg = validate_session(session.get("session_token", ""))
        if not ok or not isinstance(user_id_or_msg, int) or not is_admin(user_id_or_msg):
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))

        ip_address = request.form.get("ip_address", "").strip()
        if not ip_address:
            flash("IP address is required.", "error")
            return redirect(url_for("admin"))

        with get_connection() as conn:
            conn.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
            conn.execute(
                "INSERT INTO security_events (user_id, event_type, details) VALUES (?, ?, ?)",
                (user_id_or_msg, "ip_unblocked", ip_address),
            )

        flash(f"Unblocked IP: {ip_address}", "success")
        return redirect(url_for("admin"))

    @app.route("/admin/run-worker", methods=["POST"])
    def admin_run_worker():
        if "session_token" not in session:
            return redirect(url_for("login"))

        ok, user_id_or_msg = validate_session(session.get("session_token", ""))
        if not ok or not isinstance(user_id_or_msg, int) or not is_admin(user_id_or_msg):
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))

        run_transfer_worker()
        append_audit_log(user_id_or_msg, "worker_run", "transfer_jobs", {})
        flash("Transfer worker executed.", "success")
        return redirect(url_for("admin"))

    @app.route("/admin/generate-keys", methods=["POST"])
    def admin_generate_keys():
        if "session_token" not in session:
            return redirect(url_for("login"))

        ok, user_id_or_msg = validate_session(session.get("session_token", ""))
        if not ok or not isinstance(user_id_or_msg, int) or not is_admin(user_id_or_msg):
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))

        username = request.form.get("username", "").strip()
        user = get_user_by_username(username)
        if not user:
            flash("User not found.", "error")
            return redirect(url_for("admin"))

        key_info = generate_user_keypair(user["id"])
        append_audit_log(user_id_or_msg, "generate_user_keypair", username, {})
        flash(f"Generated key pair for {username}. Public key prefix: {key_info['public_key'][:16]}", "success")
        return redirect(url_for("admin"))

    @app.route("/admin/export-audit")
    def admin_export_audit():
        if "session_token" not in session:
            return redirect(url_for("login"))

        ok, user_id_or_msg = validate_session(session.get("session_token", ""))
        if not ok or not isinstance(user_id_or_msg, int) or not is_admin(user_id_or_msg):
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))

        hours = int(request.args.get("hours", "24"))
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=max(1, hours))
        csv_data = export_audit_report(start, end, "csv")
        append_audit_log(user_id_or_msg, "export_audit", "audit_logs", {"hours": hours})

        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_report.csv"},
        )

    @app.route("/health")
    def health():
        return jsonify(health_check())

    return app


def _log_security_event(user_id: int | None, event_type: str, details: str | None) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO security_events (user_id, event_type, details) VALUES (?, ?, ?)",
            (user_id, event_type, details),
        )


def _track_request_frequency(req, ip_address: str) -> None:
    now = datetime.now(timezone.utc)
    window_start = now.replace(second=0, microsecond=0).isoformat()

    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, request_count FROM rate_limits WHERE ip_address = ? AND window_start = ?",
            (ip_address, window_start),
        ).fetchone()

        if row:
            request_count = int(row["request_count"]) + 1
            conn.execute(
                "UPDATE rate_limits SET request_count = ? WHERE id = ?",
                (request_count, row["id"]),
            )
        else:
            request_count = 1
            conn.execute(
                "INSERT INTO rate_limits (ip_address, window_start, request_count) VALUES (?, ?, ?)",
                (ip_address, window_start, request_count),
            )

        if request_count == DDOS_SUSPECT_REQUESTS_PER_WINDOW:
            conn.execute(
                "INSERT INTO security_events (user_id, event_type, details) VALUES (?, ?, ?)",
                (
                    None,
                    "ddos_suspected",
                    f"ip={ip_address}, rpm={request_count}, window={window_start}",
                ),
            )

        if request_count == DDOS_CRITICAL_REQUESTS_PER_WINDOW:
            conn.execute(
                "INSERT INTO security_events (user_id, event_type, details) VALUES (?, ?, ?)",
                (
                    None,
                    "ddos_critical",
                    f"ip={ip_address}, rpm={request_count}, window={window_start}",
                ),
            )
            blocked_until = apply_progressive_block(ip_address, conn=conn)
            create_security_alert(
                "ddos_critical",
                "high",
                f"ip={ip_address}, rpm={request_count}, blocked_until={blocked_until.isoformat()}",
                conn=conn,
            )

        cutoff = (now - timedelta(minutes=FREQUENCY_LOOKBACK_MINUTES * 4)).isoformat()
        conn.execute("DELETE FROM rate_limits WHERE window_start < ?", (cutoff,))


def _get_frequency_and_ddos_stats(conn):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=FREQUENCY_LOOKBACK_MINUTES)).isoformat()

    frequency_rows = conn.execute(
        "SELECT ip_address, SUM(request_count) AS total_requests, MAX(request_count) AS peak_rpm, COUNT(*) AS active_windows "
        "FROM rate_limits WHERE window_start >= ? GROUP BY ip_address "
        "ORDER BY total_requests DESC, peak_rpm DESC LIMIT 10",
        (cutoff,),
    ).fetchall()

    ddos_summary = conn.execute(
        "SELECT "
        "SUM(CASE WHEN request_count >= ? THEN 1 ELSE 0 END) AS suspect_windows, "
        "SUM(CASE WHEN request_count >= ? THEN 1 ELSE 0 END) AS critical_windows, "
        "COUNT(DISTINCT CASE WHEN request_count >= ? THEN ip_address END) AS suspect_ips, "
        "MAX(request_count) AS peak_observed_rpm "
        "FROM rate_limits WHERE window_start >= ?",
        (
            DDOS_SUSPECT_REQUESTS_PER_WINDOW,
            DDOS_CRITICAL_REQUESTS_PER_WINDOW,
            DDOS_SUSPECT_REQUESTS_PER_WINDOW,
            cutoff,
        ),
    ).fetchone()

    blocked_count = conn.execute(
        "SELECT COUNT(*) AS total FROM blocked_ips WHERE blocked_until >= ?",
        (datetime.now(timezone.utc).isoformat(),),
    ).fetchone()

    return frequency_rows, {
        "suspect_windows": ddos_summary["suspect_windows"],
        "critical_windows": ddos_summary["critical_windows"],
        "suspect_ips": ddos_summary["suspect_ips"],
        "peak_observed_rpm": ddos_summary["peak_observed_rpm"],
        "blocked_ips": blocked_count["total"],
    }


def _get_client_ip(req) -> str:
    source = req.headers.get("X-Forwarded-For", req.remote_addr or "unknown")
    return source.split(",")[0].strip() if source else "unknown"


def _is_block_bypass_path(path: str) -> bool:
    return path.startswith("/admin") or path.startswith("/static/")


def _run_vulnerability_checks(app: Flask) -> list[dict]:
    checks = []

    checks.append(
        {
            "name": "Flask secret key strength",
            "severity": "high" if app.secret_key == "dev-change-me" else "low",
            "status": "fail" if app.secret_key == "dev-change-me" else "pass",
            "details": "Default secret key is in use." if app.secret_key == "dev-change-me" else "Custom secret key configured.",
        }
    )

    default_admin = ADMIN_USERNAME == "admin" and ADMIN_PASSWORD == "Admin!123456"
    checks.append(
        {
            "name": "Default admin credentials",
            "severity": "high" if default_admin else "low",
            "status": "fail" if default_admin else "pass",
            "details": "Default admin credentials detected." if default_admin else "Admin credentials overridden via environment variables.",
        }
    )

    weak_password_hashing = PASSWORD_HASH_ITERATIONS < 200_000
    checks.append(
        {
            "name": "Password hash work factor",
            "severity": "medium" if weak_password_hashing else "low",
            "status": "fail" if weak_password_hashing else "pass",
            "details": f"Configured iterations: {PASSWORD_HASH_ITERATIONS}.",
        }
    )

    weak_pbkdf2 = PBKDF2_ITERATIONS < 200_000
    checks.append(
        {
            "name": "PBKDF2 key derivation strength",
            "severity": "medium" if weak_pbkdf2 else "low",
            "status": "fail" if weak_pbkdf2 else "pass",
            "details": f"Configured iterations: {PBKDF2_ITERATIONS}.",
        }
    )

    long_session_ttl = SESSION_TTL.total_seconds() > 1800
    checks.append(
        {
            "name": "Session lifetime policy",
            "severity": "medium" if long_session_ttl else "low",
            "status": "fail" if long_session_ttl else "pass",
            "details": f"Session TTL: {int(SESSION_TTL.total_seconds() / 60)} minutes.",
        }
    )

    checks.append(
        {
            "name": "Request frequency monitoring",
            "severity": "low",
            "status": "pass",
            "details": (
                "Per-IP request windows tracked "
                f"({REQUEST_WINDOW_SECONDS}s) with suspect threshold {DDOS_SUSPECT_REQUESTS_PER_WINDOW} rpm."
            ),
        }
    )

    checks.append(
        {
            "name": "Database path hardening",
            "severity": "medium" if DB_PATH == "sfts.db" else "low",
            "status": "fail" if DB_PATH == "sfts.db" else "pass",
            "details": "Default database path in use." if DB_PATH == "sfts.db" else "Custom database path configured.",
        }
    )

    return checks


if __name__ == "__main__":
    create_app().run(debug=True)
