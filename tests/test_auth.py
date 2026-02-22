import os
import tempfile


def test_register_and_login():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "test.db")
        os.environ["SFTS_DB_PATH"] = db_path

        from sfts.auth import register_user, login_user, validate_session
        from sfts.db import init_db

        init_db()

        ok, msg = register_user("alice", "Password!12345")
        assert ok is True

        ok, token = login_user("alice", "Password!12345")
        assert ok is True

        ok, user_id = validate_session(token)
        assert ok is True
        assert isinstance(user_id, int)
