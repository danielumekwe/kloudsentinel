from __future__ import annotations

import bcrypt

#: Not tied to any real account — used by callers (e.g. the login route)
#: to run a real bcrypt comparison even when no matching user exists, so
#: "unknown username" and "wrong password" take the same time. Without
#: this, a login attempt against a nonexistent username returns almost
#: instantly while a real one takes bcrypt's ~100ms+, letting an attacker
#: enumerate valid usernames purely from response timing.
DUMMY_PASSWORD_HASH = "$2b$12$ev15/2dTsg7rjumEqNETB.Ziyprd5VPT5EeAIyk/PjNTtOEbu0zte"


def hash_password(raw_password: str) -> str:
    return bcrypt.hashpw(raw_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(raw_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(raw_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False
