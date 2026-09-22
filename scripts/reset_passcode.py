"""Replace the local ExpiryManager passcode. Run with the backend's venv python.

Prompts for the new passcode (never echoed), hashes it with the app's own Argon2id
hasher, clears any lockout, and signs out every existing session.
"""

import getpass
import sqlite3
import sys
from pathlib import Path

from expirymanager.security.passwords import PasswordPolicyError, hash_password

DB = Path.home() / ".expirymanager" / "config.sqlite3"


def main() -> int:
    new = getpass.getpass("New passcode (min 12 chars): ")
    if new != getpass.getpass("Repeat it: "):
        print("Passcodes do not match.", file=sys.stderr)
        return 1
    try:
        phc = hash_password(new)
    except PasswordPolicyError as e:
        print(e, file=sys.stderr)
        return 1

    con = sqlite3.connect(DB)
    with con:
        n = con.execute(
            "UPDATE app_user SET password_phc = ?, failed_attempts = 0, locked_until = NULL",
            (phc,),
        ).rowcount
        con.execute("DELETE FROM session")
    user = con.execute("SELECT username FROM app_user").fetchone()
    con.close()
    print(f"Passcode replaced for {user[0] if user else '?'} ({n} row). Sign in again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
