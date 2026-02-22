from __future__ import annotations

import argparse

from .auth import login_user, register_user
from .db import init_db
from .mitm import MitmSimulator


def main() -> None:
    parser = argparse.ArgumentParser(prog="sfts")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init-db")

    register = sub.add_parser("register")
    register.add_argument("username")
    register.add_argument("password")

    login = sub.add_parser("login")
    login.add_argument("username")
    login.add_argument("password")

    sub.add_parser("simulate-mitm")

    args = parser.parse_args()

    if args.command == "init-db":
        init_db()
        print("Database initialized")
        return

    if args.command == "register":
        ok, msg = register_user(args.username, args.password)
        print(msg)
        return

    if args.command == "login":
        ok, token_or_msg = login_user(args.username, args.password)
        print(token_or_msg)
        return

    if args.command == "simulate-mitm":
        sim = MitmSimulator()
        results = [
            sim.passive_eavesdropping(),
            sim.active_modification(),
            sim.certificate_spoofing(),
            sim.session_hijacking(),
        ]
        for result in results:
            print(f"{result.scenario}: {result.details}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
