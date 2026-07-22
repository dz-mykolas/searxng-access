"""Token administration commands."""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Sequence

from .store import TokenStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="searxng-access")
    parser.add_argument(
        "--database",
        default=os.environ.get("SEARXNG_ACCESS_DB"),
        help="SQLite database path (or set SEARXNG_ACCESS_DB)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    token = commands.add_parser("token", help="manage access tokens")
    token_commands = token.add_subparsers(dest="token_command", required=True)

    create = token_commands.add_parser("create", help="create a token")
    create.add_argument("--label", required=True)
    create.add_argument("--capability", action="append", dest="capabilities")
    create.add_argument("--expires-in", type=int, metavar="SECONDS")
    create.add_argument("--limit", type=int, metavar="REQUESTS")
    create.add_argument("--window", type=int, metavar="SECONDS")

    revoke = token_commands.add_parser("revoke", help="revoke a token by ID")
    revoke.add_argument("token_id")

    token_commands.add_parser("list", help="list token metadata")
    commands.add_parser("usage", help="show aggregate usage counters")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.database:
        parser.error("--database or SEARXNG_ACCESS_DB is required")

    store = TokenStore(args.database)
    if args.command == "usage":
        print(json.dumps(store.usage(), indent=2))
        return 0

    if args.token_command == "create":
        if (args.limit is None) != (args.window is None):
            parser.error("--limit and --window must be supplied together")
        if args.expires_in is not None and args.expires_in <= 0:
            parser.error("--expires-in must be positive")
        expires_at = int(time.time()) + args.expires_in if args.expires_in else None
        created = store.create_token(
            label=args.label,
            capabilities=set(args.capabilities or ["search"]),
            expires_at=expires_at,
            request_limit=args.limit,
            window_seconds=args.window,
        )
        print(f"ID: {created.id}")
        print(f"Token: {created.token}")
        print("The token is shown once; store it securely.")
        return 0

    if args.token_command == "revoke":
        if not store.revoke_token(args.token_id):
            parser.error(f"active token not found: {args.token_id}")
        print(f"Revoked {args.token_id}")
        return 0

    for token in store.list_tokens():
        state = "revoked" if token.revoked_at is not None else "active"
        capabilities = ",".join(sorted(token.capabilities))
        quota = (
            f"{token.request_limit}/{token.window_seconds}s"
            if token.request_limit is not None
            else "unlimited"
        )
        print(f"{token.id}\t{state}\t{capabilities}\t{quota}\t{token.label}")
    return 0
