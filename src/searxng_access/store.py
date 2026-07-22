"""SQLite token storage, quota decisions, and aggregate usage counters."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TokenRecord:
    id: str
    label: str
    capabilities: frozenset[str]
    created_at: int
    expires_at: int | None
    revoked_at: int | None
    request_limit: int | None
    window_seconds: int | None

    def permits(self, capability: str) -> bool:
        return "*" in self.capabilities or capability in self.capabilities


@dataclass(frozen=True)
class AuthenticationResult:
    token: TokenRecord | None
    reason: str


@dataclass(frozen=True)
class CreatedToken:
    id: str
    token: str


@dataclass(frozen=True)
class CreatedSession:
    session: str
    expires_at: int


class TokenStore:
    """Persist only token hashes and aggregate, query-free usage data."""

    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        self.database.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS tokens (
                    id TEXT PRIMARY KEY,
                    token_hash BLOB NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    capabilities TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    revoked_at INTEGER,
                    request_limit INTEGER CHECK (request_limit IS NULL OR request_limit > 0),
                    window_seconds INTEGER CHECK (window_seconds IS NULL OR window_seconds > 0),
                    CHECK ((request_limit IS NULL) = (window_seconds IS NULL))
                );

                CREATE TABLE IF NOT EXISTS quota_windows (
                    token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
                    window_start INTEGER NOT NULL,
                    request_count INTEGER NOT NULL,
                    PRIMARY KEY (token_id, window_start)
                );

                CREATE TABLE IF NOT EXISTS usage (
                    token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
                    route TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    request_count INTEGER NOT NULL,
                    last_used_at INTEGER NOT NULL,
                    PRIMARY KEY (token_id, route, outcome)
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_hash BLOB PRIMARY KEY,
                    token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
                    created_at INTEGER NOT NULL,
                    last_used_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER
                );
                """
            )

    @staticmethod
    def _hash_token(token: str) -> bytes:
        return hashlib.sha256(token.encode("utf-8")).digest()

    @staticmethod
    def _row_to_token(row: sqlite3.Row) -> TokenRecord:
        return TokenRecord(
            id=row["id"],
            label=row["label"],
            capabilities=frozenset(json.loads(row["capabilities"])),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            revoked_at=row["revoked_at"],
            request_limit=row["request_limit"],
            window_seconds=row["window_seconds"],
        )

    def create_token(
        self,
        *,
        label: str,
        capabilities: set[str] | frozenset[str],
        expires_at: int | None = None,
        request_limit: int | None = None,
        window_seconds: int | None = None,
        token: str | None = None,
        now: int | None = None,
    ) -> CreatedToken:
        if not label.strip():
            raise ValueError("label must not be empty")
        if not capabilities or any(not capability.strip() for capability in capabilities):
            raise ValueError("at least one non-empty capability is required")
        if (request_limit is None) != (window_seconds is None):
            raise ValueError("request_limit and window_seconds must be set together")
        if request_limit is not None and request_limit <= 0:
            raise ValueError("request_limit must be positive")
        if window_seconds is not None and window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        raw_token = token or f"sxng_{secrets.token_urlsafe(32)}"
        token_id = f"tok_{secrets.token_urlsafe(9)}"
        created_at = int(time.time()) if now is None else now
        encoded_capabilities = json.dumps(sorted(capabilities), separators=(",", ":"))

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO tokens (
                    id, token_hash, label, capabilities, created_at, expires_at,
                    request_limit, window_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_id,
                    self._hash_token(raw_token),
                    label.strip(),
                    encoded_capabilities,
                    created_at,
                    expires_at,
                    request_limit,
                    window_seconds,
                ),
            )
        return CreatedToken(id=token_id, token=raw_token)

    def ensure_development_token(self, token: str) -> CreatedToken | None:
        """Create the known local token only when the database has never had tokens."""

        with self._connect() as connection:
            count = connection.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
        if count:
            return None
        return self.create_token(label="local development", capabilities={"*"}, token=token)

    def authenticate(self, raw_token: str, *, now: int | None = None) -> AuthenticationResult:
        checked_at = int(time.time()) if now is None else now
        token_hash = self._hash_token(raw_token)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()

        if row is None:
            # Keep comparison work in the invalid-token path as well.
            hmac.compare_digest(token_hash, bytes(len(token_hash)))
            return AuthenticationResult(token=None, reason="invalid")
        if not hmac.compare_digest(row["token_hash"], token_hash):
            return AuthenticationResult(token=None, reason="invalid")

        return self._validate_token(self._row_to_token(row), checked_at)

    @staticmethod
    def _validate_token(token: TokenRecord, checked_at: int) -> AuthenticationResult:
        if token.revoked_at is not None:
            return AuthenticationResult(token=None, reason="revoked")
        if token.expires_at is not None and token.expires_at <= checked_at:
            return AuthenticationResult(token=None, reason="expired")
        return AuthenticationResult(token=token, reason="valid")

    def create_session(
        self,
        token_id: str,
        *,
        lifetime_seconds: int,
        now: int | None = None,
    ) -> CreatedSession:
        if lifetime_seconds <= 0:
            raise ValueError("lifetime_seconds must be positive")

        created_at = int(time.time()) if now is None else now
        expires_at = created_at + lifetime_seconds
        raw_session = f"ssn_{secrets.token_urlsafe(32)}"
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL",
                (created_at,),
            )
            connection.execute(
                """
                INSERT INTO sessions (
                    session_hash, token_id, created_at, last_used_at, expires_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    self._hash_token(raw_session),
                    token_id,
                    created_at,
                    created_at,
                    expires_at,
                ),
            )
        return CreatedSession(session=raw_session, expires_at=expires_at)

    def authenticate_session(
        self,
        raw_session: str,
        *,
        idle_seconds: int,
        now: int | None = None,
    ) -> AuthenticationResult:
        if idle_seconds <= 0:
            raise ValueError("idle_seconds must be positive")

        checked_at = int(time.time()) if now is None else now
        session_hash = self._hash_token(raw_session)
        with self._connect() as connection:
            session = connection.execute(
                "SELECT * FROM sessions WHERE session_hash = ?",
                (session_hash,),
            ).fetchone()
            if session is None or not hmac.compare_digest(session["session_hash"], session_hash):
                return AuthenticationResult(token=None, reason="invalid_session")
            if session["revoked_at"] is not None:
                return AuthenticationResult(token=None, reason="revoked_session")
            if session["expires_at"] <= checked_at:
                return AuthenticationResult(token=None, reason="expired_session")
            if session["last_used_at"] + idle_seconds <= checked_at:
                return AuthenticationResult(token=None, reason="idle_session")

            token_row = connection.execute(
                "SELECT * FROM tokens WHERE id = ?",
                (session["token_id"],),
            ).fetchone()
            if token_row is None:
                return AuthenticationResult(token=None, reason="invalid_session")
            result = self._validate_token(self._row_to_token(token_row), checked_at)
            if result.token is None:
                return result
            connection.execute(
                "UPDATE sessions SET last_used_at = ? WHERE session_hash = ?",
                (checked_at, session_hash),
            )
        return result

    def revoke_session(self, raw_session: str, *, now: int | None = None) -> bool:
        revoked_at = int(time.time()) if now is None else now
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE session_hash = ? AND revoked_at IS NULL
                """,
                (revoked_at, self._hash_token(raw_session)),
            )
        return cursor.rowcount == 1

    def revoke_token(self, token_id: str, *, now: int | None = None) -> bool:
        revoked_at = int(time.time()) if now is None else now
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (revoked_at, token_id),
            )
        return cursor.rowcount == 1

    def consume_quota(self, token: TokenRecord, *, now: int | None = None) -> bool:
        if token.request_limit is None or token.window_seconds is None:
            return True

        checked_at = int(time.time()) if now is None else now
        window_start = checked_at - (checked_at % token.window_seconds)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM quota_windows WHERE token_id = ? AND window_start < ?",
                (token.id, window_start),
            )
            row = connection.execute(
                """
                SELECT request_count FROM quota_windows
                WHERE token_id = ? AND window_start = ?
                """,
                (token.id, window_start),
            ).fetchone()
            if row is not None and row["request_count"] >= token.request_limit:
                return False
            connection.execute(
                """
                INSERT INTO quota_windows (token_id, window_start, request_count)
                VALUES (?, ?, 1)
                ON CONFLICT(token_id, window_start)
                DO UPDATE SET request_count = request_count + 1
                """,
                (token.id, window_start),
            )
        return True

    def record_usage(
        self,
        token_id: str,
        *,
        route: str,
        outcome: str,
        now: int | None = None,
    ) -> None:
        used_at = int(time.time()) if now is None else now
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO usage (token_id, route, outcome, request_count, last_used_at)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(token_id, route, outcome) DO UPDATE SET
                    request_count = request_count + 1,
                    last_used_at = excluded.last_used_at
                """,
                (token_id, route, outcome, used_at),
            )

    def list_tokens(self) -> list[TokenRecord]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM tokens ORDER BY created_at, id").fetchall()
        return [self._row_to_token(row) for row in rows]

    def usage(self) -> list[dict[str, str | int]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT token_id, route, outcome, request_count, last_used_at
                FROM usage ORDER BY token_id, route, outcome
                """
            ).fetchall()
        return [dict(row) for row in rows]
