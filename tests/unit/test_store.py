import sqlite3

import pytest

from searxng_access.store import TokenStore


@pytest.fixture
def store(tmp_path) -> TokenStore:
    return TokenStore(tmp_path / "access.db")


def test_create_and_authenticate_without_storing_raw_token(store: TokenStore) -> None:
    created = store.create_token(
        label="test",
        capabilities={"search"},
        token="raw-secret-token",
        now=100,
    )

    result = store.authenticate(created.token, now=101)

    assert result.reason == "valid"
    assert result.token is not None
    assert result.token.id == created.id
    assert result.token.capabilities == frozenset({"search"})
    assert b"raw-secret-token" not in store.database.read_bytes()


def test_operations_close_database_connections(store: TokenStore, monkeypatch) -> None:
    original_connect = store._connect
    connections = []

    def tracked_connect():
        connection = original_connect()
        connections.append(connection)
        return connection

    monkeypatch.setattr(store, "_connect", tracked_connect)

    store.list_tokens()

    assert len(connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        connections[0].execute("SELECT 1")


def test_invalid_expired_and_revoked_tokens(store: TokenStore) -> None:
    expired = store.create_token(
        label="expired",
        capabilities={"search"},
        token="expired-token",
        expires_at=100,
        now=50,
    )
    revoked = store.create_token(
        label="revoked",
        capabilities={"search"},
        token="revoked-token",
        now=50,
    )
    assert store.revoke_token(revoked.id, now=75)

    assert store.authenticate("missing", now=100).reason == "invalid"
    assert store.authenticate(expired.token, now=100).reason == "expired"
    assert store.authenticate(revoked.token, now=100).reason == "revoked"


def test_capabilities_and_wildcard(store: TokenStore) -> None:
    search = store.create_token(label="search", capabilities={"search"}, token="search")
    wildcard = store.create_token(label="all", capabilities={"*"}, token="all")

    search_record = store.authenticate(search.token).token
    wildcard_record = store.authenticate(wildcard.token).token

    assert search_record is not None
    assert search_record.permits("search")
    assert not search_record.permits("admin")
    assert wildcard_record is not None
    assert wildcard_record.permits("anything")


def test_fixed_window_quota(store: TokenStore) -> None:
    created = store.create_token(
        label="limited",
        capabilities={"search"},
        token="limited",
        request_limit=2,
        window_seconds=60,
    )
    token = store.authenticate(created.token).token
    assert token is not None

    assert store.consume_quota(token, now=100)
    assert store.consume_quota(token, now=101)
    assert not store.consume_quota(token, now=102)

    rejected = store.consume_quota_decision(token, now=102)
    assert not rejected.allowed
    assert rejected.retry_after == 18

    assert store.consume_quota(token, now=120)


def test_usage_is_aggregate_and_does_not_store_queries(store: TokenStore) -> None:
    created = store.create_token(label="usage", capabilities={"search"}, token="usage")

    store.record_usage(created.id, route="search", outcome="allowed", now=100)
    store.record_usage(created.id, route="search", outcome="allowed", now=101)

    assert store.usage() == [
        {
            "token_id": created.id,
            "route": "search",
            "outcome": "allowed",
            "request_count": 2,
            "last_used_at": 101,
        }
    ]
    with sqlite3.connect(store.database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(usage)")}
    assert "query" not in columns


def test_development_token_is_only_bootstrapped_into_empty_database(store: TokenStore) -> None:
    created = store.ensure_development_token("development-token")

    assert created is not None
    assert store.ensure_development_token("different-token") is None
    assert store.authenticate("development-token").reason == "valid"
    assert store.authenticate("different-token").reason == "invalid"


def test_browser_session_authentication_and_revocation(store: TokenStore) -> None:
    created = store.create_token(label="browser", capabilities={"search"}, token="browser-token")
    session = store.create_session(created.id, lifetime_seconds=100, now=100)

    result = store.authenticate_session(session.session, idle_seconds=30, now=110)

    assert result.reason == "valid"
    assert result.token is not None
    assert result.token.id == created.id
    assert b"ssn_" not in store.database.read_bytes()
    assert store.revoke_session(session.session, now=120)
    assert store.authenticate_session(session.session, idle_seconds=30, now=121).reason == (
        "revoked_session"
    )


def test_browser_session_idle_absolute_and_token_expiry(store: TokenStore) -> None:
    idle_token = store.create_token(label="idle", capabilities={"search"}, token="idle-token")
    idle_session = store.create_session(idle_token.id, lifetime_seconds=100, now=100)
    assert store.authenticate_session(idle_session.session, idle_seconds=30, now=130).reason == (
        "idle_session"
    )

    absolute_token = store.create_token(
        label="absolute",
        capabilities={"search"},
        token="absolute-token",
    )
    absolute_session = store.create_session(absolute_token.id, lifetime_seconds=50, now=100)
    assert store.authenticate_session(
        absolute_session.session, idle_seconds=100, now=150
    ).reason == ("expired_session")

    revoked_token = store.create_token(
        label="revoked parent",
        capabilities={"search"},
        token="revoked-parent-token",
    )
    revoked_session = store.create_session(revoked_token.id, lifetime_seconds=100, now=100)
    store.revoke_token(revoked_token.id, now=110)
    assert store.authenticate_session(
        revoked_session.session, idle_seconds=100, now=111
    ).reason == ("revoked")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"label": "", "capabilities": {"search"}},
        {"label": "test", "capabilities": set()},
        {"label": "test", "capabilities": {"search"}, "request_limit": 1},
        {"label": "test", "capabilities": {"search"}, "window_seconds": 60},
    ],
)
def test_invalid_token_configuration_is_rejected(store: TokenStore, kwargs: dict) -> None:
    with pytest.raises(ValueError):
        store.create_token(**kwargs)
