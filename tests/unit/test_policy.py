from types import SimpleNamespace

from searxng_access.policy import RouteDecision, required_capability


def request(endpoint: str | None, *, matched: bool = True) -> SimpleNamespace:
    return SimpleNamespace(endpoint=endpoint, url_rule=object() if matched else None)


def test_health_is_public() -> None:
    assert required_capability(request("health")) is RouteDecision.PUBLIC
    assert required_capability(request("searxng_access_login")) is RouteDecision.PUBLIC


def test_browser_session_routes_require_authentication_only() -> None:
    assert required_capability(request("searxng_access_account")) is RouteDecision.AUTHENTICATED
    assert required_capability(request("searxng_access_logout")) is RouteDecision.AUTHENTICATED


def test_search_routes_require_search_capability() -> None:
    assert required_capability(request("index")) == "search"
    assert required_capability(request("search")) == "search"


def test_metrics_require_admin_capability() -> None:
    assert required_capability(request("stats_open_metrics")) == "admin"


def test_other_known_routes_require_access_capability() -> None:
    assert required_capability(request("config")) == "access"


def test_unknown_and_unclassified_routes_are_denied() -> None:
    assert required_capability(request(None, matched=False)) is RouteDecision.DENY
    assert required_capability(request("new_upstream_route")) is RouteDecision.DENY
