"""Small, explicit route-to-capability policy."""

from enum import Enum
from typing import Protocol


class RequestLike(Protocol):
    endpoint: str | None
    url_rule: object | None


class RouteDecision(Enum):
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    DENY = "deny"


SEARCH_ENDPOINTS = frozenset(
    {
        "index",
        "search",
        "autocompleter",
        "image_proxy",
        "favicon_proxy",
    }
)
ADMIN_ENDPOINTS = frozenset({"stats_errors", "stats_open_metrics"})
PUBLIC_ENDPOINTS = frozenset({"health", "searxng_access_login"})
AUTHENTICATED_ENDPOINTS = frozenset(
    {
        "searxng_access_account",
        "searxng_access_logout",
    }
)
ACCESS_ENDPOINTS = frozenset(
    {
        "about",
        "clear_cookies",
        "client_token",
        "config",
        "engine_descriptions",
        "favicon",
        "info",
        "manifest",
        "manifest_logo",
        "opensearch",
        "preferences",
        "robots",
        "rss_xsl",
        "stats",
    }
)


def required_capability(request: RequestLike) -> str | RouteDecision:
    """Classify a matched SearXNG route, denying routes unknown to Flask."""

    if request.url_rule is None or request.endpoint is None:
        return RouteDecision.DENY
    if request.endpoint in PUBLIC_ENDPOINTS:
        return RouteDecision.PUBLIC
    if request.endpoint in AUTHENTICATED_ENDPOINTS:
        return RouteDecision.AUTHENTICATED
    if request.endpoint in SEARCH_ENDPOINTS:
        return "search"
    if request.endpoint in ACCESS_ENDPOINTS:
        return "access"
    if request.endpoint in ADMIN_ENDPOINTS:
        return "admin"
    return RouteDecision.DENY
