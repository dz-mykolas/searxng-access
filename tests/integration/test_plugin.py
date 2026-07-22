# ruff: noqa: E402, I001

import os
import re
import tempfile
import unittest
from pathlib import Path

from searxng_access.policy import (
    ACCESS_ENDPOINTS,
    ADMIN_ENDPOINTS,
    AUTHENTICATED_ENDPOINTS,
    PUBLIC_ENDPOINTS,
    SEARCH_ENDPOINTS,
)
from searxng_access.store import TokenStore


_TEMPORARY_DIRECTORY = tempfile.TemporaryDirectory()
_DATABASE = Path(_TEMPORARY_DIRECTORY.name) / "access.db"
_STORE = TokenStore(_DATABASE)
_STORE.create_token(label="full", capabilities={"*"}, token="integration-full-token")
_STORE.create_token(label="search", capabilities={"search"}, token="integration-search-token")
_STORE.create_token(
    label="limited",
    capabilities={"search"},
    token="integration-limited-token",
    request_limit=1,
    window_seconds=3600,
)
_REVOKED = _STORE.create_token(
    label="revoked",
    capabilities={"search"},
    token="integration-revoked-token",
)
_STORE.revoke_token(_REVOKED.id)
os.environ["SEARXNG_ACCESS_DB"] = str(_DATABASE)
os.environ["SEARXNG_ACCESS_SECURE_COOKIE"] = "false"
os.environ.pop("SEARXNG_ACCESS_DEV_TOKEN", None)

import searx.plugins
from searx.webapp import app


def authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def api_key(token: str) -> dict[str, str]:
    return {"X-API-Key": token}


class PluginIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        app.config.update(TESTING=True)

    def setUp(self) -> None:
        self.client = app.test_client()

    @classmethod
    def tearDownClass(cls) -> None:
        _TEMPORARY_DIRECTORY.cleanup()

    def get(self, path: str, headers: dict[str, str] | None = None):
        request_headers = {"X-Forwarded-For": "127.0.0.1"}
        request_headers.update(headers or {})
        return self.client.get(path, headers=request_headers)

    def post(
        self,
        path: str,
        *,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ):
        request_headers = {"X-Forwarded-For": "127.0.0.1"}
        request_headers.update(headers or {})
        return self.client.post(path, data=data, headers=request_headers)

    def test_plugin_loads(self) -> None:
        self.assertIn("searxng_access", {plugin.id for plugin in searx.plugins.STORAGE})

    def test_every_upstream_route_is_explicitly_classified(self) -> None:
        classified = (
            ACCESS_ENDPOINTS
            | ADMIN_ENDPOINTS
            | AUTHENTICATED_ENDPOINTS
            | PUBLIC_ENDPOINTS
            | SEARCH_ENDPOINTS
        )
        upstream_endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
        self.assertEqual(upstream_endpoints - classified, set())

    def test_health_check_is_public(self) -> None:
        response = self.get("/healthz")
        self.assertEqual(response.status_code, 200)

    def test_missing_invalid_and_revoked_tokens_are_unauthorized(self) -> None:
        for headers in (
            {},
            authorization("invalid"),
            authorization("integration-revoked-token"),
            api_key("invalid"),
            api_key("integration-revoked-token"),
            {**api_key("invalid"), "Accept": "text/html"},
        ):
            with self.subTest(headers=headers):
                response = self.get("/", headers=headers)
                self.assertEqual(response.status_code, 401)
                self.assertIn("Bearer", response.headers["WWW-Authenticate"])

        search_response = self.get("/search?q=test")
        self.assertEqual(search_response.status_code, 401)

    def test_x_api_key_authenticates_and_uses_capabilities(self) -> None:
        headers = api_key("integration-search-token")
        self.assertEqual(self.get("/", headers=headers).status_code, 200)

        response = self.get("/config", headers=headers)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json["error"], "insufficient_scope")

    def test_multiple_authentication_headers_are_rejected(self) -> None:
        response = self.get(
            "/",
            headers={
                **authorization("integration-full-token"),
                **api_key("integration-full-token"),
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "multiple_credentials")

    def test_browser_login_session_and_logout(self) -> None:
        redirect_to_login = self.get("/", headers={"Accept": "text/html"})
        self.assertEqual(redirect_to_login.status_code, 303)
        self.assertIn("/access/login", redirect_to_login.location)

        login_page = self.get(redirect_to_login.location)
        self.assertEqual(login_page.status_code, 200)
        self.assertIn("https://github.com/dz-mykolas/searxng-access", login_page.text)
        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
        self.assertIsNotNone(csrf_match)
        assert csrf_match is not None

        login = self.post(
            "/access/login",
            data={
                "csrf_token": csrf_match.group(1),
                "next": "/",
                "token": "integration-full-token",
            },
        )
        self.assertEqual(login.status_code, 303)
        self.assertEqual(login.location, "/")
        self.assertIn("HttpOnly", login.headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", login.headers["Set-Cookie"])

        self.assertEqual(self.get("/").status_code, 200)
        self.assertEqual(self.get("/access").status_code, 200)

        invalid_bearer = self.get("/", headers=authorization("invalid"))
        self.assertEqual(invalid_bearer.status_code, 401)

        csrf_failure = self.post("/access/logout")
        self.assertEqual(csrf_failure.status_code, 403)
        self.assertEqual(csrf_failure.json["error"], "csrf_failed")

        logout = self.post(
            "/access/logout",
            headers={"Origin": "http://localhost"},
        )
        self.assertEqual(logout.status_code, 303)
        self.assertIn("logged_out=1", logout.location)
        self.assertIn("Clear-Site-Data", logout.headers)

        after_logout = self.get("/", headers={"Accept": "text/html"})
        self.assertEqual(after_logout.status_code, 303)

    def test_browser_csrf_check_supports_a_host_rewriting_proxy(self) -> None:
        login_page = self.get("/access/login")
        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
        self.assertIsNotNone(csrf_match)
        assert csrf_match is not None
        login = self.post(
            "/access/login",
            data={
                "csrf_token": csrf_match.group(1),
                "next": "/",
                "token": "integration-full-token",
            },
        )
        self.assertEqual(login.status_code, 303)

        logout = self.post(
            "/access/logout",
            headers={
                "Origin": "https://public-port-forward.example",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        self.assertEqual(logout.status_code, 303)

    def test_browser_csrf_check_rejects_cross_site_fetch_metadata(self) -> None:
        login_page = self.get("/access/login")
        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
        self.assertIsNotNone(csrf_match)
        assert csrf_match is not None
        login = self.post(
            "/access/login",
            data={
                "csrf_token": csrf_match.group(1),
                "next": "/",
                "token": "integration-full-token",
            },
        )
        self.assertEqual(login.status_code, 303)

        logout = self.post(
            "/access/logout",
            headers={
                "Origin": "http://localhost",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        self.assertEqual(logout.status_code, 403)
        self.assertEqual(logout.json["error"], "csrf_failed")

    def test_login_form_rejects_missing_csrf(self) -> None:
        response = self.post(
            "/access/login",
            data={"token": "integration-full-token", "next": "/"},
        )
        self.assertEqual(response.status_code, 400)

    def test_login_rejects_external_next_target(self) -> None:
        login_page = self.get("/access/login?next=https://example.com/steal")
        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
        self.assertIsNotNone(csrf_match)
        assert csrf_match is not None

        login = self.post(
            "/access/login",
            data={
                "csrf_token": csrf_match.group(1),
                "next": "https://example.com/steal",
                "token": "integration-full-token",
            },
        )
        self.assertEqual(login.status_code, 303)
        self.assertEqual(login.location, "/")

    def test_search_capability_can_open_search_page(self) -> None:
        response = self.get("/", headers=authorization("integration-search-token"))
        self.assertEqual(response.status_code, 200)

    def test_capability_failure_is_forbidden(self) -> None:
        response = self.get("/config", headers=authorization("integration-search-token"))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json["error"], "insufficient_scope")

        metrics_response = self.get(
            "/metrics",
            headers=authorization("integration-search-token"),
        )
        self.assertEqual(metrics_response.status_code, 403)

    def test_wildcard_token_can_access_known_route(self) -> None:
        response = self.get("/config", headers=authorization("integration-full-token"))
        self.assertEqual(response.status_code, 200)

    def test_unknown_route_is_denied_for_valid_token(self) -> None:
        response = self.get(
            "/not-a-searxng-route",
            headers=authorization("integration-full-token"),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json["error"], "route_denied")

    def test_quota_returns_too_many_requests(self) -> None:
        headers = api_key("integration-limited-token")
        self.assertEqual(self.get("/", headers=headers).status_code, 200)
        response = self.get("/", headers=headers)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json["error"], "rate_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
