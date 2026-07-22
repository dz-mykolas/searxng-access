"""SearXNG plugin that installs request-wide token enforcement."""

from __future__ import annotations

import hmac
import json
import os
import secrets
import sqlite3
from datetime import UTC, datetime
from html import escape
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from flask import Response, g, redirect, request, url_for
from searx.plugins import Plugin, PluginInfo

from .auth import parse_api_key, parse_bearer_token
from .policy import RouteDecision, required_capability
from .store import TokenRecord, TokenStore

if TYPE_CHECKING:
    from flask import Flask
    from searx.plugins import PluginCfg


class SXNGPlugin(Plugin):
    """Enforce access independently from user-selectable search plugin hooks."""

    id = "searxng_access"

    def __init__(self, plg_cfg: PluginCfg) -> None:
        super().__init__(plg_cfg)
        self.info = PluginInfo(
            id=self.id,
            name="SearXNG Access",
            description="API-token access control",
            preference_section=None,
        )
        self.store: TokenStore | None = None
        self.session_lifetime = 7 * 24 * 60 * 60
        self.session_idle = 8 * 60 * 60
        self.secure_cookie = True
        self.session_cookie = "__Host-searxng_access_session"
        self.login_csrf_cookie = "__Host-searxng_access_login_csrf"

    def init(self, app: Flask) -> bool:
        database = os.environ.get("SEARXNG_ACCESS_DB")
        if not database:
            raise RuntimeError("SEARXNG_ACCESS_DB must be set when searxng-access is enabled")

        self.store = TokenStore(database)
        self.session_lifetime = self._positive_env(
            "SEARXNG_ACCESS_SESSION_LIFETIME",
            self.session_lifetime,
        )
        self.session_idle = self._positive_env(
            "SEARXNG_ACCESS_SESSION_IDLE",
            self.session_idle,
        )
        self.secure_cookie = self._boolean_env("SEARXNG_ACCESS_SECURE_COOKIE", True)
        if not self.secure_cookie:
            self.session_cookie = "searxng_access_session"
            self.login_csrf_cookie = "searxng_access_login_csrf"

        development_token = os.environ.get("SEARXNG_ACCESS_DEV_TOKEN")
        if development_token:
            created = self.store.ensure_development_token(development_token)
            if created:
                self.log.warning("created the local development access token")

        app.add_url_rule(
            "/access/login",
            endpoint="searxng_access_login",
            view_func=self._login,
            methods=["GET", "POST"],
        )
        app.add_url_rule(
            "/access",
            endpoint="searxng_access_account",
            view_func=self._account,
            methods=["GET"],
        )
        app.add_url_rule(
            "/access/logout",
            endpoint="searxng_access_logout",
            view_func=self._logout,
            methods=["GET", "POST"],
        )

        # SearXNG's documented search hooks do not cover every HTTP route. Registering
        # here makes authorization independent of user plugin preferences.
        app.before_request(self._authorize_request)
        self.log.info("request access control initialized")
        return True

    def _authorize_request(self) -> Response | None:
        decision = required_capability(request)
        if decision is RouteDecision.PUBLIC:
            return None

        assert self.store is not None
        try:
            authorization_header = request.headers.get("Authorization")
            api_key_header = request.headers.get("X-API-Key")
            raw_session = request.cookies.get(self.session_cookie)
            if authorization_header is not None and api_key_header is not None:
                return self._error(
                    400,
                    "multiple_credentials",
                    "Use only one authentication header",
                )

            if authorization_header is not None:
                source = "bearer"
                raw_token = parse_bearer_token(authorization_header)
                if raw_token is None:
                    return self._unauthorized(explicit_credentials=True)
                authentication = self.store.authenticate(raw_token)
            elif api_key_header is not None:
                source = "api_key"
                raw_token = parse_api_key(api_key_header)
                if raw_token is None:
                    return self._unauthorized(explicit_credentials=True)
                authentication = self.store.authenticate(raw_token)
            elif raw_session:
                source = "session"
                authentication = self.store.authenticate_session(
                    raw_session,
                    idle_seconds=self.session_idle,
                )
            else:
                return self._unauthorized(explicit_credentials=False)

            if authentication.token is None:
                explicit_credentials = (
                    authorization_header is not None or api_key_header is not None
                )
                return self._unauthorized(
                    explicit_credentials=explicit_credentials,
                    clear_session=not explicit_credentials and bool(raw_session),
                )

            token = authentication.token
            route = request.endpoint or "<unknown>"
            if decision is RouteDecision.DENY:
                self.store.record_usage(token.id, route=route, outcome="denied")
                return self._error(403, "route_denied", "The requested route is not allowed")

            if (
                source == "session"
                and request.method not in {"GET", "HEAD", "OPTIONS"}
                and not self._is_same_origin()
            ):
                self.store.record_usage(token.id, route=route, outcome="csrf_denied")
                return self._error(403, "csrf_failed", "A same-origin request is required")

            if decision is not RouteDecision.AUTHENTICATED and not token.permits(decision):
                self.store.record_usage(token.id, route=route, outcome="forbidden")
                return self._error(
                    403,
                    "insufficient_scope",
                    "The token lacks the required capability",
                )

            if not self.store.consume_quota(token):
                self.store.record_usage(token.id, route=route, outcome="rate_limited")
                return self._error(
                    429,
                    "rate_limit_exceeded",
                    "The token request limit was reached",
                )

            g.searxng_access_token = token
            g.searxng_access_source = source
            self.store.record_usage(token.id, route=route, outcome="allowed")
            return None
        except sqlite3.Error:
            self.log.exception("access database failure")
            return self._error(503, "access_unavailable", "Access validation is unavailable")

    def _login(self) -> Response:
        assert self.store is not None
        next_target = self._safe_next(request.values.get("next"))
        if request.method == "GET":
            raw_session = request.cookies.get(self.session_cookie)
            if raw_session:
                authentication = self.store.authenticate_session(
                    raw_session,
                    idle_seconds=self.session_idle,
                )
                if authentication.token is not None:
                    return redirect(url_for("searxng_access_account"), code=303)
            message = "You have been signed out." if request.args.get("logged_out") else None
            return self._login_page(next_target, message=message)

        submitted_csrf = request.form.get("csrf_token", "")
        cookie_csrf = request.cookies.get(self.login_csrf_cookie, "")
        if (
            not submitted_csrf
            or not cookie_csrf
            or not hmac.compare_digest(
                submitted_csrf,
                cookie_csrf,
            )
        ):
            return self._login_page(
                next_target,
                error="The login form expired. Please try again.",
                status=400,
            )

        raw_token = request.form.get("token", "")
        authentication = self.store.authenticate(raw_token)
        if authentication.token is None:
            return self._login_page(
                next_target,
                error="That access token is invalid, expired, or revoked.",
                status=401,
            )

        session = self.store.create_session(
            authentication.token.id,
            lifetime_seconds=self.session_lifetime,
        )
        self.store.record_usage(
            authentication.token.id,
            route="searxng_access_login",
            outcome="session_created",
        )
        response = redirect(next_target, code=303)
        response.set_cookie(
            self.session_cookie,
            session.session,
            secure=self.secure_cookie,
            httponly=True,
            samesite="Lax",
            path="/",
        )
        response.delete_cookie(
            self.login_csrf_cookie,
            secure=self.secure_cookie,
            httponly=True,
            samesite="Lax",
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    def _account(self) -> Response:
        token: TokenRecord = g.searxng_access_token
        capabilities = ", ".join(escape(item) for item in sorted(token.capabilities))
        expiry = (
            datetime.fromtimestamp(token.expires_at, UTC).strftime("%Y-%m-%d %H:%M UTC")
            if token.expires_at is not None
            else "No token expiry"
        )
        body = f"""
        <p>You are signed in as <strong>{escape(token.label)}</strong>.</p>
        <dl>
          <dt>Token ID</dt><dd><code>{escape(token.id)}</code></dd>
          <dt>Capabilities</dt><dd><code>{capabilities}</code></dd>
          <dt>Expiry</dt><dd>{escape(expiry)}</dd>
        </dl>
        <p><a class="button secondary" href="/">Open SearXNG</a></p>
        <form method="post" action="{escape(url_for("searxng_access_logout"))}">
          <button type="submit">Sign out</button>
        </form>
        """
        return self._page("Access session", body)

    def _logout(self) -> Response:
        if request.method == "GET":
            body = f"""
            <p>End this browser session?</p>
            <form method="post" action="{escape(url_for("searxng_access_logout"))}">
              <button type="submit">Sign out</button>
              <a class="button secondary" href="/">Cancel</a>
            </form>
            """
            return self._page("Sign out", body)

        raw_session = request.cookies.get(self.session_cookie)
        if raw_session:
            assert self.store is not None
            self.store.revoke_session(raw_session)
        response = redirect(url_for("searxng_access_login", logged_out="1"), code=303)
        response.delete_cookie(
            self.session_cookie,
            secure=self.secure_cookie,
            httponly=True,
            samesite="Lax",
            path="/",
        )
        response.headers["Clear-Site-Data"] = '"cache"'
        response.headers["Cache-Control"] = "no-store"
        return response

    def _login_page(
        self,
        next_target: str,
        *,
        error: str | None = None,
        message: str | None = None,
        status: int = 200,
    ) -> Response:
        csrf_token = secrets.token_urlsafe(32)
        notice = f'<p class="error">{escape(error)}</p>' if error else ""
        notice += f'<p class="message">{escape(message)}</p>' if message else ""
        body = f"""
        {notice}
        <p>Enter an access token once. It will be exchanged for a secure browser session.</p>
        <form method="post" action="{escape(url_for("searxng_access_login"))}">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <input type="hidden" name="next" value="{escape(next_target)}">
          <label for="token">Access token</label>
          <input id="token" name="token" type="password" required autofocus
                 autocomplete="off" spellcheck="false">
          <button type="submit">Sign in</button>
        </form>
        """
        response = self._page("Sign in to SearXNG", body, status=status)
        response.set_cookie(
            self.login_csrf_cookie,
            csrf_token,
            max_age=600,
            secure=self.secure_cookie,
            httponly=True,
            samesite="Lax",
            path="/",
        )
        return response

    def _unauthorized(
        self,
        *,
        explicit_credentials: bool,
        clear_session: bool = False,
    ) -> Response:
        if not explicit_credentials and self._wants_html():
            target = request.full_path.removesuffix("?")
            response = redirect(
                url_for("searxng_access_login", next=self._safe_next(target)),
                code=303,
            )
        else:
            response = self._error(401, "invalid_token", "A valid access token is required")
        if clear_session:
            response.delete_cookie(
                self.session_cookie,
                secure=self.secure_cookie,
                httponly=True,
                samesite="Lax",
                path="/",
            )
        return response

    @staticmethod
    def _wants_html() -> bool:
        output_format = request.args.get("format", "html").lower()
        return output_format == "html" and "text/html" in request.headers.get("Accept", "").lower()

    @staticmethod
    def _safe_next(value: str | None) -> str:
        if not value:
            return "/"
        parsed = urlsplit(value)
        if (
            parsed.scheme
            or parsed.netloc
            or not parsed.path.startswith("/")
            or parsed.path.startswith("//")
        ):
            return "/"
        return urlunsplit(("", "", parsed.path, parsed.query, ""))

    @staticmethod
    def _is_same_origin() -> bool:
        # Fetch Metadata describes the relationship as seen by the browser, so it
        # remains correct when a trusted development or deployment proxy rewrites
        # the Host header before Flask receives the request.  Browsers prevent
        # scripts from forging Sec-Fetch-Site.
        fetch_site = request.headers.get("Sec-Fetch-Site")
        if fetch_site:
            return fetch_site.lower() == "same-origin"

        expected = request.host_url.rstrip("/")
        origin = request.headers.get("Origin")
        if origin:
            return origin.rstrip("/") == expected
        referer = request.headers.get("Referer")
        if referer:
            parsed = urlsplit(referer)
            return f"{parsed.scheme}://{parsed.netloc}" == expected
        return False

    @staticmethod
    def _positive_env(name: str, default: int) -> int:
        raw_value = os.environ.get(name)
        if raw_value is None:
            return default
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise RuntimeError(f"{name} must be a positive integer") from exc
        if value <= 0:
            raise RuntimeError(f"{name} must be a positive integer")
        return value

    @staticmethod
    def _boolean_env(name: str, default: bool) -> bool:
        raw_value = os.environ.get(name)
        if raw_value is None:
            return default
        normalized = raw_value.lower()
        if normalized in {"1", "true", "yes"}:
            return True
        if normalized in {"0", "false", "no"}:
            return False
        raise RuntimeError(f"{name} must be true or false")

    @staticmethod
    def _page(title: str, body: str, *, status: int = 200) -> Response:
        content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
    :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
            background: #f4f6f8; }}
    main {{ width: min(28rem, calc(100% - 2rem)); padding: 2rem; border-radius: 1rem;
            background: white; box-shadow: 0 .5rem 2rem #0002; }}
    h1 {{ margin-top: 0; }}
    label, input, button {{ display: block; width: 100%; box-sizing: border-box; }}
    input {{ margin: .5rem 0 1rem; padding: .8rem; border: 1px solid #889; border-radius: .5rem; }}
    button, .button {{ display: inline-block; width: auto; border: 0; border-radius: .5rem;
                       padding: .75rem 1rem; background: #3050d0; color: white;
                       font: inherit; text-decoration: none; cursor: pointer; }}
    .secondary {{ background: #687080; }}
    .error {{ color: #b00020; }} .message {{ color: #176b32; }}
    dt {{ margin-top: .8rem; font-weight: 600; }} dd {{ margin-left: 0; }}
    footer {{ margin-top: 1.5rem; font-size: .875rem; }}
    @media (prefers-color-scheme: dark) {{
      body {{ background: #15171b; }} main {{ background: #22252b; }}
    }}
  </style>
</head>
<body>
  <main>
    <h1>{escape(title)}</h1>
    {body}
    <footer>
      <a href="https://github.com/dz-mykolas/searxng-access">Source code</a>
    </footer>
  </main>
</body>
</html>"""
        response = Response(content, status=status, content_type="text/html; charset=utf-8")
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
        return response

    @staticmethod
    def _error(status: int, code: str, message: str) -> Response:
        headers = {}
        if status == 401:
            headers["WWW-Authenticate"] = 'Bearer realm="searxng", error="invalid_token"'
        return Response(
            json.dumps({"error": code, "message": message}),
            status=status,
            headers=headers,
            content_type="application/json",
        )
