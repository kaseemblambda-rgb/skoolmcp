"""Isolated OAuth-protected hosted MCP read service.

Run with python -m catknows.hosted_server. Configuration is environment-only.
This module never imports the local MCP registry or opens a Skool profile.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings


def https_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or parsed.port == 0):
        raise ValueError("Configure an HTTPS origin without path or credentials")
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    public_origin: str
    supabase_origin: str
    service_key: str = field(repr=False)
    paid_tiers: frozenset[str]
    database: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        https_origin(self.public_origin)
        if self.supabase_origin:
            https_origin(self.supabase_origin)
        if (not self.service_key and self.database is None) or not self.paid_tiers:
            raise ValueError("Service credential and explicit paid tiers are required")
        if self.database is not None and (self.service_key or self.supabase_origin):
            raise ValueError('Database mode cannot use legacy API credentials')

    @property
    def resource(self) -> str:
        return self.public_origin.rstrip("/") + "/mcp"

    @property
    def issuer(self) -> str:
        return self.supabase_origin.rstrip("/") + "/auth/v1"

    @classmethod
    def from_env(cls):
        # Reject personal-account deployment inputs rather than silently using them.
        for name in ("CATKNOWS_COOKIE", "CATKNOWS_PROFILE_DIR", "STEALTH_MCP_COMMUNITY", "HOSTED_OWNER_PROFILE_DIR",
                     "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_URL", "SUPABASE_ACCESS_TOKEN", "CATKNOWS_ALLOW_WRITE"):
            if os.environ.get(name):
                raise ValueError("Personal Skool configuration is incompatible with hosted mode")
        tiers=frozenset(t.strip() for t in os.environ['SFC_PAID_TIERS'].split(',') if t.strip())
        if tiers != frozenset({'premium', 'standard'}):
            raise ValueError('Paid tiers must match the restricted SQL gateway')
        from .hosted_database import DatabaseConfig, RestrictedDatabase
        return cls(https_origin(os.environ['PUBLIC_BASE_URL']), '', '', tiers,
                   RestrictedDatabase(DatabaseConfig.from_env()))


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_json(url: str, headers: dict) -> object:
    # Redirects could otherwise forward credentials to another destination.
    with build_opener(NoRedirects()).open(Request(url, headers=headers), timeout=5) as response:
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError("Response too large")
        return json.loads(body)


class MemberVerifier:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.slots = asyncio.Semaphore(16)
        self.keys = jwt.PyJWKClient(
            settings.issuer + "/.well-known/jwks.json",
            timeout=5, lifespan=300,
        )

    def verify_sync(self, token: str) -> AccessToken | None:
        if len(token) > 16384:
            return None
        try:
            key = self.keys.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token, key.key, algorithms=["RS256", "ES256"],
                issuer=self.settings.issuer, audience=self.settings.resource,
                options={"require": ["exp", "iat", "sub", "iss", "aud", "client_id", "scope"]},
            )
            subject, client_id, scope = claims["sub"], claims["client_id"], claims["scope"]
            if not all(isinstance(v, str) and v for v in (subject, client_id, scope)):
                return None
            if "mcp:read" not in scope.split():
                return None
            # Ask Auth for the current confirmed identity. Do not trust an email
            # supplied by a tool argument or a stale token email claim.
            identity = get_json(self.settings.issuer + "/user", {
                "apikey": self.settings.service_key,
                "Authorization": "Bearer " + token,
            })
            if identity.get("id") != subject or not identity.get("email_confirmed_at"):
                return None
            email = identity.get("email")
            if not isinstance(email, str) or not email.strip():
                return None
            query = urlencode({"select": "tier,lifecycle,paid_through_at,observed_at", "email": "eq." + email.strip().lower()})
            rows = get_json(self.settings.supabase_origin.rstrip("/") + "/rest/v1/hosted_entitlements?" + query, {
                "apikey": self.settings.service_key,
                "Authorization": "Bearer " + self.settings.service_key,
            })
            if not isinstance(rows, list) or len(rows) != 1:
                return None
            from .hosted_membership import eligible
            if not eligible(rows[0], self.settings.paid_tiers, datetime.now(timezone.utc)):
                return None
            return AccessToken(
                token=token, client_id=client_id, subject=subject,
                scopes=["mcp:read"], expires_at=claims["exp"],
                resource=self.settings.resource,
            )
        except Exception:
            # No upstream bodies, token values, email addresses or exception
            # messages are sent to clients or logs.
            return None

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            await asyncio.wait_for(self.slots.acquire(), timeout=0.1)
        except TimeoutError:
            return None
        try:
            return await asyncio.to_thread(self.verify_sync, token)
        finally:
            self.slots.release()


def build_app(settings: Settings, session_provider=None, connect_store=None, account_verifier=None,
              browser_factory=None, oauth_provider=None, identity_reader=None):
    from .hosted_security import install_private_logging, OAuthBoundary
    install_private_logging()
    from .hosted_oauth import SkoolOAuthProvider, skool_identity
    from .hosted_connect import BrowserBridge
    from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
    provider = oauth_provider or SkoolOAuthProvider(settings)
    server = MCPServer(
        "Stealth MCP", auth_server_provider=provider,
        auth=AuthSettings(issuer_url=settings.public_origin, resource_server_url=settings.resource,
            required_scopes=["mcp:read"], validate_token_resource=True,
            client_registration_options=ClientRegistrationOptions(enabled=True,
                valid_scopes=["mcp:read"], default_scopes=["mcp:read"]),
            revocation_options=RevocationOptions(enabled=True)),
    )

    @server.tool()
    def status() -> dict:
        """Check that this authenticated connection can reach Stealth MCP."""
        return {"status": "ok", "service": "Stealth MCP"}

    from .hosted_sessions import SessionProvider
    from .hosted_tools import register_tools
    register_tools(server, session_provider or SessionProvider(settings), provider)
    app = server.streamable_http_app(
        stateless_http=True, json_response=True, max_request_body_size=65536,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
            allowed_hosts=[urlsplit(settings.public_origin).netloc], allowed_origins=[settings.public_origin]),
    )
    if account_verifier is not None:
        # Explicit legacy fixture injection only; never used by the production entry point.
        from .hosted_connect import routes
        app.routes.extend(routes(settings, connect_store, account_verifier, browser_factory or BrowserBridge))
    else:
        from .hosted_popup import routes
        app.routes.extend(routes(settings, provider, identity_reader or skool_identity, browser_factory or BrowserBridge))
    if settings.database is not None:
        from contextlib import asynccontextmanager
        original_lifespan = app.router.lifespan_context
        @asynccontextmanager
        async def lifespan(application):
            try:
                async with original_lifespan(application) as state:
                    yield state
            finally:
                settings.database.close()
        app.router.lifespan_context = lifespan
    return OAuthBoundary(app, settings.resource)


def main():
    import uvicorn
    from .hosted_security import install_private_logging
    install_private_logging()
    try:
        # Validate required secrets/trust before opening the public listener.
        # These operations are local and do not contact Supabase or Skool.
        from .hosted_connect import BrowserBridge
        from .hosted_keys import keyring
        keyring()
        BrowserBridge()
        uvicorn.run(build_app(Settings.from_env()), host="0.0.0.0",
            port=int(os.environ.get("PORT", "8000")),
            access_log=False, log_level="warning", proxy_headers=False)
    except Exception:
        raise SystemExit('Hosted server startup failed') from None


if __name__ == "__main__":
    main()
