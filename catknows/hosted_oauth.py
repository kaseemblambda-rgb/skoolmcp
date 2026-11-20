"""Native connector OAuth. Skool verifies identity; Supabase only persists state."""
import asyncio
import hashlib
import json
import os
import re
import secrets
import time
from urllib.parse import urlsplit
from contextvars import ContextVar


from mcp.server.auth.provider import (AccessToken, AuthorizationCode, RefreshToken,
    AuthorizationParams, AuthorizeError, RegistrationError, TokenError,
    OAuthAuthorizationServerProvider)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .hosted_connect import Store
from .hosted_analytics import moment
from .hosted_security import ReadOnlyTransport, RateBudget


authorization_browser = ContextVar("stealth_authorization_browser", default=None)
authorization_source = ContextVar("stealth_authorization_source", default=None)

def hashed(value):
    return hashlib.sha256(value.encode()).hexdigest()


def secret(prefix):
    return prefix + secrets.token_urlsafe(32)


class OAuthStore(Store):
    def call(self, operation, **payload):
        return self.rpc("hosted_oauth", {"p_op": operation, "p": payload})


def skool_identity(session):
    """Only the actual cookie-authenticated /self response supplies account identity."""
    from .client import SkoolClient
    client = SkoolClient(session)
    client.http._http = ReadOnlyTransport(client.http._http)
    try:
        identity = client.self_user()
        value = identity.get("id")
        if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", value):
            raise ValueError("Skool identity unavailable")
        return value
    finally:
        client.http._http.close()


class SkoolOAuthProvider(OAuthAuthorizationServerProvider):
    def __init__(self, settings, store=None, redirect_uris=None):
        self.settings = settings
        self.store = store or OAuthStore(settings)
        self.redirect_uris = frozenset(redirect_uris if redirect_uris is not None else
            json.loads(os.environ.get("HOSTED_OAUTH_REDIRECT_URIS", "[]")))
        for uri in self.redirect_uris:
            parsed = urlsplit(uri)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                    or parsed.password or parsed.fragment):
                raise ValueError("Explicit HTTPS connector callbacks required")
        self.authorize_budget = RateBudget(20)

    async def call(self, operation, **payload):
        return await asyncio.to_thread(self.store.call, operation,
            tiers=sorted(self.settings.paid_tiers), **payload)

    async def get_client(self, client_id):
        if not isinstance(client_id, str) or len(client_id) > 128:
            return None
        row = await self.call("client_get", client_id=client_id)
        return OAuthClientInformationFull.model_validate(row) if row else None

    async def register_client(self, client_info):
        redirects = [str(u) for u in client_info.redirect_uris or []]
        if (not redirects or not set(redirects).issubset(self.redirect_uris)
                or client_info.token_endpoint_auth_method != "none" or client_info.client_secret
                or set(client_info.grant_types) - {"authorization_code", "refresh_token"}
                or "authorization_code" not in client_info.grant_types
                or client_info.response_types != ["code"]
                or client_info.scope != "mcp:read"):
            raise RegistrationError("invalid_client_metadata", "Connector configuration is not approved")
        # Store only required public metadata, never client secrets or contact details.
        metadata = client_info.model_dump(mode="json", include={"client_id", "client_name", "redirect_uris",
            "token_endpoint_auth_method", "grant_types", "response_types", "scope", "client_id_issued_at"})
        metadata["client_name"] = (metadata.get("client_name") or "MCP connector")[:80]
        if await self.call("client_save", client_id=client_info.client_id, metadata=metadata) is not True:
            raise RegistrationError("invalid_client_metadata", "Connector registration capacity reached")

    async def authorize(self, client, params: AuthorizationParams):
        if (params.resource != self.settings.resource or params.scopes not in (None, ["mcp:read"])
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge)
                or len(params.state or "") > 512
                or str(params.redirect_uri) not in self.redirect_uris):
            raise AuthorizeError("invalid_request", "Invalid connector authorization")
        client.validate_redirect_uri(params.redirect_uri)
        if not self.authorize_budget.allow(client.client_id):
            raise AuthorizeError("temporarily_unavailable", "Retry shortly")
        browser = authorization_browser.get()
        if not browser:
            raise AuthorizeError("invalid_request", "Start from the connector authorization URL")
        ticket = secret("st_l_")
        request = params.model_dump(mode="json")
        request["scopes"] = ["mcp:read"]
        result = await self.call("flow_new", handle_hash=hashed(ticket), expected_browser_hash=hashed(browser),
            client_id=client.client_id, request=request, source_hash=authorization_source.get())
        if result is not True:
            raise AuthorizeError("temporarily_unavailable", "Login capacity reached; retry shortly")
        return self.settings.public_origin + "/connect/skool#" + ticket

    async def load_authorization_code(self, client, authorization_code):
        if not authorization_code.startswith("st_c_") or len(authorization_code) > 128:
            return None
        row = await self.call("code_get", code_hash=hashed(authorization_code), client_id=client.client_id)
        if not row:
            return None
        return AuthorizationCode(code=authorization_code, client_id=client.client_id,
            subject=row["account_id"], expires_at=moment(row["expires_at"]).timestamp(),
            **{k: row["request"][k] for k in ("scopes", "code_challenge", "redirect_uri",
                "redirect_uri_provided_explicitly", "resource")})

    async def exchange_authorization_code(self, client, authorization_code):
        access, refresh = secret("st_a_"), secret("st_r_")
        result = await self.call("code_exchange", code_hash=hashed(authorization_code.code),
            client_id=client.client_id, resource=authorization_code.resource,
            access_hash=hashed(access), refresh_hash=hashed(refresh))
        if not result:
            raise TokenError("invalid_grant", "Authorization expired or already used")
        return OAuthToken(access_token=access, refresh_token=refresh, expires_in=300, scope="mcp:read")

    async def load_refresh_token(self, client, refresh_token):
        if not refresh_token.startswith("st_r_") or len(refresh_token) > 128:
            return None
        row = await self.call("token_get", token_hash=hashed(refresh_token))
        if not row or row["kind"] != "refresh" or row["client_id"] != client.client_id:
            return None
        return RefreshToken(token=refresh_token, client_id=client.client_id, subject=row["account_id"],
            scopes=["mcp:read"], expires_at=int(moment(row["expires_at"]).timestamp()), resource=row["resource"])

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        if scopes != ["mcp:read"]:
            raise TokenError("invalid_scope", "Read access only")
        access, refresh = secret("st_a_"), secret("st_r_")
        result = await self.call("token_exchange", token_hash=hashed(refresh_token.token),
            client_id=client.client_id, resource=refresh_token.resource,
            access_hash=hashed(access), refresh_hash=hashed(refresh))
        if not result:
            raise TokenError("invalid_grant", "Refresh unavailable")
        return OAuthToken(access_token=access, refresh_token=refresh,
            expires_in=max(0, min(300, refresh_token.expires_at-int(time.time()))), scope="mcp:read")

    async def load_access_token(self, token):
        if not isinstance(token, str) or not token.startswith("st_a_") or len(token) > 128:
            return None
        try:
            row = await self.call("token_get", token_hash=hashed(token))
            if not row or row["kind"] != "access" or row["resource"] != self.settings.resource:
                return None
            expires = moment(row["expires_at"])
            if expires is None or expires.timestamp()<=time.time():
                return None
            return AccessToken(token=token, client_id=row["client_id"], subject=row["account_id"],
                scopes=["mcp:read"], resource=row["resource"],
                expires_at=int(moment(row["expires_at"]).timestamp()), claims={"iss": self.settings.public_origin})
        except Exception:
            return None

    verify_token = load_access_token

    async def revoke_token(self, token):
        await self.call("revoke", token_hash=hashed(token.token))
