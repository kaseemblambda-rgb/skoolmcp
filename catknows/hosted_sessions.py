"""Read-only per-request session loading. Session provisioning is a separate flow."""
import base64
import json
import os
from urllib.parse import urlencode
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .auth import Session
from .client import SkoolClient
from .hosted_server import get_json


def decrypt_session(subject, row, key, key_version):
    if str(UUID(subject)) != subject or row.get("revoked_at") is not None:
        raise ValueError("Session unavailable")
    if row["key_version"] != key_version or len(key) != 32:
        raise ValueError("Session key unavailable")
    nonce = base64.b64decode(row["nonce"], validate=True)
    if len(nonce) != 12:
        raise ValueError("Invalid nonce")
    payload = AESGCM(key).decrypt(nonce,
        base64.b64decode(row["ciphertext"], validate=True),
        (subject + ":" + key_version).encode())
    data = json.loads(payload)
    if set(data) != {"cookie_header", "auth_token", "waf_token"}:
        raise ValueError("Invalid session")
    if not all(isinstance(v, str) and v and "\r" not in v and "\n" not in v for v in data.values()):
        raise ValueError("Invalid session")
    return Session(**data)


class SessionProvider:
    def __init__(self, settings):
        self.settings = settings

    def rows(self, subject):
        if self.settings.database is not None:
            from mcp.server.auth.middleware.auth_context import get_access_token
            from .hosted_oauth import hashed
            token=get_access_token()
            if (token is None or token.subject != subject or not isinstance(token.token,str)
                    or not token.token.startswith('st_a_') or not 32<=len(token.token)<=128):
                raise PermissionError('Request-bound access token required')
            row=self.settings.database.rpc('hosted_server_session', dict(p_account=str(UUID(subject)),
                p_token_hash=hashed(token.token), p_resource=self.settings.resource))
            return [row] if row else []
        # Legacy constructor fixtures/local harness only; from_env rejects API keys.
        query=urlencode({'select':'ciphertext,nonce,key_version,revoked_at','user_id':'eq.'+str(UUID(subject))})
        return get_json(self.settings.supabase_origin+'/rest/v1/hosted_skool_sessions?'+query,
            {'apikey':self.settings.service_key,'Authorization':'Bearer '+self.settings.service_key})

    def __call__(self, subject):
        rows = self.rows(subject)
        if len(rows) != 1:
            raise ValueError("Connect your Skool account first")
        from .hosted_keys import keyring
        _, keys = keyring()
        version = rows[0]["key_version"]
        session = decrypt_session(subject, rows[0], keys[version], version)
        client = SkoolClient(session)
        from .hosted_security import ReadOnlyTransport
        client.http._http = ReadOnlyTransport(client.http._http)
        client._hosted_session_snapshot = dict(rows[0])
        # Even accidental future tool registration cannot invoke upstream writes.
        def denied(*args, **kwargs):
            raise PermissionError("Read-only service")
        client.http._write_api2 = denied
        client.http.put_bytes = denied
        return client

    def assert_current(self, subject, client):
        """A disconnect/reconnect/rotation during a read suppresses its result."""
        rows = self.rows(subject)
        if len(rows) != 1 or rows[0] != client._hosted_session_snapshot or rows[0].get("revoked_at") is not None:
            raise PermissionError("Skool connection changed")
