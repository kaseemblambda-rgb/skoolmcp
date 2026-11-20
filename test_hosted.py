"""Offline security regressions for the hosted status service."""
import asyncio
import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

from catknows.hosted_server import Settings, MemberVerifier, build_app


class HostedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.settings = Settings("https://mcp.example.test", "https://project.example.test",
                                 "test-only-placeholder", frozenset({"premium", "paid"}))
        self.verifier = MemberVerifier(self.settings)
        now = int(time.time())
        self.claims = dict(iss=self.settings.issuer, aud=self.settings.resource,
                           sub="test-user", client_id="test-client",
                           scope="mcp:read", iat=now, exp=now+300)
        self.entitlement = dict(tier="premium", lifecycle="active",
            paid_through_at="2099-01-01T00:00:00Z",
            observed_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat())
        self.identity = dict(id="test-user", email="member@example.test",
                             email_confirmed_at="2026-01-01T00:00:00Z")

    def verify(self, changes=None, rows=None, identity=None, private=None):
        claims = {**self.claims, **(changes or {})}
        token = jwt.encode(claims, private or self.private, algorithm="RS256")
        with patch.object(self.verifier.keys, "get_signing_key_from_jwt",
                          return_value=SimpleNamespace(key=self.private.public_key())), \
             patch("catknows.hosted_server.get_json",
                   side_effect=[identity or self.identity, [self.entitlement] if rows is None else rows]):
            return self.verifier.verify_sync(token)

    def test_valid_member(self):
        access = self.verify()
        self.assertEqual(access.subject, "test-user")
        self.assertEqual(access.resource, self.settings.resource)

    def test_existing_token_loses_access(self):
        self.assertIsNotNone(self.verify())
        self.entitlement["paid_through_at"] = "2020-01-01T00:00:00Z"
        self.assertIsNone(self.verify())

    def test_signature(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assertIsNone(self.verify(private=other))

    def test_claims(self):
        for changes in [
            {"iss": "https://other.test"}, {"aud": "authenticated"},
            {"exp": 1}, {"iat": int(time.time())+300}, {"scope": "openid"},
            {"client_id": ""}, {"sub": ""}, {"scope": ["mcp:read"]},
        ]:
            with self.subTest(changes=changes):
                self.assertIsNone(self.verify(changes))

    def test_nonpaying_and_removed(self):
        for rows in [[], [{"tier": "free"}], [{"tier": "admin"}],
                     [{"tier": "premium"}, {"tier": "premium"}]]:
            with self.subTest(rows=rows):
                self.assertIsNone(self.verify(rows=rows))

    def test_identity_binding(self):
        for identity in [
            {**self.identity, "id": "another-user"},
            {**self.identity, "email_confirmed_at": None},
            {**self.identity, "email": None},
        ]:
            self.assertIsNone(self.verify(identity=identity))

    def test_upstream_failure(self):
        with patch.object(self.verifier.keys, "get_signing_key_from_jwt",
                          side_effect=RuntimeError("private upstream details")):
            self.assertIsNone(self.verifier.verify_sync("invalid"))

    def test_custom_https_port(self):
        settings=Settings("https://127.0.0.1:38443","https://127.0.0.1:38445",
                          "placeholder",frozenset({"paid"}))
        self.assertEqual(settings.resource,"https://127.0.0.1:38443/mcp")

    def test_config(self):
        self.assertNotIn("test-only-placeholder", repr(self.settings))
        for url in ["http://example.test", "https://x.test/path", "https://x.test?secret=x",
                    "https://user:secret@x.test"]:
            with self.assertRaises(ValueError):
                Settings(url, self.settings.supabase_origin, "placeholder", frozenset({"paid"}))

    def test_asgi_auth_and_discovery(self):
        app = build_app(self.settings)
        async def request(path, method="GET", authorization=None, payload=None):
            messages = []
            headers = [(b"host", b"mcp.example.test"),
                       (b"accept", b"application/json, text/event-stream"),
                       (b"content-type", b"application/json")]
            if authorization:
                headers.append((b"authorization", authorization.encode()))
            async def receive():
                return {"type": "http.request", "body": json.dumps(payload or {}).encode(),
                        "more_body": False}
            async def send(message):
                messages.append(message)
            await app({"type":"http", "asgi":{"version":"3.0"}, "http_version":"1.1",
                       "scheme":"https", "method":method, "path":path, "raw_path":path.encode(),
                       "query_string":b"", "headers":headers, "server":("mcp.example.test",443),
                       "client":("127.0.0.1",1234)}, receive, send)
            return messages
        async def check():
            async with app.router.lifespan_context(app):
                messages = await request("/mcp", "POST")
                self.assertEqual(messages[0]["status"], 401)
                self.assertIn(b"www-authenticate", dict(messages[0]["headers"]))
                messages = await request("/.well-known/oauth-protected-resource/mcp")
                self.assertEqual(messages[0]["status"], 200)
                body = json.loads(b"".join(m.get("body", b"") for m in messages))
                self.assertEqual(body["resource"], self.settings.resource)
                token = SimpleNamespace()
                # Exercise the real HTTP MCP path with only the verifier mocked.
                from mcp.server.auth.provider import AccessToken
                token = AccessToken(token="test", client_id="test-client", subject="test-user",
                                    scopes=["mcp:read"], resource=self.settings.resource,
                                    expires_at=int(time.time())+300)
                async def accepted(_self, value):
                    return token
                from catknows.hosted_oauth import SkoolOAuthProvider
                with patch.object(SkoolOAuthProvider, "load_access_token", accepted):
                    messages = await request("/mcp", "POST", "Bearer test", {
                        "jsonrpc":"2.0", "id":1, "method":"tools/list", "params":{}})
                self.assertEqual(messages[0]["status"], 200)
                body = json.loads(b"".join(m.get("body",b"") for m in messages))
                names = {t["name"] for t in body["result"]["tools"]}
                self.assertIn("status", names)
                self.assertIn("get_revenue_analytics", names)
                self.assertNotIn("send_dm", names)
                self.assertEqual(len(names), 22)
        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
