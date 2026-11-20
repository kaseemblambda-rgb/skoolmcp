"""Synthetic two-account and analytics regressions; no real Skool requests."""
import asyncio
import base64
import json
import os
import unittest
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from catknows import hosted_analytics as a
from catknows.hosted_sessions import decrypt_session
from catknows.hosted_tools import register_tools


class Batch(list):
    incomplete = False
    capped_by_role = False
    @property
    def total_members(self):
        return len(self)


class FakeClient:
    def __init__(self, owner, role="group-admin"):
        self.owner = owner
        self.role = role
        self.closed = False
        self.http = SimpleNamespace(_http=SimpleNamespace(close=self.close),
            get_next=self.get_next, get_api2=self.get_api2)
    def close(self):
        self.closed = True
    def self_user(self):
        return {"id":self.owner}
    def self_groups(self):
        return [{"id":self.owner+"-group","name":self.owner,"metadata":{
            "display_name":self.owner,"total_members":2,
            "member":json.dumps({"role":self.role})}}]
    def members(self, slug, **kwargs):
        assert slug == self.owner
        return Batch([{"id":self.owner+"-member","name":"Synthetic member","member":{
            "approvedAt":"2026-11-01T00:00:00Z","metadata":{"numGenericPosts":0,
            "requestLocation":"Test city (Test country)", "isFreeTrial":False,
            "mbscpe":int((datetime.now(timezone.utc)+timedelta(days=3)).timestamp()),
            "mmbp":json.dumps({"tier":"premium","currency":"usd","amount":12000,"recurring_interval":"year"})}}},
            {"id":self.owner+"-unknown","member":{"metadata":{}}}])
    def posts(self,slug,**kwargs):
        assert slug == self.owner
        return [{"post":{"id":self.owner+"-post","name":"synthetic-post","groupId":self.owner+"-group",
            "userId":self.owner+"-member","createdAt":"2026-10-15T00:00:00Z",
            "metadata":{"title":"How do I grow?","content":"Synthetic question","comments":0,"upvotes":0,
                        "auth_token":"must never escape"}}}]
    def get_next(self,path,slug):
        from urllib.parse import urlsplit, parse_qs
        page=int(parse_qs(urlsplit(path).query)["p"][0])
        return {"pageProps":{"postTrees":self.posts(slug) if page==1 else []}}
    def get_api2(self,path):
        return {"post_tree":{"children":[]},"last":0}
    def admin_metrics(self,gid):
        return {"daily_activities":{"start_date":"2026-01-01","end_date":"2026-12-31","counts":[0,1]}}
    def analytics_chart(self,gid,chart):
        return [{"date":"2026-11-01","mrr":0,"churn":0,"auth_token":"must never escape"}]


class Registry:
    def __init__(self):
        self.tools={}
    def tool(self, **kwargs):
        def register(fn):
            self.tools[fn.__name__]=fn
            return fn
        return register


class AnalyticsTests(unittest.TestCase):
    def test_zero_missing_and_labels(self):
        client=FakeClient("account-a")
        chart=a.dashboard(client,"account-a-group","mrr")
        self.assertEqual(chart["label"],"verified")
        self.assertEqual(chart["data"][0]["mrr"],0)
        self.assertEqual(chart["unknown_counts"]["upgrade"],1)
        self.assertNotIn("must never escape",json.dumps(chart))
        revenue=a.tier_revenue(client,"account-a")
        self.assertEqual(revenue["data"][0]["monthly_amount_source_units"],1000)
        self.assertEqual(revenue["unknown_counts"]["unclassified_members"],1)
        self.assertEqual(revenue["label"],"estimated")
        self.assertIsNone(a.trials(client,"account-a")["data"]["trial_to_paid_rate"])

    def test_no_nan_and_country_coverage(self):
        class Malformed(FakeClient):
            def analytics_chart(self, gid, chart):
                return [{"date": "2026-11-01", "mrr": float("nan"),
                         "churn": float("inf"), "upgrade": {"private": "hidden"}}]
        result = a.dashboard(Malformed("account-a"),"account-a-group","mrr")
        self.assertIsNone(result["data"][0]["mrr"])
        self.assertIsNone(result["data"][0]["upgrade"])
        json.dumps(result, allow_nan=False)
        country = a.tier_revenue(FakeClient("account-a"),"account-a",True)
        self.assertEqual(country["data"][0]["country"],"test country")
        self.assertEqual(country["unknown_counts"]["unclassified_members"],1)

    def test_sparse_trial_flag_country_rankings_and_unknown_billing(self):
        now = datetime.now(timezone.utc)
        def row(country, amount=120, interval="month", currency="usd", tier="premium", days=10, **metadata):
            return {"metadata":{"location":"Private profile location"},"member":{
                "approvedAt":(now-timedelta(days=days)).isoformat(),"metadata":{
                    "requestLocation":"Private city ("+country+")",
                    "mbscpe":int((now+timedelta(days=5)).timestamp()),
                    "mmbp":json.dumps(dict(amount=amount,recurring_interval=interval,currency=currency,tier=tier)),
                    **metadata}}}
        users=Batch([
            row("Country Alpha",amount=1200,interval="year",days=50),
            row(" country alpha ",amount=100,days=30,isFreeTrial=False),
            row("Country Beta",amount=400,days=10),
            row("Country Gamma",amount=500,currency="eur",days=20),
            row("Country Beta",amount=700,tier="pro",days=40),
            row("Country Alpha",amount=9000,isFreeTrial=True),
            row("Country Alpha",amount=8000,isFreeTrial=None),
            row("Country Alpha",amount=8000,mbscpe=int((now-timedelta(days=1)).timestamp())),
            row("Country Alpha",amount=8000,interval="one_time"),
            row("Country Alpha",amount=0),
            {"metadata":{"location":"Must not infer a country"},"member":{
                "approvedAt":(now-timedelta(days=90)).isoformat(),"metadata":{
                    "requestLocation":"Private city (Country Delta)"}}},
            row("Country Alpha",requestLocation="Private city only"),
        ])
        client=FakeClient("account-a")
        client.members=lambda *args,**kwargs:users
        result=a.tier_revenue(client,"account-a",True)
        self.assertEqual(result["label"],"estimated")
        alpha=next(r for r in result["data"] if r["country"]=="country alpha")
        self.assertEqual(alpha["monthly_amount_source_units"],200)
        self.assertEqual(alpha["revenue_members"],2)
        self.assertEqual(alpha["unknown_revenue_members"],2)
        self.assertEqual(alpha["excluded_revenue_members"],3)
        self.assertEqual(alpha["revenue_rank_within_tier_currency"],2)
        beta=next(r for r in result["data"] if r["country"]=="country beta" and r["tier"]=="premium")
        self.assertEqual(beta["revenue_rank_within_tier_currency"],1)
        usd=[r for r in result["country_revenue_rankings"] if r["currency"]=="usd"]
        self.assertEqual([r["country"] for r in usd],["country beta","country alpha"])
        self.assertEqual(usd[0]["monthly_amount_source_units"],1100)
        self.assertEqual(usd[0]["tiers"],["premium","pro"])
        eur=next(r for r in result["country_revenue_rankings"] if r["currency"]=="eur")
        self.assertEqual(eur["revenue_rank"],1)
        delta=next(r for r in result["data"] if r["country"]=="country delta")
        self.assertIsNone(delta["monthly_amount_source_units"])
        self.assertIsNone(delta["tier"])
        self.assertIsNone(delta["revenue_rank_within_tier_currency"])
        self.assertEqual(result["country_tenure_rankings"][0]["country"],"country delta")
        self.assertEqual(result["unknown_counts"]["country"],1)
        self.assertEqual(result["coverage"]["members_with_country"],11)
        self.assertEqual(result["coverage"]["estimated_revenue_members_with_omitted_trial_flag"],4)
        self.assertNotIn("Private",json.dumps(result))
        json.dumps(result,allow_nan=False)

    def test_country_location_unknowns_ties_and_missing_tenure(self):
        now=datetime.now(timezone.utc)
        def user(country,joined=None):
            return {"member":{"approvedAt":joined,"metadata":{
                "requestLocation":country,"isFreeTrial":False,
                "mbscpe":int((now+timedelta(days=1)).timestamp()),
                "mmbp":dict(amount=40,currency="USD",tier="premium",recurring_interval="month")}}}
        users=Batch([user("City (COUNTRY A)"),user("Other city (country b)","invalid"),
                     user("City (country c)",(now+timedelta(days=1)).isoformat()),
                     user("City"),user(None),user("City (private@example.test)")])
        client=FakeClient("account-a");client.members=lambda *args,**kwargs:users
        result=a.country_value(client,"account-a")
        self.assertEqual(len(result["data"]),3)
        self.assertTrue(all(r["revenue_rank_within_tier_currency"]==1 for r in result["data"]))
        self.assertTrue(all(r["tenure_rank_within_tier_currency"] is None for r in result["data"]))
        self.assertEqual(result["unknown_counts"]["country"],3)
        self.assertEqual(result["unknown_counts"]["tenure"],6)
        self.assertNotIn("private@example.test",json.dumps(result))
        json.dumps(result,allow_nan=False)
        for value in (None,"",{},"City only","City ()","City (123)"):
            self.assertIsNone(a.member_country({"metadata":{"requestLocation":value}}))
        client.members=lambda *args,**kwargs:Batch([])
        empty=a.country_value(client,"account-a")
        self.assertEqual(empty["data"],[])
        self.assertEqual(empty["country_revenue_rankings"],[])
        self.assertEqual(empty["country_tenure_rankings"],[])

    def test_country_requires_complete_roster_and_keeps_invalid_prices_unknown(self):
        client=FakeClient("account-a")
        class Incomplete(Batch):
            incomplete=True
        client.members=lambda *args,**kwargs:Incomplete([])
        with self.assertRaises(ValueError):
            a.country_value(client,"account-a")
        users=FakeClient("account-a").members("account-a")
        users[0]["member"]["metadata"]["mmbp"]={
            "amount":float("inf"),"currency":"usd","tier":"premium","recurring_interval":"month"}
        client.members=lambda *args,**kwargs:users
        result=a.country_value(client,"account-a")
        self.assertEqual(len(result["data"]),1)
        self.assertIsNone(result["data"][0]["monthly_amount_source_units"])
        self.assertEqual(result["country_revenue_rankings"],[])
        self.assertEqual(result["unknown_counts"]["recurring_revenue"],2)
        json.dumps(result,allow_nan=False)

    def test_period_and_lifetime_unknown(self):
        client=FakeClient("account-a")
        data=a.activity(client,"account-a","account-a-group","2026-11-01T00:00:00Z","2026-12-01T00:00:00Z")
        self.assertTrue(data["data"]["members"][0]["never_posted"])
        self.assertIsNone(data["data"]["members"][1]["never_posted"])
        self.assertTrue(data["coverage"]["post_pages_complete"])
        self.assertTrue(data["coverage"]["members_complete"])
        for start,end in [("invalid","invalid"),("2026-01-01","2026-02-01"),
                          ("2026-03-01T00:00:00Z","2026-02-01T00:00:00Z")]:
            with self.assertRaises(ValueError):
                a.period(start,end)

    def test_community_and_role_isolation(self):
        with self.assertRaises(PermissionError):
            a.authorized(FakeClient("account-a"),"account-b")
        with self.assertRaises(PermissionError):
            a.authorized(FakeClient("account-a","member"),"account-a")
        self.assertEqual(a.authorized(FakeClient("account-a","member"),"account-a",False)["role"],"member")
        for slug in ["../other","account-a?group=account-b","https://other"]:
            with self.assertRaises(PermissionError):
                a.authorized(FakeClient("account-a"),slug)

    def test_cross_group_post_rejected(self):
        with self.assertRaises(PermissionError):
            a.posts(FakeClient("account-a"),"account-a","account-b-group")

    def test_encryption_bound_to_subject_and_version(self):
        key=os.urandom(32)
        nonce=os.urandom(12)
        owner,other=str(uuid4()),str(uuid4())
        body=json.dumps(dict(cookie_header="test=value",auth_token="synthetic",waf_token="synthetic")).encode()
        row=dict(nonce=base64.b64encode(nonce).decode(),
                 ciphertext=base64.b64encode(AESGCM(key).encrypt(nonce,body,(owner+":v1").encode())).decode(),
                 key_version="v1",revoked_at=None)
        self.assertTrue(decrypt_session(owner,row,key,"v1").is_valid)
        for subject,version,revoked in [(other,"v1",None),(owner,"v2",None),(owner,"v1","revoked")]:
            with self.assertRaises(Exception):
                decrypt_session(subject,{**row,"revoked_at":revoked},key,version)

    def test_concurrent_requests_and_revoked_access(self):
        registry=Registry()
        created=[]
        def provider(subject):
            client=FakeClient(subject)
            created.append(client)
            return client
        class Verifier:
            allowed=True
            async def verify_token(self,token):
                return SimpleNamespace(subject=identity.get().subject) if self.allowed else None
        verifier=Verifier()
        register_tools(registry,provider,verifier)
        from contextvars import ContextVar
        identity=ContextVar("synthetic_identity")
        async def call(subject,slug):
            identity.set(SimpleNamespace(subject=subject,token="synthetic"))
            return await registry.tools["get_revenue_by_tier"](slug)
        async def check():
            with patch("catknows.hosted_tools.get_access_token",side_effect=lambda:identity.get()):
                one,two=await asyncio.gather(call("account-a","account-a"),call("account-b","account-b"))
                self.assertEqual(one["data"][0]["tier"],"premium")
                self.assertEqual(two["data"][0]["tier"],"premium")
                self.assertEqual(len(created),2)
                self.assertTrue(all(c.closed for c in created))
                async def roster(subject):
                    identity.set(SimpleNamespace(subject=subject, token="synthetic"))
                    return await registry.tools["list_members"](subject)
                first, second = await asyncio.gather(roster("account-a"), roster("account-b"))
                self.assertTrue(first["data"][0]["id"].startswith("account-a"))
                self.assertTrue(second["data"][0]["id"].startswith("account-b"))
                self.assertNotIn("account-b", json.dumps(first))
                self.assertNotIn("account-a", json.dumps(second))
                with self.assertRaises(ValueError):
                    await call("account-a","account-b")
                verifier.allowed=False
                before=len(created)
                with self.assertRaises(PermissionError):
                    await call("account-a","account-a")
                self.assertEqual(len(created),before)
        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
