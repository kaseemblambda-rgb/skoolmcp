import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from catknows import hosted_activity as activity, hosted_analytics as analytics
from test_hosted_analytics import FakeClient, Batch


def post(identity, created, group="account-a-group", comments=0):
    return {"post":{"id":identity,"name":identity,"groupId":group,"userId":"account-a-member",
        "createdAt":created,"metadata":{"title":"Repeated question","content":"How?",
            "comments":comments,"upvotes":0}}}


class ActivityTests(unittest.TestCase):
    def setUp(self):
        patcher=patch("catknows.hosted_activity.time.sleep")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_complete_period_beyond_two_hundred(self):
        client=FakeClient("account-a")
        rows=[post(str(i),"2026-11-05T00:00:00Z") for i in range(251)]
        calls=[]
        def page(path,slug):
            n=int(parse_qs(urlsplit(path).query)["p"][0])
            calls.append(n)
            return {"pageProps":{"postTrees":rows[(n-1)*100:n*100]}}
        client.http.get_next=page
        result=activity.period_posts(client,"account-a","account-a-group",
            "2026-11-01T00:00:00Z","2026-12-01T00:00:00Z","question")
        self.assertEqual(len(result["data"]),251)
        self.assertEqual(calls,[1,2,3,4])
        self.assertTrue(result["coverage"]["period_membership_complete"])

    def test_repeated_pages_and_cross_group_fail(self):
        client=FakeClient("account-a")
        rows=[post("one","2026-11-05T00:00:00Z")]
        client.http.get_next=lambda *args:{"pageProps":{"postTrees":rows}}
        with self.assertRaises(activity.CoverageError):
            list(activity.walk_posts(client,"account-a","account-a-group",float("inf")))
        rows[0]["post"]["groupId"]="account-b-group"
        with self.assertRaises(PermissionError):
            list(activity.walk_posts(client,"account-a","account-a-group",float("inf")))

    def test_full_member_roster_has_no_limit(self):
        client=FakeClient("account-a")
        def get_members(slug,**kwargs):
            self.assertNotIn("limit",kwargs)
            return Batch([{"id":str(i),"member":{"metadata":{"numGenericPosts":0}}} for i in range(2201)])
        client.members=get_members
        rows,coverage=analytics.members(client,"account-a")
        self.assertEqual(len(rows),2201)
        self.assertTrue(coverage["members_complete"])
        self.assertEqual(sum(analytics.member_row(r)["lifetime_posts"] is None for r in rows),0)

    def test_incomplete_members_are_not_returned(self):
        class Short(Batch):
            total_members=100
        client=FakeClient("account-a")
        client.members=lambda *args,**kwargs:Short([{}])
        with self.assertRaises(ValueError):
            analytics.members(client,"account-a")

    def test_old_post_recent_comment_prevents_false_quiet(self):
        client=FakeClient("account-a")
        original=client.members
        def roster(*args,**kwargs):
            rows=original(*args,**kwargs)
            rows[0]["member"]["lastOffline"]="2026-10-20T00:00:00Z"
            return rows
        client.members=roster
        rows=[post("old","2026-09-01T00:00:00Z",comments=2)]
        client.http.get_next=lambda path,slug:{"pageProps":{"postTrees":rows if "p=1" in path else []}}
        def get_comments(path):
            cursor=int(parse_qs(urlsplit(path).query)["created-gt"][0])
            children=[] if cursor else [
                {"post":{"id":"oct","user_id":"account-a-member","created_at":"2026-10-15T00:00:00Z",
                         "metadata":{"content":"Old reply"}}},
                {"post":{"id":"nov","user_id":"account-a-member","created_at":"2026-11-10T00:00:00Z",
                         "metadata":{"content":"New reply"}}}]
            return {"post_tree":{"children":children},"last":10}
        client.http.get_api2=get_comments
        result=activity.evidence(client,"account-a","account-a-group",
            "2026-10-01T00:00:00Z","2026-12-01T00:00:00Z",split="2026-11-01T00:00:00Z")
        member=result["data"]["members"][0]
        self.assertEqual(member["previous_comments"],1)
        self.assertEqual(member["observed_comments"],1)
        self.assertFalse(member["quiet_candidate"])
        self.assertFalse(result["data"]["admin_daily_activities"]["individual_attribution"])

    def test_last_seen_and_missing_last_seen(self):
        client=FakeClient("account-a")
        original=client.members
        def roster(*args,**kwargs):
            rows=original(*args,**kwargs)
            rows[0]["member"]["lastOffline"]="2026-11-10T00:00:00Z"
            return rows
        client.members=roster
        result=activity.evidence(client,"account-a","account-a-group",
            "2026-10-01T00:00:00Z","2026-12-01T00:00:00Z",split="2026-11-01T00:00:00Z")
        self.assertTrue(result["data"]["members"][0]["current_activity_observed"])
        self.assertFalse(result["data"]["members"][0]["quiet_candidate"])
        self.assertEqual(result["unknown_counts"]["last_seen"],1)

    def test_stopped_comment_cursor_and_budget(self):
        client=FakeClient("account-a")
        client.http.get_api2=lambda path:{"post_tree":{"children":[
            {"post":{"id":"comment","metadata":{"content":"reply"}}}]},"last":0}
        with self.assertRaises(activity.CoverageError):
            activity.comments(client,"post","account-a-group",float("inf"))
        with self.assertRaises(activity.CoverageError):
            list(activity.walk_posts(client,"account-a","account-a-group",0))

    def test_unknown_post_dates_and_window(self):
        client=FakeClient("account-a")
        client.http.get_next=lambda path,slug:{"pageProps":{"postTrees":
            [post("unknown",None)] if "p=1" in path else []}}
        result=activity.period_posts(client,"account-a","account-a-group",
            "2026-11-01T00:00:00Z","2026-12-01T00:00:00Z")
        self.assertEqual(result["unknown_counts"]["post_dates"],1)
        self.assertFalse(result["coverage"]["period_membership_complete"])
        with self.assertRaises(ValueError):
            activity.window("2026-01-01T00:00:00Z","2026-12-01T00:00:00Z")


if __name__=="__main__":
    unittest.main()
