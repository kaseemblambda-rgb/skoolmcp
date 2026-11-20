"""Period-based complete walks, with explicit failures on degraded pagination."""
import time
import json
from collections import defaultdict
from datetime import timedelta
from urllib.parse import quote

from . import normalize
from .hosted_analytics import moment, number, period, response, members, member_row


class CoverageError(ValueError):
    """A complete answer cannot be established from this upstream walk."""


def window(start, end):
    a, b = period(start, end)
    if b - a > timedelta(days=93):
        raise ValueError("Activity windows must be at most 93 days")
    return a, b


def check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise CoverageError("Activity walk exceeded its time budget; request a shorter period")


def safe_post(post, group_id):
    if post.get("groupId", post.get("group_id")) != group_id:
        raise PermissionError("Post community mismatch")
    metadata = post.get("metadata") or {}
    created = moment(post.get("createdAt", post.get("created_at")))
    return dict(id=post.get("id"), slug=post.get("name"),
        author_id=post.get("userId", post.get("user_id")),
        created_at=created.isoformat() if created else None,
        title=str(metadata.get("title") or ""),
        text=str(metadata.get("content") or ""),
        comments=number(metadata.get("comments")), likes=number(metadata.get("upvotes")),
        last_comment_at=moment(metadata.get("lastComment")).isoformat() if moment(metadata.get("lastComment")) else None)


def walk_posts(client, slug, group_id, deadline):
    """Walk to an empty page. Never treat repeated pages as end-of-history."""
    seen = set()
    page = 1
    while True:
        check_deadline(deadline)
        path = f"/{quote(slug, safe='')}.json?group={quote(slug, safe='')}&s=newest&p={page}"
        data = client.http.get_next(path, slug)
        check_deadline(deadline)
        props = data.get("pageProps")
        if not isinstance(props, dict) or not isinstance(props.get("postTrees"), list):
            raise CoverageError("Post feed shape unavailable")
        trees = props["postTrees"]
        if not trees:
            return
        fresh = 0
        for tree in trees:
            post = safe_post(tree.get("post") or {}, group_id)
            if not post["id"]:
                raise CoverageError("Post identity missing")
            if post["id"] in seen:
                continue
            seen.add(post["id"])
            fresh += 1
            yield post
        if not fresh:
            raise CoverageError("Post feed repeated without reaching an empty page")
        page += 1
        time.sleep(0.8)


def comments(client, post_id, group_id, deadline, expected_count=None):
    cursor = 0
    found = {}
    while True:
        check_deadline(deadline)
        data = client.http.get_api2(
            f"/posts/{quote(post_id, safe='')}/comments?group-id={quote(group_id, safe='')}"
            f"&limit=25&created-gt={cursor}")
        check_deadline(deadline)
        tree = data.get("post_tree")
        if not isinstance(tree, dict) or not isinstance(tree.get("children"), list):
            raise CoverageError("Comment page shape unavailable")
        for row in normalize.comments(data):
            found[row["skool_id"]] = row
        pinned = data.get("pinned_post_tree")
        if pinned:
            children = [pinned] if pinned.get("post") else pinned.get("children", [])
            for row in normalize.comments({"post_tree":{"children":children}}):
                found[row["skool_id"]] = row
        if not tree["children"]:
            if expected_count is not None and len(found) != expected_count:
                raise CoverageError("Comment count does not match the completed walk")
            return list(found.values())
        last = data.get("last")
        if type(last) is not int or last <= cursor:
            raise CoverageError("Comment cursor stopped advancing")
        cursor = last
        time.sleep(0.8)


def period_posts(client, slug, group_id, start, end, query=None):
    a, b = window(start, end)
    deadline = time.monotonic() + 120
    rows = []
    missing_dates = 0
    examined = 0
    for post in walk_posts(client, slug, group_id, deadline):
        examined += 1
        when = moment(post["created_at"])
        if when is None:
            missing_dates += 1
            continue
        if a <= when < b:
            if query is None or query.casefold() in (post["title"]+" "+post["text"]).casefold():
                rows.append(post)
    return response(rows, start=start, end=end, unknown={"post_dates":missing_dates},
        coverage={"post_pages_complete":True, "posts_examined":examined,
                  "period_membership_complete":missing_dates == 0},
        definition="All retrieved posts created in the requested period. Undated posts cannot be assigned. No fixed post-count cap.")


def daily_activity(client, group_id):
    raw = client.admin_metrics(group_id)
    daily = raw.get("daily_activities")
    if not isinstance(daily, dict):
        return {"start":None,"end":None,"counts":None,"individual_attribution":False}
    counts = daily.get("counts")
    if isinstance(counts, str):
        try:
            counts = json.loads(counts)
        except ValueError:
            counts = None
    # Preserve the observed aggregate shape without adding per-member attribution.
    if isinstance(counts, list):
        counts = [number(value) for value in counts]
    else:
        counts = None
    series = {}
    for name in ("active_members", "total_members"):
        values = raw.get(name)
        series[name] = ([{"time":r.get("time"), "value":number(r.get("value"))}
            for r in values if isinstance(r, dict)] if isinstance(values, list) else None)
    return {"start":daily.get("start_date"),"end":daily.get("end_date"),
            "counts":counts,"individual_attribution":False,
            "latest_active_members":number(raw.get("latest_active_members")), **series}


def evidence(client, slug, group_id, start, end, split=None):
    a, b = window(start,end)
    boundary = moment(split) if split else a
    users, coverage = members(client,slug)
    deadline = time.monotonic()+120
    posts_by = [defaultdict(int),defaultdict(int)]
    comments_by = [defaultdict(int),defaultdict(int)]
    unknown = {"post_dates":0,"comment_dates":0,"post_authors":0,"comment_authors":0}
    post_total = comment_total = 0
    for post in walk_posts(client,slug,group_id,deadline):
        post_total += 1
        when = moment(post["created_at"])
        if when is None:
            unknown["post_dates"] += 1
        elif a <= when < b:
            if post["author_id"]:
                posts_by[int(when>=boundary)][post["author_id"]] += 1
            else:
                unknown["post_authors"] += 1
        # Scan comments even on old posts: a new comment can revive an old thread.
        last_comment = moment(post["last_comment_at"])
        if post["comments"] == 0 or (last_comment is not None and last_comment < a):
            rows = []
        else:
            rows = comments(client,post["id"],group_id,deadline,expected_count=post["comments"])
        comment_total += len(rows)
        for row in rows:
            when = moment(row["created_at"].isoformat()) if row["created_at"] else None
            if when is None:
                unknown["comment_dates"] += 1
            elif a <= when < b:
                if row["user_id"]:
                    comments_by[int(when>=boundary)][row["user_id"]] += 1
                else:
                    unknown["comment_authors"] += 1
    aggregate = daily_activity(client,group_id)
    result=[]
    for user in users:
        r=member_row(user)
        joined=moment(r["joined_at"])
        member=user.get("member")or{}
        last=moment(member.get("lastOffline"))
        # Account-wide lastOffline is a separate signal with broader scope.
        account_last=moment((user.get("metadata")or{}).get("lastOffline"))
        r.update(joined_in_period=None if joined is None else a<=joined<b,
            never_posted=None if r["lifetime_posts"] is None else r["lifetime_posts"]==0,
            previous_posts=posts_by[0][r["id"]], observed_posts=posts_by[1][r["id"]],
            previous_comments=comments_by[0][r["id"]], observed_comments=comments_by[1][r["id"]],
            last_seen=last.isoformat() if last else None,
            account_last_seen=account_last.isoformat() if account_last else None)
        previous_seen=last is not None and a<=last<boundary
        current_seen=last is not None and last>=boundary
        previous_active=bool(r["previous_posts"] or r["previous_comments"] or previous_seen)
        current_active=bool(r["observed_posts"] or r["observed_comments"] or current_seen)
        r["previous_activity_observed"]=previous_active
        r["current_activity_observed"]=current_active
        # A missing last-seen field cannot establish absence of visits.
        r["quiet_candidate"]=previous_active and not current_active and last is not None
        result.append(r)
    unknown.update(joined_at=sum(r["joined_at"] is None for r in result),
        lifetime_posts=sum(r["lifetime_posts"] is None for r in result),
        last_seen=sum(r["last_seen"] is None for r in result),
        admin_daily_activity=int(aggregate["counts"] is None))
    complete_dates=not any(unknown[k] for k in ("post_dates","comment_dates","post_authors","comment_authors"))
    for r in result:
        if not complete_dates:
            r["quiet_candidate"]=None
    return response({"members":result,"admin_daily_activities":aggregate},"estimated",start,end,
        unknown=unknown,coverage={**coverage,"post_pages_complete":True,"comment_pages_complete":True,
            "posts_examined":post_total,"comments_examined":comment_total,
            "dated_activity_complete":complete_dates},
        definition="All post/comment pages scanned. Community and account last-seen are separate signals. Admin daily activity is community-wide and cannot establish individual visits. Quiet candidates are evidence-based, not proof of historical absence.")


def compare(client,slug,group_id,start,end,previous_start):
    window(previous_start,start)
    window(start,end)
    result=evidence(client,slug,group_id,previous_start,end,split=start)
    result["data"]["members"]=[r for r in result["data"]["members"] if r["quiet_candidate"] is True]
    result["coverage"]["unknown_candidates_omitted"]=not result["coverage"]["dated_activity_complete"]
    return result
