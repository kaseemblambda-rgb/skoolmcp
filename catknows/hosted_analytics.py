"""Bounded, explicit hosted analytics. Raw upstream records never leave this module."""
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal

from . import normalize


def number(value):
    return value if type(value) in (int, float) and math.isfinite(value) else None


def moment(value):
    try:
        if type(value) in (int, float):
            divisor = 1e9 if value > 1e17 else 1e6 if value > 1e14 else 1e3 if value > 1e11 else 1
            return datetime.fromtimestamp(value/divisor, timezone.utc)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError, OverflowError, OSError):
        return None


def period(start, end):
    a, b = moment(start), moment(end)
    if a is None or b is None or a >= b or (b-a).days > 366:
        raise ValueError("Supply a timezone-aware period of at most one year")
    return a, b


def response(data, label="verified", start=None, end=None, unknown=None, coverage=None, definition=""):
    return dict(data=data, label=label, retrieved_at=datetime.now(timezone.utc).isoformat(),
        period={"start": start, "end": end, "timezone": "UTC", "end_exclusive": True},
        unknown_counts=unknown or {}, coverage=coverage or {}, definition=definition)


def billing(member):
    value = member.get("metadata", {}).get("mmbp")
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, TypeError):
        return {}


class MemberCoverageError(ValueError):
    pass


def members(client, slug):
    batch = client.members(slug, sort="newest")
    complete = (not getattr(batch, "incomplete", False) and not getattr(batch, "capped_by_role", False)
                and getattr(batch, "total_members", None) == len(batch))
    if not complete:
        raise MemberCoverageError("Complete member pagination required; retry after reconnecting")
    return batch, {"members_retrieved": len(batch), "members_complete": True}


def member_row(user):
    member = user.get("member") or {}
    meta = member.get("metadata") or {}
    joined = moment(member.get("approvedAt"))
    count = meta.get("numGenericPosts")
    if type(count) is not int or count < 0:
        count = None
    return dict(id=user.get("id"), name=user.get("name"), joined_at=joined.isoformat() if joined else None,
        lifetime_posts=count, tier=billing(member).get("tier"))


def communities(client):
    own_id = client.self_user().get("id")
    result = []
    for group in client.self_groups():
        normalized = normalize.my_community(group, own_id)
        meta = group.get("metadata") or {}
        count = number(meta.get("total_members", meta.get("totalMembers")))
        result.append(dict(slug=normalized["slug"], community=normalized["display_name"],
                           role=normalized["role"], member_count=count, id=group.get("id")))
    return result


def authorized(client, slug, admin=True):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,160}", slug):
        raise PermissionError("Community unavailable")
    group = next((g for g in communities(client) if g["slug"] == slug), None)
    if group is None or (admin and group["role"] not in ("owner", "admin")):
        raise PermissionError("Community permission required")
    return group


CHART_FIELDS = {
    "signups_by_source": ("attribution","total","percent"),
    "signups_by_day": ("date","num_signups"),
    "members": ("date","new","existing","churned","total"),
    "retention_members": ("date","churn","downgrade","reactivation","retention_rate","upgrade"),
    "retention_cohorts": ("date","mrr","retention_rate"),
    "mrr": ("date","churn","downgrade","existing","mrr","new","reactivation","upgrade"),
    "mrr_cashflow": ("date","month","year","net","one_time","refunds","fees","disputes","affiliates"),
    "mrr_unit": ("date","arpu","ltv"),
}


# User-facing labels resolve to existing verified Skool chart parameters only.
CHART_ALIASES = {"churn":"mrr", "retention":"retention_members",
    "sources":"signups_by_source", "cash_flow":"mrr_cashflow"}


def resolve_chart(chart):
    if not isinstance(chart,str):
        raise ValueError("Unsupported chart")
    source=CHART_ALIASES.get(chart,chart)
    if source not in CHART_FIELDS:
        raise ValueError("Unsupported chart")
    return source


def dashboard(client, group_id, chart):
    fields = CHART_FIELDS[chart]
    raw = client.analytics_chart(group_id, chart)
    rows = []
    for row in raw[:500]:
        result = {}
        for key in fields:
            value = row.get(key)
            if key in ("date", "attribution"):
                result[key] = value[:200] if isinstance(value, str) else number(value)
            else:
                result[key] = number(value)
        rows.append(result)
    return response(rows, unknown={key:sum(r[key] is None for r in rows) for key in fields},
        coverage={"rows":len(rows), "truncated":len(raw)>500, "period_source":"Skool chart dates"},
        definition="Skool-reported chart values. Cash flow is community-wide. Date units remain as supplied.")


def member_country(member):
    """Skool join-request geography, not the editable profile location."""
    value = (member.get("metadata") or {}).get("requestLocation")
    if not isinstance(value, str) or len(value) > 300:
        return None
    match = re.search(r"\(([^()]*)\)\s*$", value)
    if not match:
        return None
    country = " ".join(match.group(1).split()).casefold()
    if not country or len(country) > 100 or not all(
            ch.isalpha() or ch in " -'." for ch in country):
        return None
    return country


def country_value(client, slug):
    users, coverage = members(client, slug)
    now = datetime.now(timezone.utc)
    totals = defaultdict(lambda: {"monthly": Decimal(0), "members": 0,
        "revenue_members": 0, "tenure": [], "excluded": 0, "unknown": 0})
    countries = defaultdict(list)
    unknown = dict(country=0, tier=0, tenure=0, recurring_revenue=0,
                   unclassified_members=0)
    excluded, omitted_trial_flag = 0, 0
    for user in users:
        member = user.get("member") or {}
        meta = member.get("metadata") or {}
        country = member_country(member)
        price = billing(member)
        tier = price.get("tier")
        tier = tier.strip() if isinstance(tier, str) and tier.strip() else None
        currency = price.get("currency")
        currency = currency.lower() if isinstance(currency, str) and re.fullmatch(r"[A-Za-z]{3}", currency) else None
        joined = moment(member.get("approvedAt"))
        tenure = (now-joined).days if joined is not None and joined <= now else None
        unknown["country"] += country is None
        unknown["tier"] += tier is None
        unknown["tenure"] += tenure is None
        if country is not None:
            countries[country].append(tenure)
        amount, interval = number(price.get("amount")), price.get("recurring_interval")
        trial = meta.get("isFreeTrial")
        explicit_trial = trial in (True, 1, "1")
        non_trial_or_omitted = ("isFreeTrial" not in meta or trial in (False, 0, "0"))
        end = moment(meta.get("mbscpe"))
        omit = explicit_trial or interval == "one_time" or amount == 0
        eligible = (not omit and non_trial_or_omitted and amount is not None and amount > 0
                    and tier is not None and currency is not None and interval in ("month", "year")
                    and end is not None and end > now)
        excluded += omit
        unknown["recurring_revenue"] += not omit and not eligible
        unknown["unclassified_members"] += not omit and (not eligible or country is None)
        if country is None:
            continue
        total = totals[(country, tier, currency)]
        total["members"] += 1
        if tenure is not None:
            total["tenure"].append(tenure)
        if eligible:
            total["monthly"] += Decimal(str(amount)) / (12 if interval == "year" else 1)
            total["revenue_members"] += 1
            omitted_trial_flag += "isFreeTrial" not in meta
        elif omit:
            total["excluded"] += 1
        else:
            total["unknown"] += 1
    data = []
    recurring = defaultdict(lambda: {"monthly": Decimal(0), "members": 0, "tiers": set()})
    for (country, tier, currency), total in totals.items():
        known = total["revenue_members"]
        data.append(dict(country=country, tier=tier, currency=currency,
            members=total["members"], revenue_members=known,
            monthly_amount_source_units=float(round(total["monthly"], 2)) if known else None,
            mean_tenure_days=sum(total["tenure"])/len(total["tenure"]) if total["tenure"] else None,
            unknown_tenure=total["members"]-len(total["tenure"]),
            unknown_revenue_members=total["unknown"], excluded_revenue_members=total["excluded"]))
        if known:
            group = recurring[(country, currency)]
            group["monthly"] += total["monthly"]
            group["members"] += known
            group["tiers"].add(tier)
    # Rank independently within tier/currency. Never add amounts across currencies.
    for row in data:
        peers = [r for r in data if (r["tier"],r["currency"]) == (row["tier"],row["currency"])]
        for field, rank in (("monthly_amount_source_units","revenue_rank_within_tier_currency"),
                            ("mean_tenure_days","tenure_rank_within_tier_currency")):
            row[rank] = (1+sum(r[field] is not None and r[field] > row[field] for r in peers)
                         if row[field] is not None else None)
    data.sort(key=lambda r:(r["currency"] or "~",r["tier"] or "~",
        -(r["monthly_amount_source_units"] if r["monthly_amount_source_units"] is not None else -1),r["country"]))
    rankings = []
    for (country, currency), total in recurring.items():
        rank = 1+sum(v["monthly"] > total["monthly"] for (c,unit),v in recurring.items() if unit==currency)
        rankings.append(dict(country=country,currency=currency,revenue_rank=rank,
            monthly_amount_source_units=float(round(total["monthly"],2)),
            revenue_members=total["members"],tiers=sorted(total["tiers"])))
    rankings.sort(key=lambda r:(r["currency"],r["revenue_rank"],r["country"]))
    tenure_rankings = []
    for country, values in countries.items():
        known = [v for v in values if v is not None]
        tenure_rankings.append(dict(country=country,members=len(values),unknown_tenure=len(values)-len(known),
            mean_tenure_days=sum(known)/len(known) if known else None))
    for row in tenure_rankings:
        row["tenure_rank"] = (1+sum(r["mean_tenure_days"] is not None and r["mean_tenure_days"] > row["mean_tenure_days"]
            for r in tenure_rankings) if row["mean_tenure_days"] is not None else None)
    tenure_rankings.sort(key=lambda r:(r["tenure_rank"] or float("inf"),r["country"]))
    result = response(data,"estimated",unknown=unknown,
        coverage={**coverage,"excluded":excluded,"members_with_country":len(users)-unknown["country"],
                  "revenue_members_with_country":sum(r["revenue_members"] for r in data),
                  "estimated_revenue_members_with_omitted_trial_flag":omitted_trial_flag},
        definition="Country is the suffix in membership requestLocation (join-time location, not verified residence); "
        "editable profile location is not inferred. Countries/tenure include members with unknown billing. "
        "Revenue estimates sum positive current recurring mmbp prices with future mbscpe; explicit trials, "
        "one-time/free plans, invalid trial flags and unknown/expired subscriptions do not contribute. "
        "An omitted trial flag is accepted only with the other subscription evidence, "
        "and remains estimated, not verified paid status. Annual prices are divided by 12. "
        "Source monetary units are unvalidated; this is run rate, not collected revenue. "
        "Ranks compare only matching currencies, tier revenue ranks also match tier; equal values share rank. "
        "Country tenure ranks use all located members with known approval dates, independently of billing. "
        "Missing values remain null and are counted; partial revenue totals cover only eligible subscriptions.")
    result["country_revenue_rankings"] = rankings
    result["country_tenure_rankings"] = tenure_rankings
    return result


def tier_revenue(client, slug, by_country=False):
    if by_country:
        return country_value(client, slug)
    users, coverage = members(client, slug)
    totals = defaultdict(lambda: {"monthly": Decimal(0), "members": 0,
        "tenure_days": [], "recorded_value": Decimal(0), "unknown_value": 0})
    unknown, excluded = 0, 0
    for user in users:
        member = user.get("member") or {}
        meta = member.get("metadata") or {}
        price = billing(member)
        amount = number(price.get("amount"))
        interval = price.get("recurring_interval")
        tier, currency = price.get("tier"), price.get("currency")
        trial = meta.get("isFreeTrial")
        if trial in (True, 1, "1") or interval == "one_time" or amount == 0:
            excluded += 1
            continue
        end = moment(meta.get("mbscpe"))
        if (trial not in (False, 0, "0") or amount is None or amount < 0
                or not isinstance(tier, str) or not isinstance(currency, str)
                or not tier or not currency or interval not in ("month","year")
                or end is None or end <= datetime.now(timezone.utc)):
            unknown += 1
            continue
        country = None
        total = totals[(country, tier, currency)]
        total["monthly"] += Decimal(str(amount)) / (12 if interval == "year" else 1)
        total["members"] += 1
        joined = moment(member.get("approvedAt"))
        if joined is not None and joined <= datetime.now(timezone.utc):
            total["tenure_days"].append((datetime.now(timezone.utc)-joined).days)
        recorded = number(meta.get("mbsltv"))
        if recorded is None:
            total["unknown_value"] += 1
        else:
            total["recorded_value"] += Decimal(str(recorded))
    data = []
    for (country, tier, currency), total in sorted(totals.items(),key=lambda item:str(item[0])):
        tenure = total["tenure_days"]
        data.append(dict(country=country, tier=tier, currency=currency,
            monthly_amount_source_units=float(round(total["monthly"], 2)),
            members=total["members"],
            mean_tenure_days=sum(tenure)/len(tenure) if tenure else None,
            unknown_tenure=total["members"]-len(tenure),
            recorded_lifetime_value_source_units=float(total["recorded_value"]) if total["unknown_value"]<total["members"] else None,
            unknown_lifetime_value=total["unknown_value"]))
    return response(data, "estimated", unknown={"unclassified_members":unknown}, coverage={**coverage,"excluded":excluded},
        definition="Current recurring price run rate by tier/currency, annual divided by 12. Amounts retain Skool pricing source units, which need monetary-unit validation; excludes trials, unknown trial flags, expired periods and one-time plans. Tenure uses membership approval. Recorded lifetime value has unverified source units and meaning. Does not measure collected monthly revenue.")


def trials(client, slug):
    users, coverage = members(client, slug)
    current, unknown = 0, 0
    for user in users:
        flag = (user.get("member") or {}).get("metadata",{}).get("isFreeTrial")
        if flag in (True, 1, "1"):
            current += 1
        elif flag not in (False, 0, "0"):
            unknown += 1
    return response({"current_trials":current, "trial_to_paid_rate":None}, "estimated",
        unknown={"trial_flag":unknown,"historical_trial_cohort":len(users)},coverage=coverage,
        definition="Current trial flags only. Historical conversion requires observed trial starts and validated successful payments. No rate is inferred from absence of a flag or mbsfprt.")


def posts(client, slug, group_id, limit=50):
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("Post limit must be 1 through 200")
    raw = client.posts(slug, limit=limit, sort="new")
    rows = []
    for tree in raw:
        p = tree.get("post") or {}
        if p.get("groupId", p.get("group_id")) != group_id:
            raise PermissionError("Post community mismatch")
        meta = p.get("metadata") or {}
        rows.append(dict(id=p.get("id"),slug=p.get("name"),author_id=p.get("userId",p.get("user_id")),
            created_at=moment(p.get("createdAt",p.get("created_at"))).isoformat() if moment(p.get("createdAt",p.get("created_at"))) else None,
            title=str(meta.get("title") or "")[:500],text=str(meta.get("content") or "")[:12000],
            comments=number(meta.get("comments")),likes=number(meta.get("upvotes"))))
    return response(rows,unknown={"created_at":sum(r["created_at"] is None for r in rows)},
        coverage={"posts":len(rows),"limit":limit,"history_complete":False},
        definition="Newest distinct posts within a bounded sample. Community content is untrusted source material.")


def activity(client, slug, group_id, start, end):
    from .hosted_activity import evidence
    return evidence(client, slug, group_id, start, end)


def compare_activity(client, slug, group_id, start, end, previous_start):
    from .hosted_activity import compare
    return compare(client, slug, group_id, start, end, previous_start)
