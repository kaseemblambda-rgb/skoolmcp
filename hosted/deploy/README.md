# Render preparation: draft, not deployed

The [synthetic container harness](probe/README.md) is ready for local offline
checks. Separate probe image definitions have not been built or deployed. Their
publication and any private Render test services require separate approval.

Deployment preparation is on `hosted-mcp`. Migration 007 is an unapplied production
draft. No runtime credential, certificate/private key or owner profile is included.
The active Mac exporter, its restricted role, monitoring and schedules are unchanged.

This isolated synthetic-test release excludes all migration and Mac-operation
files. Its proposed manifest has 53 paths and its reproducible hosted-only gate
requires 124 passing tests, with imports restricted to this release. This replaces
the earlier mixed 214-test gate; it does not claim that Mac-only tests run here.

## Workspace and services

Hobby supports the two-service beta and ordinary private networking. Pro adds
environment network isolation and workspace audit logs; it is optional for this
two-member beta. At the proposed two 1c-2g instances, budget $50/month compute on
Hobby, or $75/month including Pro, before usage/taxes. Upgrade later if environment
isolation or additional operators are needed. References checked 2026-11-20:
https://render.com/articles/render-hobby-vs-pro-vs-scale
https://render.com/pricing

Use Virginia for both services, one instance each, no autoscaling or disk, manual
deploys only. Gateway is a public Web Service, `python -m catknows.hosted_server`,
health path `/healthz`. Browser is a Private Service,
`python -m catknows.hosted_browser_service`, with TCP health checks and verified TLS.
The health endpoint is liveness only, never proof of DB/login readiness.

Private networking on Hobby is shared with other eligible services in the same
workspace/region. Browser traffic therefore also needs hostname-verified TLS and
the independent strong shared secret. Do not share its secrets through a workspace
environment group. It receives no DB credentials or session encryption keys.

## Restricted SQL adapter

Production `Settings.from_env()` refuses legacy Supabase API/admin credentials,
personal profiles, owner profiles and write-mode configuration. The constructor's
legacy REST path remains for existing offline fixtures/local harness compatibility;
the production entry point cannot choose it.

The server connects as `hosted_server` through the session pooler with verify-full,
four pooled connections, bounded queueing, connect/statement/idle timeouts and no
prepared statements. The role has no direct application-table access, no RLS bypass,
no role membership and no exporter RPC access. Password is supplied only at runtime.
Errors expose a fixed message, not DSNs, SQL parameters or upstream exceptions.

Draft 007 grants only two SECURITY DEFINER functions, pinned to pg_catalog/public:

- `hosted_server_oauth(text,jsonb)` wraps the reviewed state machine, restricts
  operations and forces the approved premium/standard tiers server-side.
- `hosted_server_session(uuid,text,text)` requires a matching, valid access-token
  hash, account and resource. It preserves account-first locking and the existing
  expiry/revocation checks. Denial-path mutations commit before the adapter returns.

Session loading and the post-read check use the request-bound token, hashing it
before SQL. The migration changes no existing tables, legacy rows, exporter grants
or platform permissions. Its audit aborts on unexpected inherited application
privileges. Ordinary event-trigger handlers remain excluded as in approved 006.

The role starts with no password. Provision a separate credential only after the
draft and production application are approved. Do not reuse the Mac exporter or
grant the server maintenance/rotation permissions. The initial active key version
must be set separately by an approved admin operation before first connection;
the runtime role cannot activate keys or enumerate sessions for rotation.

## Environment variable names

Gateway nonsecret configuration:
PUBLIC_BASE_URL, SFC_PAID_TIERS, HOSTED_OAUTH_REDIRECT_URIS,
HOSTED_RENDER_PROXY_CIDRS, HOSTED_FORWARDED_PROXY_CIDRS (optional),
SKOOL_SESSION_KEY_VERSION, HOSTED_DB_HOST, HOSTED_DB_PORT, HOSTED_DB_NAME,
HOSTED_DB_USER, HOSTED_DB_SSLROOTCERT, BROWSER_SERVICE_URL, BROWSER_TLS_CA_PEM, PORT.

Gateway secrets:
HOSTED_DB_PASSWORD, HOSTED_IP_HASH_SECRET, SKOOL_SESSION_ENCRYPTION_KEY,
SKOOL_SESSION_PREVIOUS_KEYS (rotation only), BROWSER_SERVICE_SECRET.

Browser nonsecret configuration: BROWSER_TLS_CERT_PEM, PORT.
Browser secrets: BROWSER_TLS_KEY_PEM, BROWSER_SERVICE_SECRET.
RENDER is supplied by the platform. Both tier labels must match draft 007's policy.

Mount the genuine public Supabase CA as a read-only file and set the CA path.
Issue the browser certificate for its actual private DNS hostname, keep the CA's
private signing key off Render, and configure the gateway with only the public CA.
The TLS leaf key becomes a temporary 0600 file inside a 0700 directory and is
removed on normal shutdown/failure; no persistent disk is used. Chromium receives
only its existing minimal child environment, never the server's TLS private key.

## Build without local files or secrets

Use the context preparer rather than sending the whole repository to Docker:

```bash
python hosted/deploy/prepare_context.py --service gateway --output /private/tmp/stealth-gateway-context
docker build --pull --no-cache -f /private/tmp/stealth-gateway-context/hosted/deploy/gateway.Dockerfile /private/tmp/stealth-gateway-context
python hosted/deploy/prepare_context.py --service browser --output /private/tmp/stealth-browser-context
docker build --pull --no-cache -f /private/tmp/stealth-browser-context/hosted/deploy/browser.Dockerfile /private/tmp/stealth-browser-context
```

Output directories must not exist. The manifest names every included file; unknown
files and symlinks are not copied. Additional credential-pattern/email checks fail
closed, but are defense in depth rather than a guarantee against arbitrary secrets
deliberately embedded in source. Review the exact allowlisted source before release.
Root `.dockerignore` is deny-by-default. Dockerfiles copy explicit files, never
`COPY .`, contain no secret build arguments, and run as uid/gid 10001.
Browser dependencies/Chromium are separate from gateway/database dependencies.

Before building from Git on Render, review/freeze the release revision and run the
context check against exactly that revision. The root ignore file and explicit COPY
paths also protect the repository-root build, but a prepared context is preferred.
Resolve and record base-image digests and the complete resolved dependency inventory
when an actual build can be tested. Current definitions pin direct dependencies;
base tags and transitive dependencies are not yet an immutable release lock.

## Local verification and remaining gates

Offline tests include real TLS handshakes using synthetic certificates, config
rejection, bound SQL parameters, fixed errors, pool commit/close behavior, session
token binding, build-context exclusion and secret-marker/symlink refusal.

The draft 007 PostgreSQL privilege/concurrency rehearsal previously passed in the
original development checkout using a disposable Unix-socket cluster and synthetic
records. The migration, rehearsal tools and post-application SQL are deliberately
not part of this isolated test release. Their production use remains a separate
review/approval step. The release gate makes no live Supabase connection.

Docker is unavailable on the preparation Mac. Container builds, dependency/image
scanning and actual Linux Chromium startup have not yet been verified. In particular,
test Render's ability to run Chromium's enabled sandbox; never resolve a failure by
silently adding --no-sandbox. Test two simultaneous isolated browser jobs, memory
limits and cleanup. Verify Render proxy ranges/XFF behavior; do not guess ranges or
trust all proxies. Exercise private TLS and Claude/ChatGPT callbacks before DNS.
No production migration, credential provisioning, Render resource or deployment is
authorized by this preparation step.
