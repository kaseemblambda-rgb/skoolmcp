# Stealth MCP: offline Render production review

Status: OFFLINE REVIEW ONLY. No resources, API keys, production credentials or production TLS material,
commits, pushes or deploys created. Tests use synthetic public fixtures. The source change is not on GitHub yet.
production-review.json is an internal review inventory, NOT a Render API payload
or Blueprint, and intentionally says deploy_ready=false.

## Current user-confirmed prerequisites

- Supabase migrations 001 through frozen 007 applied and verified manually.
- hosted_server password provisioned; ACTIVE credential remains in Mac Keychain.
- Three independent runtime secrets prepared and bound locally.
- Initial sfc-v1 registered: one expected version, zero other versions; activation
  denied to hosted_server/exporter/anon/authenticated. No service-role key needed.
- Owner's hourly entitlement export/watchdog/heartbeat remain on the Mac.
- Prior synthetic browser probe on 5a606bc passed 20 checks on Render, including
  sandbox_verified=1 and cleanup_zombie=0. User deleted that temporary service.
  This is previous probe evidence, NOT a build/test of the new production image.

## Image parity and build boundary

browser.Dockerfile now has exactly the v0.19.0 Tini installer from the passing
browser-probe.Dockerfile, including SHA-256
93dcc18adc78c65a028a84799ecf8ad40c936fdfc5f2a57b1acda5a8117fa82c.
The installer rejects oversized or mismatched bytes before making Tini executable.
USER stays 10001:10001; ENTRYPOINT is /usr/local/bin/tini --; CMD remains
python -m catknows.hosted_browser_service. No Docker Command override is allowed.

No launch flags, Chromium options, browser-policy code, kernel sandbox checks or
fail-closed zombie cleanup were changed. chromium_sandbox=True stays in place.
Tini parity is verified offline; production image build and live Linux sandbox/
cleanup verification remain a later gate. No Docker/container was launched here.

The existing deny-by-default .dockerignore, explicit COPY statements and prepared
context allowlist stay intact. No ARG consumes a runtime secret. Operator helpers,
Keychain records, .env files, profiles, certificates and private keys are outside
the image context. Docker recipes do not consume the runtime secrets; this does
not claim Render's infrastructure cannot access environment configuration. Never
supply build secrets as ARG, put keys in a Dockerfile, or copy a private TLS bundle.
Base tags/transitive dependencies still need an inventory/digest review at the
actual image-build gate. No new digest is invented by this offline change.

## Two service settings (no resources created)

Workspace: Stealth Founders Club, existing Hobby workspace. Region: Virginia for
BOTH services. Git repo: kaseemblambda-rgb/skoolmcp, branch hosted-mcp. Later pin a
separately approved published production commit, not a moving unreviewed HEAD.

| Setting | Gateway | Browser |
|---|---|---|
| Name | stealth-mcp | stealth-mcp-browser |
| Type | Web Service | Private Service |
| Runtime | Docker | Docker |
| Compute | 1c-2g, one instance | 1c-2g, one instance |
| Dockerfile | hosted/deploy/gateway.Dockerfile | hosted/deploy/browser.Dockerfile |
| Context/root | . / blank root directory | . / blank root directory |
| Docker Command | blank; use image CMD | blank; preserve Tini ENTRYPOINT and image CMD |
| Auto-Deploy | Off | Off |
| Health check | /healthz | TCP only |
| PORT | 10000 | 8001 |
| WEB_CONCURRENCY | 1 | 1 |
| Disk/autoscaling/previews | none/off/off | none/off/off |
| Environment groups | none | none |

Current quoted compute is $25/service/month, $50 total before usage/taxes on Hobby;
Pro workspace is not required for this two-member beta. Recheck at creation.
Private networking is shared within the workspace/region on Hobby, so application
TLS AND the independent shared auth secret are both required. Pro environment
isolation would be an additional boundary; it is not assumed here.

The gateway's /healthz is liveness only. A 200 does not prove DB authorization,
paying-member access, browser TLS, OAuth callbacks or sandbox readiness.

## Complete environment map

production-review.json is the authoritative inventory of required/optional names,
secret classification, known nonsecret values and unresolved value sources. No
real secret values, project reference, service IDs, private hostname, CA or keys
are embedded. Set values directly on the individual services, never a shared group.

Gateway secret writes, only:
- HOSTED_DB_PASSWORD, from ACTIVE hosted_server.<project> Keychain entry.
- SKOOL_SESSION_ENCRYPTION_KEY, BROWSER_SERVICE_SECRET, HOSTED_IP_HASH_SECRET,
  from the already-bound runtime Keychain entries.

Browser secret writes, only:
- BROWSER_SERVICE_SECRET, identical to gateway's internal-auth secret.
- BROWSER_TLS_KEY_PEM, a separately issued leaf server key, never the CA key.

Gateway also requires SKOOL_SESSION_KEY_VERSION=sfc-v1 (public configuration).
This uploader writes ONLY secrets; the version label and other public settings
are separately configured with Save only. SKOOL_SESSION_PREVIOUS_KEYS stays unset
for the initial beta. No Supabase API/service-role/admin key goes on either server.
No DB credentials, encryption key, IP hash secret or owner profile goes on browser.
RENDER is platform supplied, not an operator value to override.

Mount the genuine Supabase project CA as supabase-project-ca.crt and point
HOSTED_DB_SSLROOTCERT to /etc/secrets/supabase-project-ca.crt on the gateway. The
certificate is public but must be authentic and correct. It is not copied into
an image. Secret-file upload can trigger deployment; it needs its own explicit
authorization/timing rather than being assumed covered by Save only.

## Private TLS gate (not implemented/executed issuance)

The browser's actual private hostname is allocated after service creation. Copy
it from Render's Connect/Internal address; do not guess it from the service name.
Set BROWSER_SERVICE_URL=https://<that hostname>:8001 on the gateway. The browser
leaf certificate SAN must contain EXACTLY that hostname, no wildcard or IP.

After separate approval, issue a private CA and a distinct leaf certificate/key.
The CA signing key stays protected on the Mac, never Render, this repo or chat.
Publish only the CA certificate to BROWSER_TLS_CA_PEM (gateway) and the leaf cert
to BROWSER_TLS_CERT_PEM (browser). Leaf private key goes only to browser.

A future reviewed issuer must save one protected Keychain item, not a repo file:
service Stealth Hosted Browser TLS, account <project>:browser-tls; JSON fields
format_version=1, project, hostname, ca_pem, certificate_pem, key_pem. The record
contains one unencrypted PKCS8 LEAF private-key PEM block only, is at most 8192
bytes, and must not be printed. Concatenated keys or trailing material are refused.
The new uploader READS this format but does not generate, save or rotate it.
Use a separately approved Keychain-backed issuer; no such production bundle was
created in this task. This remains a real prerequisite before secret transfer.

Validation checks: strong EC/RSA keys, SHA-256-or-better signatures, root signature,
issuer signature, CA/key usage, non-CA leaf, server-auth EKU, exact SAN, matching
leaf key, distinct CA/leaf keys and at least 24 hours of remaining validity. No
network is needed to validate this local bundle. Runtime TLS retains hostname
checks, CERT_REQUIRED, minimum TLS 1.2 and temporary 0600 key-file cleanup.

## Proxy and connector settings: intentionally unresolved

HOSTED_RENDER_PROXY_CIDRS must be a JSON array of independently verified Render
INGRESS peer networks. Render's public guidance says requests traverse proxies,
but this review found no authoritative CIDR list to safely substitute. Obtain
confirmation from Render and verify the actual peer/XFF chain in a later controlled
check. Outbound ranges, all RFC1918 ranges and 0.0.0.0/0 are NOT substitutes.
HOSTED_FORWARDED_PROXY_CIDRS defaults to [] until any intermediate hops are verified.
Existing startup remains fail-closed if required proxy trust is absent.

HOSTED_OAUTH_REDIRECT_URIS must contain exact HTTPS callbacks. Claude's published
callback is https://claude.ai/api/mcp/auth_callback. OpenAI currently documents
callback-ID-specific redirects and a conditional stable redirect; copy the exact
production URI from the connector management page. Do not guess an ID or allow a
host/path wildcard. The current server supports public-client DCR with PKCE and
no client secret; verify each connector uses that supported path. No OAuth code
or authorization rules changed here.

For initial testing before DNS, use the gateway's assigned HTTPS onrender.com
origin as PUBLIC_BASE_URL. No invented hostname is filled into the review JSON.
A later switch to mcp.stealthfoundersclub.com changes issuer/resource bindings;
plan for reconnecting test clients and separately approve DNS/configuration.

## Uploader review and scope

upload-render-secrets.py now uses render_production.py, not the legacy generic
operator transfer. It is not a Render resource-creation/configuration tool.

Before Keychain reads or PUTs it verifies both service IDs/names/types/workspace,
repo, hosted-mcp branch, Virginia region, one 1c-2g Docker instance, no disk or
autoscaling, correct Dockerfiles, blank command override, Off auto-deploy, proper
health-check type and actual browser private hostname.

Environment inventory is paginated until empty (including short pages), bounded
to 16 pages, discards values and refuses duplicate keys/cursors. Unknown direct
variables cause STOP before secret reads/writes, including any gateway/DB secret
on browser. Render's per-service env API does not include linked-group values;
--no-env-groups-reviewed is an explicit attestation of manual empty-group review,
NOT a programmatic guarantee about inheritance. Check inherited secret files too.

A strict per-service HTTP policy independently denies wrong-destination writes:
only four gateway secret keys and two browser secret keys. No create/delete/deploy,
collection replacement, public-setting change or API-key-management endpoint is
allowed. All existing values are compared BEFORE any PUT; any conflict stops.
Partial transfers preserve values and can be rerun with the same local material.

Local runtime binding and registration-attempt journal must match sfc-v1; this
checks local provenance, not a new live SQL read. Then it loads ACTIVE password,
three runtime entries and the validated private TLS leaf bundle. It never reads
owner/exporter credentials, a CA signing key or Supabase service-role key.

Render API credential: hidden getpass prompt once per invocation; transient
memory only, no env/argv/Keychain/file/log saving. API errors/bodies are suppressed,
redirects and environment proxies refused, request/response sizes bounded. Success
AND failure results remind you to revoke the dedicated API key immediately.
Clearing a local reference is not revocation; revocation is a manual Dashboard
step. No claim of secure zeroization of Python strings is made.

## Later execution sequence, separate approvals at each boundary

1. Review this folder; then separately approve a scoped production commit/push.
   Keep Mac operator helpers out of the hosted image/publication manifest.
2. Separately approve creation of the two services. Auto-Deploy Off prevents
   future automatic Git deploys; do NOT assume it suppresses the initial creation
   build/deploy. A creation click may start one. Missing secrets make current
   startup fail closed before serving member tools; never insert dummy secrets
   or weaken auth to make this preliminary attempt green.
3. Capture actual workspace/service IDs, DNS and URL. Verify all source/settings,
   no groups/inherited files and required proxy/callback configuration. Stop if
   supported fields/shapes differ; do not relax the uploader silently.
4. Separately review/perform TLS issuance and protected bundle storage. Configure
   public certificates/variables and CA file using appropriate approved save/
   deploy timing. Do not expose a new public login route as ready yet.
5. Only when targets and local inputs are ready, create the dedicated Render API
   key in your Dashboard. Treat it as account-wide. Never paste it into chat.
6. After explicit upload approval, use the new helper with --apply plus project-ref,
   workspace-id, gateway-id/name, browser-id/name, browser-hostname, key-version
   sfc-v1 and --no-env-groups-reviewed. All CLI arguments are nonsecret metadata;
   the credential itself uses the hidden prompt. No live command is authorized here.
7. Record counts/status only; immediately revoke that dedicated key in Dashboard
   on success OR failure. Confirm it is revoked before doing anything else.
   No automatic revocation or service deployment is performed by the helper.
8. Separately approve browser, then gateway production deploys at the approved
   commit. Verify both deployed revisions, TLS, headers, unauthenticated denial,
   paid/unpaid/expired membership, two-account isolation and real sandbox cleanup.
   Health checks alone are insufficient. DNS/custom domain remains another gate.

An env PUT by this helper is a direct per-key update; no deploy endpoint is called.
Do not equate a successful update with active runtime configuration. Inspect
pending/active deployment state in the later verification gate.

## Documentation consulted (public references only, no authenticated Render calls)

- https://render.com/docs/configure-environment-variables.md
- https://render.com/docs/environment-variables.md
- https://render.com/docs/deploys.md
- https://render.com/docs/health-checks.md
- https://render.com/docs/private-network.md
- https://render.com/pricing.md
- https://api-docs.render.com/openapi/render-public-api-1.json
- https://api-docs.render.com/reference/update-env-var
- https://api-docs.render.com/reference/retrieve-service
- https://render.com/articles/how-render-handles-ddos-attacks
- https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp
- https://developers.openai.com/plugins/build/auth

Render Markdown references and the public OpenAPI schema were retrieved/read.
API endpoint .md pages were unavailable; their HTML and schema were used instead.
No documentation source supplied an authoritative trusted ingress CIDR set.
