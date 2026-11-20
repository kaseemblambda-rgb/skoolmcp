# Synthetic container gate: local harness ready, images not yet run

This harness is test-image-only code. Production Dockerfiles and entry points do
not import it. No production DB, migration, Keychain item, saved profile, member
data, Render resource or real-account sign-in is used by the local checks.

## Run locally, fully offline

```bash
cd ~/skoolmcp
.venv/bin/python -m hosted.deploy.probe.main --mode all
.venv/bin/python -m unittest test_hosted_container_probe -q
```

The revised hosted-only release gate is separate:

```bash
python -I hosted/deploy/run_release_tests.py
```

It requires 98 tests with no failures, errors or skips. It explicitly rejects
hosted/runtime/test imports from another checkout, including editable-install
fallbacks. test-gate.json names the exact modules. Fixtures are in-memory helpers
in test_hosted_popup.py and test_hosted_analytics.py; no member exports or saved
profiles are used. The former mixed 214-test development suite includes Mac-only
work and is not this release's gate.

The JSON must say PASS, container_runtime_checked=false and
real_chromium_checked=false. Those false fields are intentional: local synthetic
tests do not prove Linux/Render Chromium compatibility. No listener starts unless
--serve is explicitly requested. The local listener defaults to loopback.

Checks cover actual gateway/SDK health and authenticated status dispatch with an
in-memory database, anonymous/unpaid denials, request-bound session selection,
real TLS socketpair handshakes, bad-host/untrusted/expired certificate rejection,
private TLS file removal, fake browser-job isolation/capacity/error cleanup and
application shutdown. SQL expiry semantics remain covered by the separate reviewed
PostgreSQL rehearsal; a synthetic DB response is not a new SQL verification.

The harness refuses environment variables associated with real DB/API credentials,
session keys, browser secrets or saved profiles. It does not load configuration or
.env files. Offline probes reject socket connections and DNS. Temporary test TLS
material is generated in memory, with private files only through the existing
temporary 0600/0700 TLS implementation; it is never printed or retained.

## Prepared test image definitions

- hosted/deploy/gateway-probe.Dockerfile
- hosted/deploy/browser-probe.Dockerfile

These reproduce the production base/dependency/source instructions and add only
allowlisted harness files. The browser probe adds cryptography for its synthetic
TLS tests. Both run as uid/gid 10001. Build contexts are explicit:

```bash
.venv/bin/python hosted/deploy/prepare_context.py --service gateway-probe --output /private/tmp/stealth-gateway-probe-context
.venv/bin/python hosted/deploy/prepare_context.py --service browser-probe --output /private/tmp/stealth-browser-probe-context
```

No Docker build is performed by these commands. Production contexts continue to
exclude harness files. Do not supply secrets as build arguments or environment
groups to either test service.

## Later container/Render gate, requires separate approval

Use temporary Private Services only. The --private-service flag is an operator
declaration, not proof that a Render service was configured private. Do not create
a public Web Service for these probes. Disable automatic deploys and attach no real
credentials, production config, persistent disk or profiles.

The image CMD runs its probe before starting the result-only listener. Gateway
mode uses the synthetic database and makes no external requests. Browser mode
additionally requires Linux and uid 10001, starts fresh real Chromium instances
using the existing read-only login policy, and loads only Skool's public login
page. No credentials are typed, no sign-in is attempted, and no member endpoints
are read. A harmless test cookie confirms context separation.

The real-browser checks require two distinct browser/context/directory instances,
deny a third simultaneous job, check frames without returning/logging screenshots,
test one-job failure without disturbing the other, close jobs and clean up on app
shutdown. They inspect only their own process descendants and require renderer
NoNewPrivs, seccomp filtering, zero effective capabilities and no --no-sandbox.
They verify process/directory cleanup. Unsupported or uninspectable sandbox state
fails the probe rather than silently weakening it. Never add privileged mode,
SYS_ADMIN, --no-sandbox or unconfined seccomp to get a pass.

On PASS, only /healthz and /result are exposed, with fixed check names and boolean
flags. MCP and /job are never mounted on the listener. On failure, output is a
fixed E_* code, exit is nonzero and no listener starts. Health remains closed until
the entire gate passes. Screenshots, cookie contents, exception text, passwords,
tokens, process arguments, environment values and request logs are never printed.

This still does not test production Supabase connectivity, a real member login,
cross-service DNS/TLS, Claude/ChatGPT callbacks or live membership revocation.
Those remain separate acceptance gates after approval. Docker/Render image builds,
Linux sandbox operation and image/dependency scans have not run on this Mac.

## Step 2 publication proposal: review before commit/push

publish-manifest.json lists the permitted source paths for the proposed synthetic
test release: required hosted runtime sources, production/test image definitions,
context allowlist/preparer, harness, documentation and related offline tests.
The two-member test does not need migration files, Mac sync/exporter scripts,
personal remote/tunnel code, profiles, local harnesses, .env files or exports.
The revised inventory contains 53 paths. The shared hosted_membership module
contains only its unchanged timestamp/legacy-eligibility helpers; owner collection,
Keychain, sync configuration and CLI operations are absent from the isolated tree.

This is an inventory, not authorization to stage a whole file or push the dirty
branch. Before any publication, inspect the exact outgoing commits and scoped
diff, isolate required changes from pre-existing unrelated edits, scan for private
data and show the final revision/files to the user. If branch history would publish
unrelated work, stop for review rather than push it. No Git changes are made by
the harness or context preparer.
