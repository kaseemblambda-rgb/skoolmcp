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

It requires 116 tests with no failures, errors or skips. It explicitly rejects
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
shutdown. CDP SystemInfo.getProcessInfo identifies every renderer of each owned
browser, replacing the fragile renderer argv/parent-discovery heuristic. The probe
maps CDP IDs through NSpid into the procfs namespace. The browser must remain a
launcher descendant in the launcher's PID namespace. Renderers need not remain
Python descendants, but each must map uniquely to its browser's CDP inventory.

Each process directory is pinned while bounded stat/status/executable/namespace
reads run. The executable must match the root-owned, non-writable Playwright
binary under /opt/playwright; UIDs, namespace mapping and process start times must
match. A second CDP inventory and repeated kernel evidence must remain stable.
No raw process argument is used to recognize renderer roles. Browser command
arguments are inspected internally through CDP to reject sandbox-disabling flags;
they are never printed. Unsupported CDP commands fail closed without adding flags.

Every renderer must have NoNewPrivs=1, Seccomp=2, CapEff=0, nested PID and separate
network namespaces. Seccomp_filters must exceed its browser process baseline,
so the container's inherited filter alone cannot pass. Missing fields, unreadable
/proc/exe/namespace evidence, ambiguous PID mapping or reused PIDs fail closed.
In particular, Render denying these reads will fail the probe; this change does
not grant ptrace, change dumpability or add capabilities to bypass that boundary.
Never add privileged mode, SYS_ADMIN, --no-sandbox, --allow-sandbox-debugging or
unconfined seccomp to get a pass. Production launch flags/images remain unchanged.

Discovery/exit/inventory races take at most four snapshots with three 250 ms waits.
Observed unsafe, unreadable or invalid security evidence fails immediately.
On success or failure, sandbox_counts reports allowlisted integer categories only,
including CDP renderer counts, namespace confirmations and extra-filter evidence.
CDP alone cannot authorize a pass. CDP requests and detach have bounded timeouts.
Raw process arguments, IDs, status records, cookies and CDP responses never leave
the quiet diagnostic boundary. Failure still exits before starting the listener.

Kernel field definitions: [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html).
CDP methods: [official protocol](https://chromedevtools.github.io/devtools-protocol/tot/SystemInfo/#method-getProcessInfo)
and [Browser.getBrowserCommandLine](https://chromedevtools.github.io/devtools-protocol/tot/Browser/#method-getBrowserCommandLine).

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
