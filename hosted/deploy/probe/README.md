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

It requires 140 tests with no failures, errors or skips. It explicitly rejects
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
arguments are read only from the verified browser's pinned /proc directory to
reject sandbox-disabling flags; they are never printed. Before cmdline is opened,
its PID/start time, UIDs, executable inode and namespaces must match the verified
browser, and /proc/exe must resolve to the trusted Playwright binary. Reads use
O_NOFOLLOW, a 64 KiB limit, at most 4096 NUL-delimited arguments and a required
terminator. The repeated evidence check also rechecks the browser command line.
Browser.getBrowserCommandLine is never called: Playwright 1.64.1 does not supply
the enable-automation switch required by that CDP method. No launch flags change.

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
including CDP renderer observations, namespace confirmations and extra-filter
evidence. Query/read counters include both verification passes.
CDP alone cannot authorize a pass. CDP requests and detach have bounded timeouts.
Raw process arguments, IDs, status records, cookies and CDP responses never leave
the quiet diagnostic boundary. Failure still exits before starting the listener.

Kernel field definitions: [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html).
CDP methods: [official protocol](https://chromedevtools.github.io/devtools-protocol/tot/SystemInfo/#method-getProcessInfo)
and [proc_pid_cmdline(5)](https://man7.org/linux/man-pages/man5/proc_pid_cmdline.5.html).

Failure stages have separate fixed categories (never upstream exception text):

| Stage | Failure code |
| --- | --- |
| CDP session | E_SANDBOX_CDP_SESSION |
| CDP process query | E_SANDBOX_CDP_PROCESS_QUERY |
| CDP process response validation | E_SANDBOX_CDP_PROCESS_INVALID |
| Command-line access denied | E_SANDBOX_CMDLINE_DENIED |
| Command line disappeared | E_SANDBOX_CMDLINE_UNAVAILABLE |
| Command-line read error | E_SANDBOX_CMDLINE_READ |
| Malformed or oversized command line | E_SANDBOX_CMDLINE_INVALID |

Identity and every existing kernel restriction retain their fail-closed checks.
Only discovery/exit races use the bounded retry; command-line failures never fall
back to CDP, skip a browser or authorize a pass. Detach failures are counted while
browser/job cleanup remains mandatory. No cookies, credentials or raw arguments
are added to the diagnostic output.

## Change A: identity-aware cleanup diagnostics (implemented)

The probe retains the first PID/start-time/UID/NSpid identity of each tracked
process before shutdown. Browser/renderer identities and roles come from the
verified CDP/kernel evidence. Other descendants, including the third browser
job, are captured before application shutdown. Their role labels are diagnostic
hints from exact allowlisted executable basenames or type switches. A failed
role read becomes unknown; it never changes sandbox authorization. Raw names,
arguments, paths, identities, status records and exceptions are not emitted.
Tracking never overwrites an earlier identity when a PID is reused.

Post-shutdown reads pin the process directory and inspect bounded stat/status
files. These work for zombies even when exe/namespace links no longer exist.
A missing inner file is not enough to declare exit: the numeric process directory
must also be absent. No signals, wait calls, process reaping or extra privileges
are introduced by this diagnostic patch.

Cleanup reports fixed integer totals and role/state cross-counts:

- Roles: browser, renderer, zygote, gpu, utility, driver, crash_handler, unknown.
- States: live, zombie, reused, unreadable, gone.
- Totals: cleanup_tracked, cleanup_live, cleanup_zombie, cleanup_reused,
  cleanup_unreadable, cleanup_gone, cleanup_poll_attempts and
  cleanup_tracking_incomplete. Cross-count example: cleanup_renderer_zombie.
- sandbox_verified=1 and the earlier sandbox counters accompany a cleanup
  failure. This confirms the earlier stage, not overall probe success.

Live includes running/sleeping/stopped kernel states. Zombie requires Z. Reused
means the observed identity differs; labels describe the originally tracked
role, never the replacement process. Unreadable includes denied, malformed,
unstable, unsupported or unavailable identity evidence and a missing baseline.
Only processes whose directories are gone pass cleanup. Live, zombie, reused,
unreadable or incomplete tracking keeps E_BROWSER_CHILD_CLEANUP fail-closed.
The existing 30 polls with 100 ms waits remain. Only the final snapshot counts
are emitted, rather than cumulative counts of the same process across polls.

The synthetic regressions cover state/role categories, pinned and bounded reads,
PID reuse, missing inner files, unknown roles, incomplete tracking, the full
shutdown failure path and counts-only output with the listener kept closed.
The Docker/Linux behavior is still a separate Render acceptance gate.

## Change B: pinned PID-1 init/reaper (browser probe only)

Run 5 reported sandbox_verified=1, live=0, zombie=6, unreadable=0 and reused=0.
The approved next trial adds tini only to hosted/deploy/browser-probe.Dockerfile.
The production browser.Dockerfile and both gateway images remain unchanged.

The image downloads the upstream Linux/amd64 Tini v0.19.0 binary over verified
HTTPS and enforces this hardcoded SHA-256 before writing or chmod-ing the file:

```text
93dcc18adc78c65a028a84799ecf8ad40c936fdfc5f2a57b1acda5a8117fa82c
```

The downloaded 24,064-byte binary was independently compared with the upstream
release's tini-amd64.sha256sum during preparation. Neither binary nor checksum
asset is added to the repository. The image build checks the pinned digest, not
a mutable checksum fetched alongside the binary. Oversized/mismatched downloads
fail the build with E_TINI_CHECKSUM. Version/hash have no build-argument override.

Source: [Tini v0.19.0 release](https://github.com/krallin/tini/releases/tag/v0.19.0).
The entrypoint is /usr/local/bin/tini followed by --; the existing Python CMD and
USER 10001:10001 remain. The installed binary is root-owned and mode 0555. Default
quiet tini behavior forwards signals and preserves the probe's exit status.
Python becomes tini's child. Chromium arguments, chromium_sandbox=True, seccomp,
capabilities and every sandbox/cleanup gate remain unchanged. Tini runs as PID 1
under the image entrypoint; no extra privileges or process-killing code are added.

Tini can adopt/reap orphaned zombies. It cannot reap a child still owned by a
living parent, fix a live-child leak or repair unreadable/changed identity data.
See [Tini's PID-1 behavior](https://github.com/krallin/tini#subreaping). Zombie
entries still fail E_BROWSER_CHILD_CLEANUP if they remain. The probe code and
cleanup budget are unchanged. The next separately approved Render run must prove
cleanup_gone=cleanup_tracked with all unresolved categories zero and the sandbox
checks still passing. This local patch does not claim a successful Linux run.

Offline tests enforce the immutable artifact/version/hash, unchanged CMD/user,
image scope, rejection before install for corrupt/oversized payloads, and verified
payload installation with mode 0555. The full cleanup/sandbox regressions still
run. Applying the equivalent change to production needs separate approval.

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
