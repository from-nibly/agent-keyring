# Single-window approval integration contract

Implementation target: one persistent GTK3 window containing scope radios and
polkit identity/password controls, rather than Zenity plus a desktop-agent window.
Root independently checks every new grant through polkit. GUI output is never
authorization. This is still the trusted-host-desktop model, not a sandbox.

## Executable and wire contract

The root-owned native executable is `agent-keyring-approval`, configured by
`daemon --approval-agent <absolute-path>` (default
`/usr/local/libexec/agent-keyring-approval`). No Zenity fallback.

Arguments, all separate argv entries:

- `--pid <positive CLI PID>`
- `--start-time <positive /proc start ticks>`
- `--uid <nonzero authenticated CLI UID>`
- `--request-id <32 lowercase hexadecimal characters>`
- `--once-message <root-authored exact once authorization message>`
- `--run-message <root-authored exact run authorization message>`
- `--timeout-seconds <positive bounded integer>`

Both messages contain key, version, actual agent-root PID/start time, and scope.
They contain no secret values or passwords. The GUI runs with real/effective UID
matching `--uid`, never root. It registers a non-fallback PolkitAgentListener for
that exact CLI unix-process subject, NOT for the GUI or desktop session.

After successful registration/window initialization, stdout is exactly:

```
READY
CHOICE 1 once
```

Each active scope-radio change clears the password, disables credential entry
until the corresponding challenge arrives, and emits `CHOICE <n> once|run` with
strictly consecutive sequence numbers. Maximum 16 choices, one READY, bounded
ASCII lines/total bytes. Window closure emits `CANCEL` before any potentially
blocking session cleanup, then closes the protocol writer. This matters because
the launcher/manager may retain other stdout writers and delay EOF. A scope change
must emit CHOICE before cancelling its old session, so cancellation cannot finish
the old check before root learns of the change. EOF also means cancel. There are
no other stdout records. The GUI must never emit authentication results, prompts,
cookies, or passwords.
Stderr goes to /dev/null, never the daemon log or journald. No POLKIT_DEBUG.

Stdin is a private liveness pipe: root retains its only write end and sends no
bytes. EOF/HUP or unexpected bytes cancel all sessions and close the GUI. All
protocol/liveness descriptors are CLOEXEC before spawning authentication helpers.

## Root authorization generations

For each accepted choice, invalidate the old attempt FIRST, kill/reap its exact
pkcheck child, and start a fresh independent root-side check for the authenticated
CLI subject. Check message must be exactly:

```
<once-message or run-message>

Request: <request-id>/<sequence>
```

Use `pkcheck -d polkit.message <message> --allow-user-interaction` and existing
read action/policy (`auth_admin`, never `_keep`). Do not depend on custom details:
polkit 124 does not forward arbitrary detail keys to BeginAuthentication.

Root associates each child immutably with its sequence and scope. Process observed
GUI changes/cancellation before accepting simultaneous check success. Never apply
a later GUI preference to an older successful check. Only exit 0 of the current
non-invalidated root-side check can succeed, and only for that launch's scope.
GUI/helper/launcher success alone cannot grant anything. At most one root-side
check is live. One absolute deadline covers startup and all choices, not a reset
per choice. Keep current subject/session and final broker ancestry, key/version,
revocation epoch, process liveness and owner checks.

## Native listener

Use a single GTK toplevel with a dialog type hint and stable WM_CLASS
`AgentKeyringApproval`; tiling-desktop configuration should float that class.
Initially Once is selected; password entry waits for the first challenge. Put the
secret name first and emphasize it using theme-relative typography. Show agent,
process ID, start ticks, version, and access scope on separate labeled lines, with
o privilege-reassurance sentence. Show the offered administrator identities inline.
After exact challenge validation, render the selected base message, not the
internal request nonce suffix. This is display formatting only: Every BeginAuthentication must match the read action, the
expected exact message above for the latest emitted choice, and the CLI subject
PID in `polkit.subject-pid`. Reject stale/foreign/duplicate challenges.

Track each cookie/task/session separately. Root child reaping does NOT acknowledge
polkit cancellation: CancelAuthentication is asynchronous. Retire old challenge
callbacks before accepting a new one; old cancellation/completion must never
clear or close the new challenge. PolkitAgentSession cancellation can emit its
completed signal synchronously. Copy/ref callback data retained after initiate
returns; complete every task exactly once and respect its GCancellable.

Scope and identity controls freeze BEFORE the first credential response (including
Enter-key submission), and stay frozen through PAM prompts/retries. Use only
identities offered by polkit; support multiple inline identities and prompts with
polkit's echo_on property. Credential bytes go only from GTK to PolkitAgentSession
and the host helper. Clear entry/copied buffers promptly, disable core dumps and
set PR_SET_DUMPABLE=0 before credential entry. Do not claim all GTK/PAM allocator
copies are zeroized. Keep the listener/window alive after helper success until
root closes stdin after collecting its own check result. Authority disconnect,
registration failure/loss, subject exit or timeout fails closed; no automatic
re-registration or alternate application UI.

## User-manager launch and cleanup

Preserve root service NoNewPrivileges and the existing UID-dropping launcher.
A direct daemon child cannot use the host setuid PAM helper. Launch the GUI via
an existing user-manager SERVICE, not scope, using a trusted `/usr/bin/systemd-run`:

- `--user --pipe --wait --collect --quiet --no-ask-password`
- `--service-type=exec --expand-environment=no`
- unique root-generated unit name (not supplied by GUI)
- LimitCORE=0, Restart=no, bounded TimeoutStartSec/RuntimeMaxSec/TimeoutStopSec,
  KillMode=control-group, SendSIGKILL=yes
- working directory `/`, trusted `/usr/bin/env -i` and a strict environment allowlist
  derived from the already verified desktop account/session
- preserve the account HOME for normal GTK settings; the user GUI's XDG_DATA_DIRS
  includes `HOME/.nix-profile/share`, `/usr/local/share`, and `/usr/share` so
  Home Manager themes/icons resolve. Do not force GTK_THEME or custom colors,
  inherit arbitrary loader variables, or send these data paths to root checks
- remove loader-injection variables at the unit boundary as defense in depth;
  user manager and same-UID desktop still remain trusted

No root elevation/new setuid helper/policy relaxation. The GUI links the existing
hostPolkit library override from nix/polkit-agent.nix. Missing user manager or
unsupported options fails closed. Preserve normal global desktop agent behavior
for unrelated operations.

Close stdin on every terminal path; wait for real transient-service settlement.
The GUI is not in the launcher's process group. Killing only systemd-run is not
cleanup. Use bounded stop of the exact generated user-unit when needed, in
addition to runtime/stop backstops. Do not kill PIDs claimed by stdout. Keep the
per-UID prompt guard until cleanup is known; fail closed/fence that UID on unknown
cleanup instead of allowing overlapping prompts. Readiness is not proof of
continuous registration: a listener-loss race can let polkit route elsewhere;
monitor GUI loss and refuse that request rather than treating fallback as success.

## Verification gates

- Parser ordering, fragmented/coalesced records, malformed/flooded input, EOF.
- Once/run/same-scope changes racing old successful checks; immutable result scope.
- No preference stream or GUI exit can authorize without root check success.
- Late cancellation/completion, multiple identities/PAM prompts, Enter, frozen
  scope, password clearing, one toplevel, no credential bytes on control streams.
- Synthetic user-service tests: launcher NNP versus child context, literal argv,
  stdin EOF/daemon loss, startup/runtime/stop bounds and no orphan window/helper.
- Existing broker tests, GNU and musl suites, native C strict warnings and GUI tests.
- Real synthetic-secret desktop test before release/install: one window, once,
  run/cache, scope changes before submission, deny/wrong password/cancel/timeout.
