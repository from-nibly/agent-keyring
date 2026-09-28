# Verification

## Automated

The implementation passes 87 Rust tests on both GNU and musl, 13 native GTK
fake-session tests under Xvfb, Clippy with warnings denied on GNU, Rustfmt,
ShellCheck, and actionlint. The v0.1.0 tag's
static build exposed libc-specific ancillary length types; v0.1.1 fixes those
conversions and adds musl tests as a release gate. Local musl testing used Rust
1.98.1; CI pins Rust 1.95.0 for both targets.

Tests were run with a process-local umask of 077, matching the service's private
file-creation policy. One earlier parallel run reported an undiagnosed raw
packet-send failure. The assertion now includes errno; thirty subsequent full
parallel GNU runs passed without reproducing it. No packet-size or truncation
assertions were weakened.

Coverage includes:

- Per-message kernel credentials and pidfds, descriptor passing, malformed and
  oversized messages, descriptor cleanup, idle listeners and short first-packet
  deadlines.
- PID/start-time binding, dead processes, parent-edge changes, detached helpers,
  exact agent discovery and a real Node process changing its title to `pi`.
- UID/key/version-scoped grants, noninteractive denial, revocation epochs,
  per-owner connection limits, and one pending prompt per user.
- Atomic create, compare-and-swap replacement, tombstones, competing writers,
  persistence, key/value bounds and unsafe filesystem paths.
- Native helper trust, bounded subprocess execution and cleanup, sanitized
  environment/FDs, logind session checks and the installed pkcheck argument parser.

The `pkcheck` parser regression matters: polkit 124's help advertises `--details`,
while the executable accepts `--detail` or `-d`. Production uses `-d`.

## Single-window desktop acceptance (v0.2.0)

The static musl daemon and Nix-built GTK3/PolkitAgent frontend were exercised with
synthetic data on the same host described below. Verified:

- An unprivileged Xvfb probe registered the actual process-scoped listener with
  the real polkit authority, observed exactly one visible GTK toplevel, and
  confirmed liveness-EOF shutdown and inactive transient-service state. It made
  no authentication request.
- Actual administrator authentication in the combined window released a Once
  response; a subsequent noninteractive request was denied with exit 4.
- Changing the selection from Once to Run in that window cancelled the old
  check and completed a fresh scope-bound authentication. The next temporary
  child request succeeded without a prompt, and the grant identified the real
  Pi PID/start-time instance.
- Explicit revoke invalidated the grant; subsequent noninteractive read denied.
- Cancel returned exit 4, left no grants, and left no approval user service.
- The root daemon retained NoNewPrivileges=yes and did not restart. Polkit logs
  identified the process-scoped agent and ONE-SHOT authorizations. The cancelled
  superseded scope check is logged as failed authentication, as expected.

Review corrected CHOICE/CANCEL-before-session-cleanup ordering. Tests cover that
ordering, stale callbacks/results, scope freezing before credential responses,
private liveness/control descriptors, and credential-canary exclusion from those
streams. Nix's root-owned sticky store ancestor is accepted without permitting
writable executable files or initial parent-directory traversal.

Wrong-password account-lockout behavior and every possible host PAM conversation
were not manually exercised. Native tests simulate failure, multiple prompts,
identity changes, cancellation, and stale callbacks without real credentials.

## Initial desktop acceptance (two-dialog implementation)

A root-owned transient system service and temporary vault were exercised on
Pop!_OS 24.04, Linux 7.0, X11/logind and polkit 124. A normal-user GNOME polkit
agent used the host's existing privileged authentication helper. Tests used only
synthetic `acceptance.*` values, not the existing desktop keyring.

Verified:

1. Create succeeds without user elevation; duplicate create returns exit 6.
2. Initial noninteractive read returns exit 4 without a prompt.
3. Allow once plus actual administrator authentication releases one response;
   the next noninteractive read is denied and the grant list is empty.
4. Allow for this agent run plus actual authentication permits another temporary
   child request without a new prompt. A different secret remains denied.
5. The stored grant identifies the actual Pi PID/start-time instance, not its
   shell or the CLI requesting the secret.
6. Replacement requires a fresh administrator prompt, increments the version,
   and invalidates the old read grant.
7. Deny returns exit 4 without disclosure.
8. A detached non-agent request launched by the user service manager returns
   exit 8 instead of inheriting Pi's permission.
9. The daemon survives idle periods exceeding the former socket timeout with no
   restart. Polkit logs report ONE-SHOT authorization for the read and replacement
   actions, not retained authentication.

## Limits

This is not a formal security audit. Root and the desktop remain trusted; there
is no sandbox or resistance to existing host-root privileges. The vault is not
encrypted at rest. Real Claude/Codex launch topologies, other desktops and older
kernels have not been exercised. Wayland-only/headless/remote sessions fail
closed. Screen-lock hints depend on the desktop's logind integration. Revocation
cannot retract bytes already authorized or released.
