# Native approval checks

`docs/approval-protocol.md` is the interface authority. This directory implements
only the unprivileged listener; its output never authorizes a request.

## Build and test

Ubuntu 24.04 build dependencies: a C compiler and Make (`build-essential`),
`libgtk-3-dev`, `libpolkit-agent-1-dev`, `pkg-config`, `xvfb`, and `xauth`
(the latter is needed by Ubuntu's `xvfb-run`). The headless runtime also needs
`librsvg2-common`, `shared-mime-info`, and `adwaita-icon-theme` so GTK can decode
its SVG radio-button assets. Missing loaders remain fatal test warnings; do not
suppress them. No PAM development package or replacement authentication helper
is needed.

```nu
make -C gui all check
```

Nix uses the same strict C build and runs the same tests during `checkPhase`:

```nu
nix-build nix/approval-agent.nix --no-out-link
```

The package installs `libexec/agent-keyring-approval`, with GTK runtime wrapping.
It links `nix/host-polkit.nix`, whose helper path defaults to
`/usr/lib/polkit-1/polkit-agent-helper-1`, not `/run/wrappers/bin`.
No helper is installed with setuid permissions by this package.

`make check` opens synthetic widgets only on Xvfb. The test translation unit
includes the implementation with a renamed, **uncalled** production main. Its
SessionOps use a fake GObject with polkit-compatible signals. It never registers
an agent, runs pkcheck, starts a PAM helper, or asks for a real password.

Checks exercise argv and exact message/PID/action matching; duplicate/reused
cookies; Once → Run → Once generation changes; one GTK toplevel; late old
requests/completions; synchronous cancel/completed reentrancy; queued and
cross-thread cancellation; retained identities; identity switching; Enter and
button submission; freeze-before-response; multiple hidden/visible PAM prompts;
password clearing; the 16-choice cap; liveness EOF/unexpected data; deadlines;
and credential/cookie exclusion from control streams. A fork-only hardening
probe checks core limits, dumpability, CLOEXEC, and library stdout/stderr
redirection without executing any authentication code.

Control records are sent before retiring an old authentication session: CHOICE
invalidates the old root check before cancellation can finish it, and CANCEL
notifies root before synchronous cleanup can delay window shutdown.

## Lifetime and deployment boundaries

Each accepted challenge owns its task, cancellable, copied cookie and identity
references. The active challenge is retired before cancelling its session.
Cancellation callbacks retain a reference and defer onto the GTK context, so
synchronous completion and delayed cancellation cannot mutate a replacement
challenge. Identity switching similarly invalidates the old session first.
Task completion is conversation handling, never an authorization result.

A private CLOEXEC duplicate of stdout carries only READY/CHOICE/CANCEL; ordinary
stdout and stderr are replaced by `/dev/null` before GTK or polkit initialization.
Entry contents are cleared before response, and the temporary response copy is
explicitly overwritten afterward. This does not promise to erase every GTK,
GLib, PAM, or allocator copy.

The GUI refuses root, mismatched real/effective UID, and inherited
NoNewPrivileges. It must be launched by the user-manager **service** outside the
root daemon's NNP ancestry. Registration is non-fallback and scoped to the exact
CLI PID/start/UID. Subject identity, authority owner and system-bus loss are
monitored; timeout and stdin closure cancel the UI. The owner watcher is installed
before registration and unregisters on loss, preventing libpolkit's normal
automatic reconnect/re-registration in the running listener.

Polkit has no public continuous registration-attestation API. READY is not such
an attestation; root still must reject GUI/launcher loss and own all authorization
and service cleanup. Startup/unregister calls can block in the system bus;
root's absolute deadline and bounded user-unit stop remain essential. No
claim is made that an authority-routing race can never show the global desktop
agent. Keep the real synthetic-secret desktop integration gate before release:
these tests intentionally do not validate actual registration, user-manager
launch, host PAM, or global-agent coexistence.
