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

To build and run the native fake-session tests in the same Nix development
environment without running the package's install phase:

```nu
nix-shell nix/approval-agent.nix --run 'make -C gui all check'
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
cookies; Once → Run → Once generation changes; one GTK toplevel with the X11
`AgentKeyringApproval` WM_CLASS, dialog hint, modal and nonresizable flags;
a horizontal Cancel/Authenticate action row; plain-text multiline metadata with
a bold, relatively scaled secret heading; literal markup-like/non-ASCII text;
long unbroken secret names wrapping within the allocated label; and display of
the selected base message without the verified challenge's request nonce.
They also cover late old requests/completions; synchronous cancel/completed
reentrancy; queued and cross-thread cancellation; retained identities; identity
switching; Enter and
button submission; freeze-before-response; multiple hidden/visible PAM prompts;
password clearing; the 16-choice cap; liveness EOF/unexpected data; deadlines;
and credential/cookie exclusion from control streams. A fork-only hardening
probe checks core limits, dumpability, CLOEXEC, and library stdout/stderr
redirection without executing any authentication code.

Control records are sent before retiring an old authentication session: CHOICE
invalidates the old root check before cancellation can finish it, and CANCEL
notifies root before synchronous cleanup can delay window shutdown.

The layout uses the installed GTK theme's font family and colors, without CSS,
absolute font sizes, or a forced theme. Dialog hints are advisory; tiling window
managers may additionally need a floating rule matching `AgentKeyringApproval`.
The base message is only a presentation choice: action, full challenge text
(including request ID and generation), and subject-PID validation remain exact.

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

## Operator-controlled native Wayland acceptance (0.3.0)

Xvfb proves only the X11 widget branch. Rust tests use temporary UNIX sockets,
not a compositor, and do not prove GTK Wayland or polkit/PAM integration.
Native Wayland acceptance remains unverified until an operator performs it.
Do not automate a live lock, logout, compositor/session restart, or suspend;
each disruptive check needs fresh explicit operator approval.

On an already active, local, unlocked Wayland session with an existing user
manager and the host's real polkit helper:

1. Install reviewed native packaging/policy and configured trusted tool paths.
   Preserve root daemon `NoNewPrivileges=true`, requester-UID GUI service without
   NNP, and root vault 0700/database 0600. Do not import, delete or migrate secrets.
2. Use an operator-designated non-sensitive test key and a real supported agent
   topology. Confirm the subject has the correct `/run/user/UID` runtime and
   compositor socket. A missing subject Wayland environment must fail closed,
   even if the user manager has its own usable environment.
3. Request approval; inspect Hyprland's window metadata while it is visible.
   Confirm native Wayland (not XWayland), app_id/class `AgentKeyringApproval`, one
   window, readable metadata and an effective floating rule for that app_id.
   X11 separately retains WM_CLASS `AgentKeyringApproval` and `GDK_BACKEND=x11`.
4. Exercise Cancel, window close, bad password, Once, Run, and rapid scope changes.
   Only the daemon's current exact polkit check may grant access; a stale success,
   unrelated action or dialog output must never suffice. Confirm process exit,
   unrelated agents and revocation retain existing process-scoped behavior.
5. Confirm deadline/cancellation cleanup removes the exact transient unit and
   all GUI/PAM descendants, leaves the global desktop agent registered, and
   leaves the root daemon running with NNP. A cleanup failure must retain the
   per-UID prompt fence rather than open another approval.
6. Test missing/bad runtime, socket and environment using isolated fixtures, not
   by modifying live compositor sockets. Rust covers UID mismatch and
   remote/locked/inactive/unsupported session properties; an actual lock/unlock
   or remote-session gate is a separate explicitly authorized operator check.

Record compositor/GTK/polkit/systemd versions and what actually passed. Do not
label a package build or Xvfb run as native Wayland acceptance.
