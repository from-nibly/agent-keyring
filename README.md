# agent-keyring

A Linux Rust CLI and root-owned daemon for administrator-approved access to secrets
from Pi, Claude Code and Codex process trees. The single-window approval flow
has been verified with Pi on an X11/logind desktop. Claude/Codex entrypoint
matching has unit coverage, but their live installations have not yet been tested.

## Security boundary

This uses the same *desktop trust model* as a polkit administrator prompt: the
host desktop, administrator and root are trusted. It is **not an agent sandbox**.
X11 input capture, unrestricted Docker access, host-root compromise and injection
into another same-user process are outside its protection. Agent executable names
are display/discovery hints, not proof that code is trustworthy. Administrator
approval is always required before a new read grant is created.

The daemon never elevates an agent. It releases only the approved secret. Once a
secret has been released, it cannot prevent copying, forwarding or retention.

Secrets live in a separate root-owned SQLite vault (`/var/lib/agent-keyring`,
0700; database 0600), namespaced by the authenticated client's UID. This is
**plaintext storage protected by filesystem permissions**, not an encrypted
keyring. Use full-disk encryption for offline disk protection. The daemon does
not use the unlocked desktop Secret Service as its protected backend.

Existing desktop-keyring items are **not imported or deleted automatically**.
Removing an old `keyring` shell wrapper does not delete those items. Existing
raw copies may remain accessible through other Secret Service clients.

## Approval behavior

1. Start your agent normally; no launcher or persistent shell is required.
2. Its child runs `agent-keyring get application.label`.
3. The daemon authenticates the sender using kernel message credentials and a
   kernel-supplied pidfd, then verifies its live ancestry to an agent process.
4. One desktop window contains Cancel, Once/For this agent run choices, and the
   administrator identity/password controls. The secret name appears first in
   bold, with each request detail on its own line. GTK supplies the configured
   desktop theme and fonts, including Home Manager themes. No separate Zenity
   dialog is used. The window advertises itself as a dialog; tiling WMs can enforce
   floating placement with a rule for WM_CLASS `AgentKeyringApproval`.
5. Either Allow choice requires **polkit administrator authentication**. Changing
   duration before password submission clears the entry and starts a fresh check
   in the same window. Submitting credentials freezes the scope for that check.
   The root-owned daemon independently checks the exact pending request; GUI
   output alone cannot create a grant. Passwords go only from the native GUI to
   the host polkit authentication helper, never through the daemon or CLI.

**Once** releases one response, not one read per child. **For this agent run**
allows that secret/version for the approved process and its verified live
children until that process exits. Another terminal or another execution does
not inherit the grant. Separate temporary shells from the same agent can use it.

If a helper detaches and its ancestry no longer leads to the approved root,
access is denied. There is no historical-descendant tracking or fallback approval
for that detached helper. Native and Node/Bun agent entrypoints are recognized;
unknown wrappers fail closed rather than approving a whole login shell.

A broker restart clears grants. Secret replacement/deletion invalidates old
version grants. Revocation prevents future authorization, not responses already
authorized and in flight. No sudo timestamp or polkit `*_keep` cache is reused.
An additional request while an approval is pending for that user gets a retryable
error instead of opening another dialog. If GUI cleanup cannot be confirmed,
further approvals for that UID remain blocked until the service is restarted.

Cached run grants follow the approved process lifetime; screen lock or logout
does not itself revoke them if the process survives. Cached reads do not perform
fresh desktop/session checks. Use `revoke` to end that permission explicitly.

## Commands

```text
agent-keyring set pi.example             # create only; hidden TTY input or stdin
agent-keyring get pi.example             # invoked from an agent's process tree
agent-keyring get --non-interactive pi.example
agent-keyring replace pi.example         # administrator authentication
agent-keyring delete pi.example          # administrator authentication
agent-keyring grants                     # metadata only, JSON
agent-keyring revoke --current           # current agent's grants
agent-keyring revoke --all               # all grants for the invoking UID
agent-keyring status
```

Keys are case-sensitive `application.label` names, at most 128 ASCII bytes.
Components contain letters, digits, `_` or `-` and are separated by dots. Values
may contain arbitrary bytes, including NULs, up to 64 KiB. Redirected input is
preserved exactly; interactive input ends at its line delimiter. `get` writes
only the value to stdout, without adding a newline. Diagnostics go to stderr.
Never supply secrets as command arguments.

`set` atomically creates a never-before-used key without elevation. It cannot
replace an existing value. Deleted keys retain tombstones so delete/recreate is
not an overwrite bypass. Replacement is bound to the version observed before
administrator authentication; concurrent changes require a fresh request.

Exit status: 0 success, 1 internal/transport error, 2 invalid request, 3 missing
key, 4 denied/no grant, 5 approval unavailable/busy, 6 existing key, 7 version
conflict, 8 no supported live agent ancestor.

## Requirements and installation

- Linux with `SO_PASSPIDFD`/`SCM_PIDFD` support (Linux 6.5+; absence fails closed).
- systemd 254+ with logind and an existing user service manager; polkit (`pkcheck`
  and its host authentication helper). A normal desktop authentication agent is
  still useful for installation through `pkexec` and replacement/deletion.
- The native `agent-keyring-approval` GUI, GTK3/libpolkit-agent, and an active
  local X11 desktop session for new approvals. New approvals in Wayland-only,
  remote, or headless sessions fail closed; already-approved run grants follow
  the lifetime described above.
- Root installation of the system service and polkit policy. A user service
  alone cannot enforce ownership of the vault or authorization state.

The distribution contains the static Rust executable, a native dynamically linked
GTK3 approval agent, service/policy assets, and a system installer. The GUI needs
the host GTK3 and polkit libraries, SVG pixbuf loader, MIME database, and icon
theme; it is not part of the static Rust binary. On Ubuntu these include
`librsvg2-common`, `shared-mime-info`, and `adwaita-icon-theme`.
Install the CLI from the release archive, then run
`agent-keyring-install-system <extracted-package-directory> <absolute-approval-agent-path>`
through `sudo` or `pkexec`. The approval-agent path can point to the release's
`libexec/agent-keyring-approval` or a Nix-built GUI package. This installs root-owned
copies of both executables, the systemd unit, and the three polkit policies. It
does not import existing secrets.
On systems where `pkexec` rejects a Nix-provided login shell, set `SHELL=/bin/bash`
for that installer invocation.

For standalone Home Manager on Debian/Ubuntu, `nix/approval-agent.nix` builds
the GUI against the host's existing polkit helper rather than NixOS's
`/run/wrappers/bin` path. `nix/polkit-agent.nix` supplies an optional ordinary
desktop authentication agent for other operations. Neither installs a new setuid
helper. Retain Nix-built packages in your profile while the daemon uses them.

The daemon keeps `NoNewPrivileges=true`. It starts the approval GUI as an
ordinary-user transient service through the existing user manager, outside that
inherited restriction so the standard host polkit helper can authenticate. The
GUI registers only for the requesting CLI process, leaving the normal desktop
agent alone. Missing manager/registration, invalid protocol, or failed cleanup
fails closed; there is no application fallback to a second dialog. The user
manager and desktop are trusted, not an isolation boundary. A privileged
bootstrap remains necessary for the root daemon and vault.

See [the approval protocol](docs/approval-protocol.md) for scope binding,
credential handling, cancellation, and lifecycle requirements.

Do not grant the daemon installer or secret operations a broad `NOPASSWD` rule.
Do not run the actual agent as root.

## Development

```text
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
```

The Rust toolchain may be provided through `nix-shell '<nixpkgs>' -p cargo rustc`.
Unit tests use synthetic data and temporary directories, never the desktop
keyring. Real desktop/polkit and root-service tests are separate acceptance steps;
a passing storage test is not proof of the full approval boundary.

For sudo precedents, see [sudoers_timestamp(5)](https://www.sudo.ws/docs/man/sudoers_timestamp.man/).
For authorization semantics, see [polkit(8)](https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html).
