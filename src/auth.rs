//! Host-desktop authorization, not a sandbox or an agent-elevation mechanism.
//!
//! A Zenity answer is only an untrusted preference. The root daemon MUST call
//! `authorize` separately for EVERY new Once/Run grant and every overwrite/delete,
//! with a message binding the key, root process identity, choice and secret version.
//! It must independently revalidate ancestry/version before committing the operation.
//! Install the three actions with `auth_admin` (NEVER `*_keep`), and deny inactive
//! and remote sessions. Root-owned polkit rules must not bypass those defaults:
//! pkcheck cannot distinguish a rule returning YES from fresh authentication.
//!
//! This deliberately trusts root and the host desktop. X11 clients can spoof or
//! observe dialogs; same-UID processes can tamper with Zenity and its environment.
//! Neither GUI output nor this module makes Docker/root-equivalent users safe.
//! Password entry belongs to the registered polkit agent, never to this daemon.
//! X11 is supported; Wayland-only/headless sessions fail closed. A local active
//! logind session and a registered authentication agent are prerequisites. User
//! service processes require polkit's logind UID-to-display-session fallback;
//! older builds without it fail closed rather than changing the polkit subject.
//! LockedHint is advisory: the desktop locker must update logind, and locks are
//! checked before/after interaction (not an atomic transaction with the desktop).
//! When logind's Display is empty (e.g. greetd), we use the verified subject's local
//! DISPLAY and UID-owned X socket; logind cannot attest that fallback's exact X
//! server. This is the explicit trusted-host-desktop baseline, not isolation.
//!
//! pkcheck(1) requires PID,START_TIME,UID (start time is /proc stat field 22, in
//! clock ticks). Its -d polkit.message VALUE is supported for privileged
//! callers; VALUE is passed unchanged as one argv element. On timeout we kill and
//! reap pkcheck. Upstream polkit's interactive authority cancels authentication
//! sessions when their initiating D-Bus name vanishes, dismissing the external
//! agent's prompt; this relies on the host polkit/agent honoring cancellation.
//! References: pkcheck(1), polkit(8), and polkit 124's
//! polkitbackendinteractiveauthority.c (system_bus_name_owner_changed) and
//! polkitbackendsessionmonitor-systemd.c (get_session_for_subject).

use anyhow::{Context, Result, bail, ensure};
use std::collections::HashMap;
use std::ffi::{CStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub pid: i32,
    pub uid: u32,
    pub start_time: u64,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub zenity: PathBuf,
    pub pkcheck: PathBuf,
    pub loginctl: PathBuf,
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            zenity: "/usr/bin/zenity".into(),
            pkcheck: "/usr/bin/pkcheck".into(),
            loginctl: "/usr/bin/loginctl".into(),
            timeout: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantChoice {
    Once,
    Run,
}

const READ_ACTION: &str = "io.github.from-nibly.agent-keyring.read";
const REPLACE_ACTION: &str = "io.github.from-nibly.agent-keyring.replace";
const DELETE_ACTION: &str = "io.github.from-nibly.agent-keyring.delete";
const PROC_LIMIT: usize = 128 * 1024;
const OUTPUT_LIMIT: usize = 16 * 1024;

/// Obtain a preference, NOT authorization. Even `Some(Run)` requires a fresh
/// root-side `authorize` call; never turn this function's stdout into a grant.
/// Denial/closing returns None. Timeouts, malformed output and unsafe state err.
pub fn choose_read(
    config: &Config,
    subject: &Subject,
    key: &str,
    agent_name: &str,
    root_pid: i32,
    root_executable: &str,
) -> Result<Option<GrantChoice>> {
    require_root()?;
    let deadline = deadline(config)?;
    verify_subject(subject)?;
    ensure!(root_pid > 0, "invalid agent root PID");
    let session = active_session(config, subject, deadline)?;
    let account = account(subject.uid)?;
    let environment = desktop_environment(subject, &session, &account)?;
    let mut command = clean_command(&trusted_executable(&config.zenity)?);
    command.envs(environment);
    let text = format!(
        "An agent requests a secret. Administrator authentication is required next.\n\n\
         Key: {}\nAgent: {}\nAgent root PID: {}\nRoot executable: {}\n\n\
         Allow for this agent run applies only to this running agent, not future runs.",
        escaped_label(key),
        escaped_label(agent_name),
        root_pid,
        escaped_label(root_executable),
    );
    command.args([
        "--list",
        "--radiolist",
        "--title=Agent Keyring",
        "--width=640",
        "--height=420",
        "--column=Select",
        "--column=Permission",
        "--print-column=2",
        "--ok-label=Continue",
        "--cancel-label=Deny",
    ]);
    command.arg(format!("--text={text}"));
    command.args([
        "TRUE",
        "Deny",
        "FALSE",
        "Allow once",
        "FALSE",
        "Allow for this agent run",
    ]);
    prepare_child(&mut command, Some((subject.uid, account.gid)));
    let output = run(&mut command, deadline, Some(subject))?;
    verify_subject(subject)?;
    ensure!(
        active_session(config, subject, deadline)? == session,
        "desktop session changed"
    );
    match output.status.code() {
        Some(1) => Ok(None),
        Some(0) => match output.stdout.as_slice() {
            b"Deny\n" => Ok(None),
            b"Allow once\n" => Ok(Some(GrantChoice::Once)),
            b"Allow for this agent run\n" => Ok(Some(GrantChoice::Run)),
            _ => bail!("unrecognized desktop choice"),
        },
        _ => bail!("desktop dialog failed"),
    }
}

/// Independently ask polkit for authorization, as root, for the authenticated
/// socket peer. Do not use a GUI child or the daemon as the polkit subject.
/// `message` must explain the exact key/root/choice/version being authorized.
/// No successful result is cached here. The policy MUST require auth_admin.
pub fn authorize(config: &Config, subject: &Subject, action: &str, message: &str) -> Result<bool> {
    require_root()?;
    validate_action(action)?;
    ensure!(
        !message.is_empty() && message.len() <= 8192,
        "invalid authorization message length"
    );
    ensure!(
        !message.chars().any(|c| c.is_control() && c != '\n'),
        "invalid authorization message"
    );
    let deadline = deadline(config)?;
    verify_subject(subject)?;
    let session = active_session(config, subject, deadline)?;
    let mut command = clean_command(&trusted_executable(&config.pkcheck)?);
    command.args([
        "--action-id",
        action,
        "--process",
        &subject_argument(subject)?,
    ]);
    command.args(["--allow-user-interaction", "-d", "polkit.message", message]);
    // No internal agent, shell, GUI credentials, or inherited D-Bus address.
    prepare_child(&mut command, None);
    let output = run(&mut command, deadline, Some(subject))?;
    verify_subject(subject)?;
    ensure!(
        active_session(config, subject, deadline)? == session,
        "desktop session changed"
    );
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1..=3) => Ok(false),
        _ => bail!(
            "polkit authorization check failed ({:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

fn require_root() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "authorization must run in the root daemon"
    );
    Ok(())
}

fn validate_action(action: &str) -> Result<()> {
    ensure!(
        matches!(action, READ_ACTION | REPLACE_ACTION | DELETE_ACTION),
        "unsupported polkit action"
    );
    Ok(())
}

fn subject_argument(subject: &Subject) -> Result<String> {
    ensure!(
        subject.pid > 0 && subject.uid != 0 && subject.start_time > 0,
        "invalid subject"
    );
    Ok(format!(
        "{},{},{}",
        subject.pid, subject.start_time, subject.uid
    ))
}

fn deadline(config: &Config) -> Result<Instant> {
    ensure!(!config.timeout.is_zero(), "zero authentication timeout");
    Instant::now()
        .checked_add(config.timeout)
        .context("authentication timeout overflow")
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut data)?;
    ensure!(data.len() <= limit, "input exceeds size limit");
    Ok(data)
}

fn stat_start_time(data: &[u8], pid: i32) -> Result<u64> {
    let data = std::str::from_utf8(data).context("invalid process stat")?;
    let (prefix, rest) = data.rsplit_once(')').context("invalid process stat")?;
    ensure!(
        prefix.starts_with(&format!("{pid} (")),
        "process PID mismatch"
    );
    let fields: Vec<_> = rest.split_whitespace().collect();
    ensure!(
        fields.len() >= 20 && !matches!(fields[0], "Z" | "X" | "x"),
        "process is not live"
    );
    fields[19].parse().context("invalid process start time")
}

fn verify_subject(subject: &Subject) -> Result<()> {
    subject_argument(subject)?;
    let base = PathBuf::from(format!("/proc/{}", subject.pid));
    let before = stat_start_time(&read_bounded(&base.join("stat"), PROC_LIMIT)?, subject.pid)?;
    let status = read_bounded(&base.join("status"), PROC_LIMIT)?;
    let status = std::str::from_utf8(&status)?;
    let uids = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .context("process UID missing")?;
    let uids = uids
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    // Reject set-ID transitions, including saved/fs credentials, not just euid.
    ensure!(
        uids.len() == 4 && uids.iter().all(|uid| *uid == subject.uid),
        "process UID changed"
    );
    let after = stat_start_time(&read_bounded(&base.join("stat"), PROC_LIMIT)?, subject.pid)?;
    ensure!(
        before == subject.start_time && after == before,
        "process identity changed"
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Session {
    id: String,
    uid: u32,
    leader: i32,
    leader_start: u64,
    display: String,
}

fn properties(text: &str) -> Result<HashMap<&str, &str>> {
    let mut result = HashMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').context("invalid logind property")?;
        ensure!(
            result.insert(key, value).is_none(),
            "duplicate logind property"
        );
    }
    Ok(result)
}

fn session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn parse_session(id: &str, text: &str, uid: u32) -> Result<Session> {
    ensure!(session_id(id), "invalid desktop session ID");
    let p = properties(text)?;
    ensure!(
        p.get("User")
            .context("session user missing")?
            .parse::<u32>()?
            == uid,
        "wrong desktop user"
    );
    ensure!(
        p.get("Active") == Some(&"yes")
            && p.get("Remote") == Some(&"no")
            && p.get("LockedHint") == Some(&"no"),
        "desktop must be local, active and unlocked"
    );
    ensure!(
        p.get("Type") == Some(&"x11"),
        "an X11 desktop session is required"
    );
    let leader: i32 = p.get("Leader").context("session leader missing")?.parse()?;
    ensure!(leader > 0, "invalid session leader");
    let display = p
        .get("Display")
        .context("session display missing")?
        .to_string();
    ensure!(
        display.is_empty() || local_display(&display).is_some(),
        "nonlocal desktop display"
    );
    Ok(Session {
        id: id.into(),
        uid,
        leader,
        leader_start: 0,
        display,
    })
}

fn active_session(config: &Config, subject: &Subject, deadline: Instant) -> Result<Session> {
    let helper = trusted_executable(&config.loginctl)?;
    let query = |args: &[&str]| -> Result<String> {
        let mut command = clean_command(&helper);
        command.args(["--no-pager", "--no-ask-password"]).args(args);
        prepare_child(&mut command, None);
        let output = run(&mut command, deadline, Some(subject))?;
        ensure!(output.status.success(), "logind query failed");
        String::from_utf8(output.stdout).context("invalid logind response")
    };
    let user = query(&["show-user", &subject.uid.to_string(), "--property=Display"])?;
    let p = properties(&user)?;
    let id = *p.get("Display").context("no desktop session")?;
    ensure!(session_id(id), "no valid desktop session");
    let text = query(&[
        "show-session",
        id,
        "--property=User",
        "--property=Active",
        "--property=Remote",
        "--property=LockedHint",
        "--property=Type",
        "--property=Display",
        "--property=Leader",
    ])?;
    let mut session = parse_session(id, &text, subject.uid)?;
    session.leader_start = stat_start_time(
        &read_bounded(
            &PathBuf::from(format!("/proc/{}/stat", session.leader)),
            PROC_LIMIT,
        )?,
        session.leader,
    )?;
    // A leader may be a root-owned display manager (e.g. greetd), not the user.
    Ok(session)
}

/// Only :N or :N.S; no hostnames, protocol prefixes, whitespace or remote TCP.
fn local_display(value: &str) -> Option<u32> {
    let rest = value.strip_prefix(':')?;
    let mut parts = rest.split('.');
    let number = parts.next()?;
    let valid_number =
        |s: &str| !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit());
    if !valid_number(number) {
        return None;
    }
    if let Some(screen) = parts.next() {
        if !valid_number(screen) {
            return None;
        }
    }
    if parts.next().is_some() {
        return None;
    }
    number.parse().ok()
}

struct Account {
    gid: u32,
    home: PathBuf,
    name: OsString,
}

fn account(uid: u32) -> Result<Account> {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let code = unsafe {
        libc::getpwuid_r(
            uid,
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    ensure!(
        code == 0 && !result.is_null(),
        "desktop user not found in passwd"
    );
    let passwd = unsafe { passwd.assume_init() };
    ensure!(
        passwd.pw_uid == uid && !passwd.pw_dir.is_null() && !passwd.pw_name.is_null(),
        "invalid passwd entry"
    );
    let home = PathBuf::from(OsString::from_vec(
        unsafe { CStr::from_ptr(passwd.pw_dir) }.to_bytes().to_vec(),
    ));
    ensure!(
        home.is_absolute() && home != Path::new("/"),
        "invalid desktop home"
    );
    let name = OsString::from_vec(
        unsafe { CStr::from_ptr(passwd.pw_name) }
            .to_bytes()
            .to_vec(),
    );
    Ok(Account {
        gid: passwd.pw_gid,
        home,
        name,
    })
}

fn desktop_environment(
    subject: &Subject,
    session: &Session,
    account: &Account,
) -> Result<Vec<(OsString, OsString)>> {
    verify_subject(subject)?;
    let data = read_bounded(
        &PathBuf::from(format!("/proc/{}/environ", subject.pid)),
        PROC_LIMIT,
    )?;
    let mut display = None;
    let mut authority = None;
    // Do not decode, forward, or log unrelated environment variables.
    for entry in data.split(|b| *b == 0) {
        if let Some(value) = entry.strip_prefix(b"DISPLAY=") {
            ensure!(display.is_none(), "duplicate subject DISPLAY");
            display = Some(std::str::from_utf8(value)?.to_owned());
        } else if let Some(value) = entry.strip_prefix(b"XAUTHORITY=") {
            ensure!(authority.is_none(), "duplicate subject XAUTHORITY");
            authority = Some(PathBuf::from(OsString::from_vec(value.to_vec())));
        }
    }
    verify_subject(subject)?;
    let display = if session.display.is_empty() {
        display.context("subject has no local display")?
    } else {
        if let Some(ref value) = display {
            ensure!(
                value == &session.display,
                "subject display differs from logind"
            );
        }
        session.display.clone()
    };
    let number = local_display(&display).context("subject display is not local")?;
    let socket_dir = fs::symlink_metadata("/tmp/.X11-unix")?;
    ensure!(
        socket_dir.is_dir() && socket_dir.uid() == 0 && socket_dir.mode() & libc::S_ISVTX != 0,
        "unsafe X11 socket directory"
    );
    let socket = fs::symlink_metadata(format!("/tmp/.X11-unix/X{number}"))?;
    ensure!(
        socket.file_type().is_socket() && (socket.uid() == subject.uid || socket.uid() == 0),
        "no trusted local X11 socket"
    );
    let authority = authority.unwrap_or_else(|| account.home.join(".Xauthority"));
    ensure!(authority.is_absolute(), "Xauthority path must be absolute");
    let authority = fs::canonicalize(authority).context("Xauthority is unavailable")?;
    let runtime = PathBuf::from(format!("/run/user/{}", subject.uid));
    let home = fs::canonicalize(&account.home)?;
    ensure!(
        authority.starts_with(&home) || authority.starts_with(&runtime),
        "Xauthority must be in user home or runtime directory"
    );
    let meta = fs::metadata(&authority)?;
    ensure!(
        meta.is_file()
            && meta.uid() == subject.uid
            && meta.mode() & 0o022 == 0
            && meta.len() <= 1024 * 1024,
        "unsafe Xauthority file"
    );
    let mut env = vec![
        ("HOME".into(), account.home.as_os_str().to_owned()),
        ("USER".into(), account.name.clone()),
        ("LOGNAME".into(), account.name.clone()),
        ("DISPLAY".into(), display.into()),
        ("XAUTHORITY".into(), authority.into_os_string()),
        ("GDK_BACKEND".into(), "x11".into()),
    ];
    if let Ok(meta) = fs::symlink_metadata(&runtime) {
        ensure!(
            meta.is_dir() && meta.uid() == subject.uid && meta.mode() & 0o077 == 0,
            "unsafe desktop runtime directory"
        );
        env.push(("XDG_RUNTIME_DIR".into(), runtime.as_os_str().to_owned()));
        if let Ok(bus) = fs::symlink_metadata(runtime.join("bus")) {
            ensure!(
                bus.file_type().is_socket() && bus.uid() == subject.uid,
                "unsafe desktop bus"
            );
            env.push((
                "DBUS_SESSION_BUS_ADDRESS".into(),
                format!("unix:path={}/bus", runtime.display()).into(),
            ));
        }
    }
    Ok(env)
}

fn escaped_label(input: &str) -> String {
    let mut output = String::new();
    for (index, c) in input.chars().enumerate() {
        if index == 256 {
            output.push('…');
            break;
        }
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            // Also neutralize bidi and zero-width formatting that can spoof labels.
            c if c.is_control()
                || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}') =>
            {
                output.push('�')
            }
            c => output.push(c),
        }
    }
    output
}

/// Resolve every symlink hop, checking both original and resolved ancestors.
/// This accepts immutable root-owned Nix store executables, not user profiles.
fn trusted_executable(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "helper path must be absolute");
    let mut pending = path.to_path_buf();
    let mut links = 0;
    'resolve: loop {
        let components: Vec<_> = pending.components().collect();
        let mut resolved = PathBuf::from("/");
        let root = fs::symlink_metadata(&resolved)?;
        ensure!(
            root.uid() == 0 && root.mode() & 0o022 == 0,
            "untrusted helper root"
        );
        for (index, component) in components.iter().enumerate() {
            match component {
                Component::RootDir => continue,
                Component::Normal(name) => resolved.push(name),
                Component::ParentDir => {
                    resolved.pop();
                    continue;
                }
                Component::CurDir => continue,
                _ => bail!("helper path contains non-normal components"),
            }
            let meta = fs::symlink_metadata(&resolved).context("helper path unavailable")?;
            ensure!(meta.uid() == 0, "helper path is not root owned");
            if meta.file_type().is_symlink() {
                links += 1;
                ensure!(links <= 40, "too many helper symlinks");
                let target = fs::read_link(&resolved)?;
                let mut next = if target.is_absolute() {
                    target
                } else {
                    resolved.parent().unwrap().join(target)
                };
                for component in &components[index + 1..] {
                    next.push(component.as_os_str());
                }
                // Traverse and check the target before interpreting any '..';
                // canonicalize() alone would hide insecure intermediate links.
                pending = next;
                continue 'resolve;
            }
            ensure!(
                meta.mode() & 0o022 == 0,
                "helper path is writable by non-root"
            );
            if index + 1 == components.len() {
                ensure!(
                    meta.is_file() && meta.mode() & 0o111 != 0 && meta.mode() & 0o6000 == 0,
                    "helper is not a regular non-set-ID executable"
                );
                return Ok(resolved);
            }
            ensure!(meta.is_dir(), "helper ancestor is not a directory");
        }
        bail!("helper path is not an executable");
    }
}

fn clean_command(path: &Path) -> Command {
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn prepare_child(command: &mut Command, identity: Option<(u32, u32)>) {
    let parent_pid = unsafe { libc::getpid() };
    // pre_exec uses only async-signal-safe syscalls, with no allocations/locks.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            // CLOEXEC preserves Rust's exec-error pipe until exec succeeds. Fail
            // closed on kernels without close_range (Linux >= 5.11 required).
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if let Some((uid, gid)) = identity {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            // Credential changes clear PDEATHSIG, so install it afterward.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(io::Error::from_raw_os_error(libc::ECANCELED));
            }
            Ok(())
        });
    }
}

struct Output {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
struct Running {
    child: Child,
    reaped: bool,
}
impl Running {
    fn kill_and_reap(&mut self) -> io::Result<ExitStatus> {
        // The direct child has NOT been reaped: its PID/process-group ID cannot
        // have been recycled into an unrelated process, even on normal exit.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill_and_reap();
        }
    }
}

fn run(command: &mut Command, deadline: Instant, subject: Option<&Subject>) -> Result<Output> {
    ensure!(Instant::now() < deadline, "authentication timed out");
    let mut child = Running {
        child: command
            .spawn()
            .context("cannot start authentication helper")?,
        reaped: false,
    };
    let mut stdout = child.child.stdout.take().context("helper stdout missing")?;
    let mut stderr = child.child.stderr.take().context("helper stderr missing")?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        ensure!(
            flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
            "cannot configure helper output"
        );
    }
    let mut data = Vec::new();
    let mut diagnostics = Vec::new();
    let mut checked = Instant::now();
    loop {
        ensure!(Instant::now() < deadline, "authentication timed out");
        if checked.elapsed() >= Duration::from_millis(100) {
            if let Some(subject) = subject {
                verify_subject(subject)?;
            }
            checked = Instant::now();
        }
        drain(&mut stdout, &mut data)?;
        drain(&mut stderr, &mut diagnostics)?;
        // WNOWAIT retains the child PID until we have killed its process group.
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if unsafe { info.si_pid() } != 0 {
            let status = child.kill_and_reap()?;
            drain(&mut stdout, &mut data)?;
            drain(&mut stderr, &mut diagnostics)?;
            return Ok(Output {
                status,
                stdout: data,
                stderr: diagnostics,
            });
        }
        thread::sleep(
            Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

fn drain(reader: &mut impl Read, output: &mut Vec<u8>) -> Result<()> {
    let mut buffer = [0; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                ensure!(
                    output.len() + n <= OUTPUT_LIMIT,
                    "helper output exceeds size limit"
                );
                output.extend_from_slice(&buffer[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn defaults_are_absolute_and_bounded() {
        let c = Config::default();
        assert_eq!(c.zenity, Path::new("/usr/bin/zenity"));
        assert_eq!(c.pkcheck, Path::new("/usr/bin/pkcheck"));
        assert_eq!(c.loginctl, Path::new("/usr/bin/loginctl"));
        assert_eq!(c.timeout, Duration::from_secs(60));
        assert!(
            deadline(&Config {
                timeout: Duration::ZERO,
                ..c
            })
            .is_err()
        );
    }

    #[test]
    fn display_is_strictly_local() {
        for display in [":0", ":1", ":1.0", ":123.45"] {
            assert!(local_display(display).is_some());
        }
        for display in [
            "",
            ":",
            "localhost:1",
            "host:0",
            "unix:0",
            "unix/:0",
            ":1.0.0",
            ":-1",
            ":1\n",
            ":1 ",
            ":999999",
            ":1.",
            ":.0",
        ] {
            assert!(local_display(display).is_none(), "{display:?}");
        }
    }

    #[test]
    fn labels_are_escaped_bounded_and_not_spoofable() {
        assert_eq!(
            escaped_label("<&>\"'\n\u{202e}"),
            "&lt;&amp;&gt;&quot;&apos;��"
        );
        assert_eq!(
            escaped_label(&"a".repeat(257)),
            format!("{}…", "a".repeat(256))
        );
        assert_eq!(escaped_label("café"), "café");
    }

    fn session_text() -> &'static str {
        "User=1000\nActive=yes\nRemote=no\nLockedHint=no\nType=x11\nDisplay=\nLeader=123\n"
    }

    #[test]
    fn session_accepts_greetd_empty_display_but_requires_all_checks() {
        let session = parse_session("62", session_text(), 1000).unwrap();
        assert_eq!(session.display, "");
        assert_eq!(session.leader, 123);
        assert!(
            parse_session(
                "62",
                &session_text().replace("Display=", "Display=:1"),
                1000
            )
            .is_ok()
        );
        for (old, new) in [
            ("User=1000", "User=1001"),
            ("Active=yes", "Active=no"),
            ("Remote=no", "Remote=yes"),
            ("LockedHint=no", "LockedHint=yes"),
            ("LockedHint=no\n", ""),
            ("Type=x11", "Type=tty"),
            ("Type=x11", "Type=wayland"),
            ("Leader=123", "Leader=0"),
            ("Display=", "Display=remote:0"),
        ] {
            assert!(
                parse_session("62", &session_text().replace(old, new), 1000).is_err(),
                "{new}"
            );
        }
        assert!(parse_session("--all", session_text(), 1000).is_err());
        assert!(parse_session("62", &format!("{}Active=yes\n", session_text()), 1000).is_err());
        assert!(!session_id(""));
    }

    #[test]
    fn installed_pkcheck_accepts_the_details_flag() {
        if !Path::new("/usr/bin/pkcheck").exists() {
            return;
        }
        // Parsing only: no subject/action/interaction, so no auth request occurs.
        // polkit 124's help advertises --details but its parser accepts -d or
        // --detail; exercise the real parser instead of trusting the help text.
        let output = Command::new("/usr/bin/pkcheck")
            .args(["-d", "example", "value"])
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostic.contains("Subject not specified"),
            "unexpected pkcheck argument behavior: {diagnostic}"
        );
    }

    #[test]
    fn actions_and_subjects_are_exact() {
        for action in [READ_ACTION, REPLACE_ACTION, DELETE_ACTION] {
            validate_action(action).unwrap();
        }
        for action in [
            "",
            "org.freedesktop.policykit.exec",
            "io.github.from-nibly.agent-keyring.read_keep",
        ] {
            assert!(validate_action(action).is_err());
        }
        let subject = Subject {
            pid: 12,
            uid: 1000,
            start_time: 456,
        };
        assert_eq!(subject_argument(&subject).unwrap(), "12,456,1000");
        for invalid in [
            Subject {
                pid: -1,
                ..subject.clone()
            },
            Subject {
                uid: 0,
                ..subject.clone()
            },
            Subject {
                start_time: 0,
                ..subject
            },
        ] {
            assert!(subject_argument(&invalid).is_err());
        }
    }

    #[test]
    fn proc_stat_handles_spaces_and_parentheses() {
        let fields = format!("S {} 4242 0", "0 ".repeat(18));
        assert_eq!(
            stat_start_time(format!("123 (awk ) with spaces) {fields}").as_bytes(), 123).unwrap(),
            4242
        );
        assert!(stat_start_time(b"123 (dead) Z 0", 123).is_err());
        assert!(stat_start_time(b"12 (name) S 0", 123).is_err());
    }

    #[test]
    fn subject_identity_is_checked_against_proc() {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return;
        } // tests never need a root invocation
        let pid = std::process::id() as i32;
        let start_time = stat_start_time(
            &read_bounded(&PathBuf::from(format!("/proc/{pid}/stat")), PROC_LIMIT).unwrap(),
            pid,
        )
        .unwrap();
        let subject = Subject {
            pid,
            uid,
            start_time,
        };
        verify_subject(&subject).unwrap();
        assert!(
            verify_subject(&Subject {
                start_time: start_time + 1,
                ..subject.clone()
            })
            .is_err()
        );
        assert!(
            verify_subject(&Subject {
                uid: uid + 1,
                ..subject
            })
            .is_err()
        );
    }

    #[test]
    fn unsafe_helpers_are_rejected_without_a_test_bypass() {
        assert!(trusted_executable(Path::new("zenity")).is_err());
        assert!(trusted_executable(Path::new("/tmp/../usr/bin/true")).is_err());
        assert!(trusted_executable(Path::new("/usr/bin")).is_err());
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("helper");
        fs::write(&path, b"not an executable").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(trusted_executable(&path).is_err());
        let link = temp.path().join("link");
        std::os::unix::fs::symlink("/usr/bin/true", &link).unwrap();
        assert!(trusted_executable(&link).is_err());
    }

    #[test]
    fn installed_root_owned_helpers_are_accepted() {
        for path in ["/usr/bin/true", "/bin/true"] {
            let resolved = trusted_executable(Path::new(path)).unwrap();
            assert_eq!(resolved, fs::canonicalize(path).unwrap());
        }
    }

    #[test]
    fn passwd_lookup_uses_system_identity() {
        let uid = unsafe { libc::getuid() };
        let account = account(uid).unwrap();
        assert!(account.home.is_absolute());
        assert!(!account.name.is_empty());
        assert_ne!(account.gid, u32::MAX);
    }

    #[test]
    fn child_environment_does_not_inherit_variables() {
        let command = clean_command(Path::new("/usr/bin/true"));
        let vars: Vec<_> = command
            .get_envs()
            .map(|(k, _)| k.to_str().unwrap())
            .collect();
        assert_eq!(vars, ["LANG", "LC_ALL", "PATH"]);
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
    }

    #[test]
    fn output_is_bounded() {
        assert!(drain(&mut &vec![b'x'; OUTPUT_LIMIT + 1][..], &mut Vec::new()).is_err());
    }

    #[test]
    fn subprocess_timeout_kills_and_reaps() {
        let mut command = clean_command(Path::new("/usr/bin/sleep"));
        command.arg("10");
        prepare_child(&mut command, None);
        let start = Instant::now();
        let error = run(&mut command, start + Duration::from_millis(50), None)
            .err()
            .unwrap();
        assert!(error.to_string().contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn cancelled_child_is_reaped() {
        let mut command = clean_command(Path::new("/usr/bin/sleep"));
        command.arg("10");
        prepare_child(&mut command, None);
        let child = Running {
            child: command.spawn().unwrap(),
            reaped: false,
        };
        let pid = child.child.id() as i32;
        drop(child);
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn child_has_only_sanitized_environment() {
        let mut command = clean_command(Path::new("/usr/bin/env"));
        prepare_child(&mut command, None);
        let result = run(&mut command, Instant::now() + Duration::from_secs(2), None).unwrap();
        assert!(result.status.success());
        let mut lines: Vec<_> = std::str::from_utf8(&result.stdout)
            .unwrap()
            .lines()
            .collect();
        lines.sort_unstable();
        assert_eq!(
            lines,
            ["LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin"]
        );
    }

    #[test]
    fn extra_file_descriptors_do_not_survive_exec() {
        let file = File::open("/dev/null").unwrap();
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 200) };
        assert!(fd >= 200);
        // This duplicate deliberately lacks CLOEXEC, like an inherited daemon FD.
        let probe = thread::current().name().unwrap().replace(
            "extra_file_descriptors_do_not_survive_exec",
            "inherited_fd_probe",
        );
        let mut command = clean_command(&std::env::current_exe().unwrap());
        command.args(["--exact", &probe]);
        command.env("AUTH_TEST_FD", fd.to_string());
        prepare_child(&mut command, None);
        let result = run(&mut command, Instant::now() + Duration::from_secs(2), None);
        unsafe {
            libc::close(fd);
        }
        let result = result.unwrap();
        assert!(result.status.success());
        assert!(
            std::str::from_utf8(&result.stdout)
                .unwrap()
                .contains("1 passed")
        );
    }

    #[test]
    fn inherited_fd_probe() {
        if let Ok(fd) = std::env::var("AUTH_TEST_FD") {
            let fd: i32 = fd.parse().unwrap();
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
    }

    #[test]
    fn ordinary_child_is_collected() {
        let mut command = clean_command(Path::new("/usr/bin/printf"));
        command.args(["%s", "literal $(not a shell) ; <&>"]);
        prepare_child(&mut command, None);
        let result = run(&mut command, Instant::now() + Duration::from_secs(2), None).unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"literal $(not a shell) ; <&>");
    }
}
