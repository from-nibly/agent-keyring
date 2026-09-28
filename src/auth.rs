//! Host-desktop authorization, not a sandbox or an agent-elevation mechanism.
//!
//! GUI output is only an untrusted preference. `approve_read` independently checks
//! EVERY new Once/Run grant; `authorize` handles overwrites/deletes independently.
//! Each check binds the key, root process identity, scope and secret version.
//! It must independently revalidate ancestry/version before committing the operation.
//! Install the three actions with `auth_admin` (NEVER `*_keep`), and deny inactive
//! and remote sessions. Root-owned polkit rules must not bypass those defaults:
//! pkcheck cannot distinguish a rule returning YES from fresh authentication.
//!
//! This deliberately trusts root and the host desktop. X11 clients can spoof or
//! observe dialogs; same-UID processes can tamper with the GUI and its environment.
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
use std::os::unix::io::{AsRawFd, FromRawFd};
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
    pub approval_agent: PathBuf,
    pub pkcheck: PathBuf,
    pub loginctl: PathBuf,
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            approval_agent: "/usr/local/libexec/agent-keyring-approval".into(),
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

const MAX_CHOICES: u32 = 16;
const PROTOCOL_LIMIT: usize = 512;
const LINE_LIMIT: usize = 32;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Cleanup could not be proved. The broker must retain its per-UID prompt guard
/// until daemon restart rather than permit a second, potentially overlapping UI.
#[derive(Debug)]
pub struct CleanupError;
impl std::fmt::Display for CleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("approval cleanup could not be confirmed; user prompts fenced")
    }
}
impl std::error::Error for CleanupError {}

#[derive(Debug)]
struct ApprovalClosed;
impl std::fmt::Display for ApprovalClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("approval window closed")
    }
}
impl std::error::Error for ApprovalClosed {}

// Called only after cleanup is proved: window closure is denial, whereas a
// malformed stream or unavailable service remains an operational error.
fn approval_outcome(result: Result<Option<GrantChoice>>) -> Result<Option<GrantChoice>> {
    match result {
        Err(error) if error.is::<ApprovalClosed>() => Ok(None),
        result => result,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Attempt {
    sequence: u32,
    scope: GrantChoice,
}

#[derive(Default)]
struct ApprovalParser {
    ready: bool,
    sequence: u32,
    total: usize,
    line: Vec<u8>,
}
impl ApprovalParser {
    fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Attempt>> {
        self.total = self.total.saturating_add(bytes.len());
        ensure!(
            self.total <= PROTOCOL_LIMIT,
            "approval protocol limit exceeded"
        );
        let mut choices = Vec::new();
        for &byte in bytes {
            if byte == b'\n' {
                if !self.ready {
                    ensure!(self.line == b"READY", "invalid approval protocol order");
                    self.ready = true;
                } else {
                    if self.line == b"CANCEL" {
                        return Err(ApprovalClosed.into());
                    }
                    let sequence = self.sequence + 1;
                    ensure!(sequence <= MAX_CHOICES, "too many approval choices");
                    let scope = if self.line == format!("CHOICE {sequence} once").as_bytes() {
                        GrantChoice::Once
                    } else if self.line == format!("CHOICE {sequence} run").as_bytes() {
                        GrantChoice::Run
                    } else {
                        // Never include untrusted stdout in errors or daemon logs.
                        bail!("invalid approval protocol record");
                    };
                    ensure!(
                        sequence != 1 || scope == GrantChoice::Once,
                        "invalid initial approval scope"
                    );
                    self.sequence = sequence;
                    choices.push(Attempt { sequence, scope });
                }
                self.line.clear();
            } else {
                ensure!(
                    byte.is_ascii_graphic() || byte == b' ',
                    "invalid approval protocol byte"
                );
                ensure!(
                    self.line.len() < LINE_LIMIT,
                    "approval protocol line too long"
                );
                self.line.push(byte);
            }
        }
        Ok(choices)
    }
}

// This boundary also permits deterministic scheduling tests without any real
// authentication requests, GUI windows or user-manager state.
trait ApprovalIo {
    fn observe_gui(&mut self, parser: &mut ApprovalParser) -> Result<Vec<Attempt>>;
    fn stop_check(&mut self) -> Result<()>;
    fn start_check(&mut self, attempt: Attempt) -> Result<()>;
    fn check_result(&mut self) -> Result<Option<bool>>;
}

fn apply_choices(
    io: &mut impl ApprovalIo,
    current: &mut Option<Attempt>,
    choices: Vec<Attempt>,
) -> Result<()> {
    for attempt in choices {
        // Invalidate FIRST, including an already-exited successful old child.
        *current = None;
        io.stop_check()?;
        io.start_check(attempt)?;
        *current = Some(attempt);
    }
    Ok(())
}

fn approval_tick(
    io: &mut impl ApprovalIo,
    parser: &mut ApprovalParser,
    current: &mut Option<Attempt>,
    now: Instant,
    deadline: Instant,
) -> Result<Option<Option<GrantChoice>>> {
    ensure!(now < deadline, "authentication timed out");
    let choices = io.observe_gui(parser)?;
    apply_choices(io, current, choices)?;
    let Some(attempt) = *current else {
        return Ok(None);
    };
    let Some(success) = io.check_result()? else {
        return Ok(None);
    };
    // Observe cancellation/changes once more AFTER collecting status. A partial
    // record also blocks commitment, rather than authorizing over its prefix.
    let choices = io.observe_gui(parser)?;
    apply_choices(io, current, choices)?;
    if *current != Some(attempt) || !parser.line.is_empty() {
        return Ok(None);
    }
    Ok(Some(success.then_some(attempt.scope)))
}

/// One GUI, one absolute deadline, and at most one independent root check.
/// Returns only the immutable scope of the successful current check, never a
/// preference. Both messages are authored by the broker from pinned metadata.
pub fn approve_read(
    config: &Config,
    subject: &Subject,
    once_message: &str,
    run_message: &str,
) -> Result<Option<GrantChoice>> {
    require_root()?;
    validate_message(once_message)?;
    validate_message(run_message)?;
    let deadline = deadline(config)?;
    verify_subject(subject)?;
    let session = active_session(config, subject, deadline)?;
    let account = account(subject.uid)?;
    let environment = desktop_environment(subject, &session, &account)?;
    ensure!(
        environment
            .iter()
            .any(|(k, _)| k == "DBUS_SESSION_BUS_ADDRESS"),
        "desktop user manager unavailable"
    );
    let agent = trusted_executable(&config.approval_agent)?;
    let runner = trusted_executable(Path::new("/usr/bin/systemd-run"))?;
    let systemctl = trusted_executable(Path::new("/usr/bin/systemctl"))?;
    let env = trusted_executable(Path::new("/usr/bin/env"))?;
    let pkcheck = trusted_executable(&config.pkcheck)?;
    let request_id = request_id()?;
    let unit = format!("agent-keyring-approval-{request_id}.service");
    let mut command = approval_command(
        &runner,
        &env,
        &agent,
        subject,
        &environment,
        &unit,
        &request_id,
        once_message,
        run_message,
        config.timeout.as_secs().max(1),
    );
    let (input, liveness) = liveness_pipe()?;
    command.stdin(Stdio::from(input));
    prepare_child(&mut command, Some((subject.uid, account.gid)));
    ensure!(Instant::now() < deadline, "authentication timed out");
    let mut launcher = Running {
        child: command.spawn().context("cannot start approval service")?,
        reaped: false,
    };
    // Command retains the parent's read-end, not the private write capability.
    drop(command);
    let mut live = Some(liveness);
    let mut parser = ApprovalParser::default();
    let mut current = None;
    let mut check = None;
    let result: Result<Option<GrantChoice>> = (|| {
        let mut stdout = launcher
            .child
            .stdout
            .take()
            .context("approval stdout missing")?;
        nonblocking(stdout.as_raw_fd())?;
        let mut checked = Instant::now();
        let mut io = LiveApproval {
            launcher: &mut launcher,
            stdout: &mut stdout,
            check: &mut check,
            pkcheck: &pkcheck,
            subject,
            once_message,
            run_message,
            request_id: &request_id,
            deadline,
        };
        loop {
            if checked.elapsed() >= Duration::from_millis(100) {
                verify_subject(subject)?;
                checked = Instant::now();
            }
            if let Some(result) =
                approval_tick(&mut io, &mut parser, &mut current, Instant::now(), deadline)?
            {
                return Ok(result);
            }
            thread::sleep(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })();
    // Closing the sole writer is mandatory even on parser, launch or check error.
    drop(live.take());
    current.take();
    let check_settled = stop_check(&mut check).is_ok();
    let gui_settled = settle_gui(&mut launcher, &unit, parser.ready, |args| {
        let mut command = clean_command(&systemctl);
        command.envs(environment.iter().cloned());
        command
            .args(["--user", "--no-pager", "--no-ask-password"])
            .args(args);
        prepare_child(&mut command, Some((subject.uid, account.gid)));
        run(&mut command, Instant::now() + Duration::from_secs(4), None)
    });
    if !check_settled || gui_settled.is_err() {
        return Err(CleanupError.into());
    }
    let result = approval_outcome(result)?;
    verify_subject(subject)?;
    ensure!(
        active_session(config, subject, deadline)? == session,
        "desktop session changed"
    );
    ensure!(Instant::now() < deadline, "authentication timed out");
    Ok(result)
}

fn request_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn liveness_pipe() -> Result<(File, File)> {
    let mut fds = [-1; 2];
    ensure!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == 0,
        "cannot create approval liveness pipe"
    );
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

#[allow(clippy::too_many_arguments)]
fn approval_command(
    runner: &Path,
    env: &Path,
    agent: &Path,
    subject: &Subject,
    environment: &[(OsString, OsString)],
    unit: &str,
    request_id: &str,
    once_message: &str,
    run_message: &str,
    timeout: u64,
) -> Command {
    let mut command = clean_command(runner);
    command
        .envs(environment.iter().cloned())
        .stderr(Stdio::null());
    command.args([
        "--user", "--pipe", "--wait", "--collect", "--quiet", "--no-ask-password",
        "--service-type=exec", "--expand-environment=no", "--unit", unit,
        "--property=LimitCORE=0", "--property=Restart=no", "--property=WorkingDirectory=/",
        "--property=TimeoutStartSec=5s", "--property=TimeoutStopSec=2s",
        "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
        "--property=UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_DEBUG_OUTPUT LD_PROFILE LD_ORIGIN_PATH LD_ASSUME_KERNEL LD_DYNAMIC_WEAK LD_BIND_NOW LD_BIND_NOT LD_HWCAP_MASK LD_SHOW_AUXV LD_USE_LOAD_BIAS GLIBC_TUNABLES GCONV_PATH LOCPATH POLKIT_DEBUG",
    ]);
    command.arg(format!("--property=RuntimeMaxSec={timeout}s"));
    command
        .arg("--")
        .arg(env)
        .args(["-i", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin"]);
    for (name, value) in environment {
        let mut assignment = name.clone();
        assignment.push("=");
        assignment.push(value);
        command.arg(assignment);
    }
    command
        .arg(agent)
        .arg("--pid")
        .arg(subject.pid.to_string())
        .arg("--start-time")
        .arg(subject.start_time.to_string())
        .arg("--uid")
        .arg(subject.uid.to_string())
        .arg("--request-id")
        .arg(request_id)
        .arg("--once-message")
        .arg(once_message)
        .arg("--run-message")
        .arg(run_message)
        .arg("--timeout-seconds")
        .arg(timeout.to_string());
    command
}

struct LiveApproval<'a> {
    launcher: &'a mut Running,
    stdout: &'a mut std::process::ChildStdout,
    check: &'a mut Option<Running>,
    pkcheck: &'a Path,
    subject: &'a Subject,
    once_message: &'a str,
    run_message: &'a str,
    request_id: &'a str,
    deadline: Instant,
}
impl ApprovalIo for LiveApproval<'_> {
    fn observe_gui(&mut self, parser: &mut ApprovalParser) -> Result<Vec<Attempt>> {
        let mut choices = Vec::new();
        let mut buffer = [0u8; 128];
        loop {
            match self.stdout.read(&mut buffer) {
                Ok(0) => {
                    ensure!(
                        parser.line.is_empty(),
                        "incomplete approval protocol record"
                    );
                    return Err(ApprovalClosed.into());
                }
                Ok(n) => choices.extend(parser.feed(&buffer[..n])?),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => bail!("approval protocol unavailable"),
            }
        }
        ensure!(!self.launcher.exited()?, "approval service exited");
        Ok(choices)
    }
    fn stop_check(&mut self) -> Result<()> {
        stop_check(self.check)
    }
    fn start_check(&mut self, attempt: Attempt) -> Result<()> {
        ensure!(Instant::now() < self.deadline, "authentication timed out");
        ensure!(self.check.is_none(), "overlapping authorization checks");
        let message = match attempt.scope {
            GrantChoice::Once => self.once_message,
            GrantChoice::Run => self.run_message,
        };
        let message = format!(
            "{message}\n\nRequest: {}/{}",
            self.request_id, attempt.sequence
        );
        let mut command = check_command(self.pkcheck, self.subject, READ_ACTION, &message)?;
        command.stdout(Stdio::null()).stderr(Stdio::null());
        *self.check = Some(Running {
            child: command
                .spawn()
                .context("cannot start authorization check")?,
            reaped: false,
        });
        Ok(())
    }
    fn check_result(&mut self) -> Result<Option<bool>> {
        let Some(check) = self.check.as_mut() else {
            return Ok(None);
        };
        if !check.exited()? {
            return Ok(None);
        }
        // Retain the collected status while a fragmented next GUI record arrives.
        let status = check.kill_and_reap().map_err(|_| CleanupError)?;
        match status.code() {
            Some(0) => Ok(Some(true)),
            Some(1..=3) => Ok(Some(false)),
            _ => bail!("polkit authorization check failed"),
        }
    }
}

fn stop_check(check: &mut Option<Running>) -> Result<()> {
    if let Some(mut child) = check.take() {
        child.kill_and_reap().map_err(|_| CleanupError)?;
    }
    Ok(())
}

fn settle_gui(
    launcher: &mut Running,
    unit: &str,
    ready: bool,
    mut query: impl FnMut(&[&str]) -> Result<Output>,
) -> Result<()> {
    let grace = Instant::now() + Duration::from_millis(200);
    while matches!(launcher.exited(), Ok(false)) && Instant::now() < grace {
        thread::sleep(Duration::from_millis(10));
    }
    let exited = launcher.exited().unwrap_or(false);
    // No late launcher submission may follow our exact-unit stop request. Still
    // attempt manager cleanup if reaping fails, but never report that as settled.
    let launcher_status = launcher.kill_and_reap();
    let completed = exited && launcher_status.as_ref().is_ok_and(ExitStatus::success);
    let stopped = query(&["stop", "--", unit]);
    let state = query(&[
        "show",
        "--property=LoadState",
        "--property=ActiveState",
        "--",
        unit,
    ])?;
    ensure!(launcher_status.is_ok(), "approval launcher cleanup unknown");
    let stopped = stopped?;
    ensure!(
        state.status.success(),
        "cannot confirm approval service state"
    );
    let text = std::str::from_utf8(&state.stdout).context("invalid service state")?;
    let props = properties(text)?;
    let absent = props.get("LoadState") == Some(&"not-found");
    ensure!(
        props.get("ActiveState") == Some(&"inactive") && (stopped.status.success() || absent),
        "approval service not settled"
    );
    // Without READY or successful --wait completion, an interrupted/failed
    // launcher may have lost its bus during submission. An absent unit alone
    // cannot rule out a still-pending activation on that previous connection.
    ensure!(ready || completed, "approval startup settlement unknown");
    Ok(())
}

fn validate_message(message: &str) -> Result<()> {
    ensure!(
        !message.is_empty() && message.len() <= 8192,
        "invalid authorization message length"
    );
    ensure!(
        !message.chars().any(|c| c.is_control() && c != '\n'),
        "invalid authorization message"
    );
    Ok(())
}

/// Independently ask polkit for authorization, as root, for the authenticated
/// socket peer. Do not use a GUI child or the daemon as the polkit subject.
/// `message` must explain the exact key/root/choice/version being authorized.
/// No successful result is cached here. The policy MUST require auth_admin.
pub fn authorize(config: &Config, subject: &Subject, action: &str, message: &str) -> Result<bool> {
    require_root()?;
    validate_action(action)?;
    validate_message(message)?;
    let deadline = deadline(config)?;
    verify_subject(subject)?;
    let session = active_session(config, subject, deadline)?;
    let mut command = check_command(
        &trusted_executable(&config.pkcheck)?,
        subject,
        action,
        message,
    )?;
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
            "polkit authorization check failed ({:?})",
            output.status.code()
        ),
    }
}

fn check_command(path: &Path, subject: &Subject, action: &str, message: &str) -> Result<Command> {
    let mut command = clean_command(path);
    command.args([
        "--action-id",
        action,
        "--process",
        &subject_argument(subject)?,
        "--allow-user-interaction",
        "-d",
        "polkit.message",
        message,
    ]);
    // No internal agent, shell, GUI credentials, or inherited D-Bus address.
    prepare_child(&mut command, None);
    Ok(command)
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
    ensure!(
        !config.timeout.is_zero() && config.timeout <= Duration::from_secs(300),
        "invalid authentication timeout"
    );
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

fn desktop_data_dirs(home: &Path) -> Result<OsString> {
    // The user GUI may load themes/icons from Home Manager. Do not pass this
    // search path to root polkit checks or inherit arbitrary loader variables.
    std::env::join_paths([
        home.join(".nix-profile/share"),
        PathBuf::from("/usr/local/share"),
        PathBuf::from("/usr/share"),
    ])
    .context("invalid desktop data path")
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
        ("XDG_DATA_DIRS".into(), desktop_data_dirs(&account.home)?),
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

fn trusted_helper_mode(mode: u32) -> bool {
    mode & 0o022 == 0 || (mode & libc::S_IFMT == libc::S_IFDIR && mode & libc::S_ISVTX != 0)
}

/// Resolve every symlink hop, checking both original and resolved ancestors.
/// This accepts immutable root-owned Nix store executables, not user profiles.
fn trusted_executable(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "helper path must be absolute");
    ensure!(
        !path.components().any(|c| matches!(c, Component::ParentDir)),
        "helper path must not contain traversal"
    );
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
            // Root ownership was checked above. A sticky root-owned ancestor
            // (notably /nix/store) cannot have its root-owned entries replaced
            // by the other users allowed to create siblings there.
            ensure!(
                trusted_helper_mode(meta.mode()),
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
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
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
}
struct Running {
    child: Child,
    reaped: bool,
}
impl Running {
    fn exited(&self) -> io::Result<bool> {
        if self.reaped {
            return Ok(true);
        }
        // WNOWAIT pins the process-group identity until cleanup, even at exit 0.
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        loop {
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                return Ok(unsafe { info.si_pid() } != 0);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    fn kill_and_reap(&mut self) -> io::Result<ExitStatus> {
        // Child::wait caches a previously collected status. Never signal its
        // potentially recycled PID/group a second time.
        if self.reaped {
            return self.child.wait();
        }
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while !self.exited()? {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "helper cleanup timed out",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
        let status = self.child.wait()?; // WNOWAIT proved this cannot block.
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
    let result = (|| {
        let mut stdout = child.child.stdout.take().context("helper stdout missing")?;
        let mut stderr = child.child.stderr.take().context("helper stderr missing")?;
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            ensure!(
                flags >= 0
                    && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
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
                });
            }
            thread::sleep(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })();
    if !child.reaped && child.kill_and_reap().is_err() {
        return Err(CleanupError.into());
    }
    result
}

fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "cannot configure helper output"
    );
    Ok(())
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

    #[derive(Default)]
    struct FakeProcesses {
        gui: std::collections::VecDeque<Option<Vec<u8>>>,
        child: Option<Attempt>,
        results: HashMap<u32, bool>,
        events: Vec<String>,
        cleanup_fails: bool,
    }
    impl FakeProcesses {
        fn bytes(&mut self, text: &str) {
            self.gui.push_back(Some(text.as_bytes().to_vec()));
        }
    }
    impl ApprovalIo for FakeProcesses {
        fn observe_gui(&mut self, parser: &mut ApprovalParser) -> Result<Vec<Attempt>> {
            match self.gui.pop_front() {
                Some(Some(bytes)) => parser.feed(&bytes),
                Some(None) => bail!("approval window closed"),
                None => Ok(Vec::new()),
            }
        }
        fn stop_check(&mut self) -> Result<()> {
            if self.cleanup_fails {
                return Err(CleanupError.into());
            }
            if let Some(attempt) = self.child.take() {
                self.events.push(format!("reap {}", attempt.sequence));
            }
            Ok(())
        }
        fn start_check(&mut self, attempt: Attempt) -> Result<()> {
            assert!(
                self.child.is_none(),
                "second live check before old child reaped"
            );
            self.events.push(format!("start {}", attempt.sequence));
            self.child = Some(attempt);
            Ok(())
        }
        fn check_result(&mut self) -> Result<Option<bool>> {
            Ok(self
                .child
                .and_then(|a| self.results.get(&a.sequence).copied()))
        }
    }
    fn tick(
        io: &mut FakeProcesses,
        parser: &mut ApprovalParser,
        current: &mut Option<Attempt>,
    ) -> Result<Option<Option<GrantChoice>>> {
        let now = Instant::now();
        approval_tick(io, parser, current, now, now + Duration::from_secs(1))
    }

    #[test]
    fn explicit_cancel_is_observed_without_waiting_for_service_eof() {
        let mut parser = ApprovalParser::default();
        parser.feed(b"READY\nCHOICE 1 once\nCAN").unwrap();
        let error = parser.feed(b"CEL\n").unwrap_err();
        assert!(error.is::<ApprovalClosed>());
        assert_eq!(approval_outcome(Err(error)).unwrap(), None);
        assert!(
            !ApprovalParser::default()
                .feed(b"CANCEL\n")
                .unwrap_err()
                .is::<ApprovalClosed>()
        );
    }

    #[test]
    fn approval_parser_fragmented_and_coalesced_records() {
        let stream = b"READY\nCHOICE 1 once\nCHOICE 2 run\nCHOICE 3 once\n";
        let expected = vec![
            Attempt {
                sequence: 1,
                scope: GrantChoice::Once,
            },
            Attempt {
                sequence: 2,
                scope: GrantChoice::Run,
            },
            Attempt {
                sequence: 3,
                scope: GrantChoice::Once,
            },
        ];
        for split in 0..=stream.len() {
            let mut parser = ApprovalParser::default();
            let mut actual = parser.feed(&stream[..split]).unwrap();
            actual.extend(parser.feed(&stream[split..]).unwrap());
            assert_eq!(actual, expected);
        }
        let mut parser = ApprovalParser::default();
        let actual: Vec<_> = stream
            .iter()
            .flat_map(|b| parser.feed(&[*b]).unwrap())
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn approval_parser_rejects_order_injection_and_floods_without_echoing() {
        for stream in [
            "CHOICE 1 once\n",
            "READY\nREADY\n",
            "READY\nCHOICE 1 run\n",
            "READY\nCHOICE 0 once\n",
            "READY\nCHOICE 2 once\n",
            "READY\nCHOICE 01 once\n",
            "READY\nCHOICE 1 once\nCHOICE 1 run\n",
            "READY\nCHOICE 1 once extra\n",
            "READY\nAUTHORIZED\n",
            "READY\nCHOICE 1 Once\n",
            "READY\r\n",
            "READY\0\n",
            "READY\nprivate-password-must-not-be-logged\n",
            "READY\nCHOICE 1 oncé\n",
        ] {
            let error = ApprovalParser::default()
                .feed(stream.as_bytes())
                .unwrap_err();
            assert!(!format!("{error:#}").contains("private-password"));
        }
        assert!(
            ApprovalParser::default()
                .feed(&[b'x'; LINE_LIMIT + 1])
                .is_err()
        );
        assert!(
            ApprovalParser::default()
                .feed(&[b'x'; PROTOCOL_LIMIT + 1])
                .is_err()
        );
        let mut parser = ApprovalParser::default();
        parser.feed(b"READY\n").unwrap();
        for sequence in 1..=MAX_CHOICES {
            parser
                .feed(format!("CHOICE {sequence} once\n").as_bytes())
                .unwrap();
        }
        assert!(parser.feed(b"CHOICE 17 once\n").is_err());
    }

    #[test]
    fn scope_changes_invalidate_old_success_before_reap_and_new_launch() {
        for scopes in [
            [GrantChoice::Once, GrantChoice::Run],
            [GrantChoice::Once, GrantChoice::Once],
            [GrantChoice::Run, GrantChoice::Once],
        ] {
            for arrives_after_status in [false, true] {
                let mut io = FakeProcesses::default();
                let mut parser = ApprovalParser::default();
                let mut current = None;
                io.bytes("READY\nCHOICE 1 once\n");
                assert_eq!(tick(&mut io, &mut parser, &mut current).unwrap(), None);
                let old = if scopes[0] == GrantChoice::Run {
                    io.bytes("CHOICE 2 run\n");
                    tick(&mut io, &mut parser, &mut current).unwrap();
                    2
                } else {
                    1
                };
                io.results.insert(old, true);
                if arrives_after_status {
                    io.bytes("");
                }
                let scope = if scopes[1] == GrantChoice::Run {
                    "run"
                } else {
                    "once"
                };
                io.bytes(&format!("CHOICE {} {scope}\n", old + 1));
                assert_eq!(tick(&mut io, &mut parser, &mut current).unwrap(), None);
                assert_eq!(
                    current,
                    Some(Attempt {
                        sequence: old + 1,
                        scope: scopes[1]
                    })
                );
                assert!(
                    io.events
                        .ends_with(&[format!("reap {old}"), format!("start {}", old + 1)])
                );
                // Repeated observation of the superseded successful child has no authority.
                assert_eq!(tick(&mut io, &mut parser, &mut current).unwrap(), None);
                io.results.insert(old + 1, true);
                assert_eq!(
                    tick(&mut io, &mut parser, &mut current).unwrap(),
                    Some(Some(scopes[1]))
                );
            }
        }
    }

    #[test]
    fn gui_death_and_malformed_output_precede_simultaneous_check_success() {
        for after_status in [false, true] {
            for data in [None, Some(b"credential-adjacent-invalid-record\n".to_vec())] {
                let mut io = FakeProcesses::default();
                let mut parser = ApprovalParser::default();
                let mut current = None;
                io.bytes("READY\nCHOICE 1 once\n");
                tick(&mut io, &mut parser, &mut current).unwrap();
                io.results.insert(1, true);
                if after_status {
                    io.bytes("");
                }
                io.gui.push_back(data);
                assert!(tick(&mut io, &mut parser, &mut current).is_err());
            }
        }
    }

    #[test]
    fn gui_preferences_ready_and_exit_never_authorize() {
        let mut io = FakeProcesses::default();
        let mut parser = ApprovalParser::default();
        let mut current = None;
        io.bytes("READY\n");
        assert_eq!(tick(&mut io, &mut parser, &mut current).unwrap(), None);
        assert!(io.child.is_none());
        io.bytes("CHOICE 1 once\nCHOICE 2 run\n");
        assert_eq!(tick(&mut io, &mut parser, &mut current).unwrap(), None);
        io.results.insert(2, false);
        assert_eq!(
            tick(&mut io, &mut parser, &mut current).unwrap(),
            Some(None)
        );
        io.gui.push_back(None);
        assert!(tick(&mut io, &mut parser, &mut current).is_err());
    }

    #[test]
    fn fragmented_next_choice_blocks_old_success_and_eof_cancels() {
        let mut io = FakeProcesses::default();
        let mut parser = ApprovalParser::default();
        let mut current = None;
        io.bytes("READY\nCHOICE 1 once\n");
        tick(&mut io, &mut parser, &mut current).unwrap();
        io.results.insert(1, true);
        io.bytes("CHOI");
        assert_eq!(tick(&mut io, &mut parser, &mut current).unwrap(), None);
        io.bytes("CE 2 run\n");
        assert_eq!(tick(&mut io, &mut parser, &mut current).unwrap(), None);
        io.gui.push_back(None);
        assert!(tick(&mut io, &mut parser, &mut current).is_err());
    }

    #[test]
    fn original_deadline_beats_even_current_success() {
        let mut io = FakeProcesses::default();
        let mut parser = ApprovalParser::default();
        let mut current = None;
        io.bytes("READY\nCHOICE 1 once\nCHOICE 2 run\n");
        tick(&mut io, &mut parser, &mut current).unwrap();
        io.results.insert(2, true);
        let deadline = Instant::now();
        assert!(approval_tick(&mut io, &mut parser, &mut current, deadline, deadline).is_err());
    }

    #[test]
    fn unknown_check_cleanup_invalidates_and_never_launches_replacement() {
        let mut io = FakeProcesses::default();
        let mut parser = ApprovalParser::default();
        let mut current = None;
        io.bytes("READY\nCHOICE 1 once\n");
        tick(&mut io, &mut parser, &mut current).unwrap();
        io.results.insert(1, true);
        io.cleanup_fails = true;
        io.bytes("CHOICE 2 run\n");
        let error = tick(&mut io, &mut parser, &mut current).unwrap_err();
        assert!(error.is::<CleanupError>());
        assert_eq!(current, None);
        assert_eq!(io.events, ["start 1"]);
    }

    #[test]
    fn service_launch_argv_is_literal_and_hardened() {
        let subject = Subject {
            pid: 42,
            uid: 1000,
            start_time: 123,
        };
        let once = "once $HOME ${HOME} $$ %u \\ \"\n--option";
        let run = "run message";
        let environment = vec![("HOME".into(), "/home/literal $ %".into())];
        let command = approval_command(
            Path::new("/usr/bin/systemd-run"),
            Path::new("/usr/bin/env"),
            Path::new("/trusted/agent"),
            &subject,
            &environment,
            "agent-keyring-approval-0123456789abcdef0123456789abcdef.service",
            "0123456789abcdef0123456789abcdef",
            once,
            run,
            60,
        );
        let args: Vec<_> = command.get_args().map(|x| x.to_str().unwrap()).collect();
        for arg in [
            "--user",
            "--pipe",
            "--wait",
            "--collect",
            "--quiet",
            "--no-ask-password",
            "--service-type=exec",
            "--expand-environment=no",
            "--property=LimitCORE=0",
            "--property=Restart=no",
            "--property=TimeoutStartSec=5s",
            "--property=RuntimeMaxSec=60s",
            "--property=TimeoutStopSec=2s",
            "--property=KillMode=control-group",
            "--property=SendSIGKILL=yes",
            "HOME=/home/literal $ %",
        ] {
            assert!(args.contains(&arg), "{arg}");
        }
        assert!(!args.contains(&"--scope"));
        assert!(
            args.iter()
                .any(|x| x.starts_with("--property=UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH"))
        );
        let agent = args.iter().position(|x| *x == "/trusted/agent").unwrap();
        assert_eq!(
            &args[agent + 1..],
            [
                "--pid",
                "42",
                "--start-time",
                "123",
                "--uid",
                "1000",
                "--request-id",
                "0123456789abcdef0123456789abcdef",
                "--once-message",
                once,
                "--run-message",
                run,
                "--timeout-seconds",
                "60"
            ]
        );
        let env = args.iter().position(|x| *x == "/usr/bin/env").unwrap();
        assert_eq!(
            &args[env - 1..env + 5],
            [
                "--",
                "/usr/bin/env",
                "-i",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "PATH=/usr/bin:/bin"
            ]
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
    }

    #[test]
    fn liveness_writer_is_private_and_cloexec_and_stdin_eof_settles_child() {
        let (input, writer) = liveness_pipe().unwrap();
        for fd in [input.as_raw_fd(), writer.as_raw_fd()] {
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        // Another concurrently launched helper must not retain this request's writer.
        let probe = thread::current().name().unwrap().replace(
            "liveness_writer_is_private_and_cloexec_and_stdin_eof_settles_child",
            "inherited_fd_probe",
        );
        let mut other = clean_command(&std::env::current_exe().unwrap());
        other
            .args(["--exact", &probe])
            .env("AUTH_TEST_FD", writer.as_raw_fd().to_string());
        prepare_child(&mut other, None);
        assert!(
            run(&mut other, Instant::now() + Duration::from_secs(2), None)
                .unwrap()
                .status
                .success()
        );
        let mut command = clean_command(Path::new("/usr/bin/cat"));
        command.stdin(Stdio::from(input)).stderr(Stdio::null());
        prepare_child(&mut command, None);
        let mut child = Running {
            child: command.spawn().unwrap(),
            reaped: false,
        };
        drop(command);
        assert!(!child.exited().unwrap());
        drop(writer);
        let deadline = Instant::now() + Duration::from_secs(1);
        while !child.exited().unwrap() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(child.exited().unwrap(), "an inherited writer prevented EOF");
        assert!(child.kill_and_reap().unwrap().success());
        assert!(child.kill_and_reap().unwrap().success()); // cached, no recycled PID signal
    }

    #[test]
    fn live_protocol_eof_with_successful_check_is_not_authority() {
        let mut gui = clean_command(Path::new("/usr/bin/printf"));
        gui.args(["%s", "READY\nCHOICE 1 once\n"]);
        prepare_child(&mut gui, None);
        let mut launcher = Running {
            child: gui.spawn().unwrap(),
            reaped: false,
        };
        let mut stdout = launcher.child.stdout.take().unwrap();
        nonblocking(stdout.as_raw_fd()).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while !launcher.exited().unwrap() && Instant::now() < until {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(launcher.exited().unwrap());
        let mut command = clean_command(Path::new("/usr/bin/true"));
        prepare_child(&mut command, None);
        let mut check = Some(Running {
            child: command.spawn().unwrap(),
            reaped: false,
        });
        let subject = Subject {
            pid: 1,
            uid: 1000,
            start_time: 1,
        };
        let mut io = LiveApproval {
            launcher: &mut launcher,
            stdout: &mut stdout,
            check: &mut check,
            pkcheck: Path::new("/usr/bin/false"),
            subject: &subject,
            once_message: "once",
            run_message: "run",
            request_id: "0123456789abcdef0123456789abcdef",
            deadline: until,
        };
        assert!(
            approval_tick(
                &mut io,
                &mut ApprovalParser::default(),
                &mut None,
                Instant::now(),
                until
            )
            .is_err()
        );
        stop_check(&mut check).unwrap();
    }

    #[test]
    fn exact_unit_stop_and_confirmed_inactive_state_are_required() {
        use std::os::unix::process::ExitStatusExt;
        for (ready, stop_ok, show_ok, state, expected) in [
            (
                true,
                true,
                true,
                "LoadState=loaded\nActiveState=inactive\n",
                true,
            ),
            (
                true,
                false,
                true,
                "LoadState=not-found\nActiveState=inactive\n",
                true,
            ),
            (
                true,
                false,
                true,
                "LoadState=loaded\nActiveState=inactive\n",
                false,
            ),
            (
                true,
                true,
                true,
                "LoadState=loaded\nActiveState=active\n",
                false,
            ),
            (
                true,
                true,
                true,
                "LoadState=loaded\nActiveState=deactivating\n",
                false,
            ),
            (
                true,
                true,
                true,
                "LoadState=loaded\nActiveState=failed\n",
                false,
            ),
            (
                true,
                true,
                false,
                "LoadState=not-found\nActiveState=inactive\n",
                false,
            ),
            (
                false,
                true,
                true,
                "LoadState=not-found\nActiveState=inactive\n",
                false,
            ),
        ] {
            let mut command = clean_command(Path::new("/usr/bin/sleep"));
            command.arg("10");
            prepare_child(&mut command, None);
            let mut launcher = Running {
                child: command.spawn().unwrap(),
                reaped: false,
            };
            let pid = launcher.child.id() as i32;
            let mut calls = Vec::new();
            let result = settle_gui(
                &mut launcher,
                "agent-keyring-approval-test.service",
                ready,
                |args| {
                    // Even an unresponsive launcher is gone before manager stop.
                    assert_eq!(
                        unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
                        -1
                    );
                    assert_eq!(
                        io::Error::last_os_error().raw_os_error(),
                        Some(libc::ECHILD)
                    );
                    calls.push(args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
                    let success = if args[0] == "stop" { stop_ok } else { show_ok };
                    Ok(Output {
                        status: ExitStatus::from_raw(if success { 0 } else { 256 }),
                        stdout: if args[0] == "show" {
                            state.as_bytes().to_vec()
                        } else {
                            Vec::new()
                        },
                    })
                },
            );
            assert_eq!(result.is_ok(), expected, "{state}");
            assert_eq!(
                calls,
                [
                    vec!["stop", "--", "agent-keyring-approval-test.service"],
                    vec![
                        "show",
                        "--property=LoadState",
                        "--property=ActiveState",
                        "--",
                        "agent-keyring-approval-test.service"
                    ]
                ]
            );
        }
    }

    #[test]
    fn failed_unacknowledged_launcher_is_not_proof_of_settlement() {
        use std::os::unix::process::ExitStatusExt;
        for executable in ["/usr/bin/true", "/usr/bin/false"] {
            let mut command = clean_command(Path::new(executable));
            prepare_child(&mut command, None);
            let mut launcher = Running {
                child: command.spawn().unwrap(),
                reaped: false,
            };
            let until = Instant::now() + Duration::from_secs(1);
            while !launcher.exited().unwrap() && Instant::now() < until {
                thread::sleep(Duration::from_millis(5));
            }
            assert!(launcher.exited().unwrap());
            let result = settle_gui(
                &mut launcher,
                "agent-keyring-approval-test.service",
                false,
                |_| {
                    Ok(Output {
                        status: ExitStatus::from_raw(0),
                        stdout: b"LoadState=not-found\nActiveState=inactive\n".to_vec(),
                    })
                },
            );
            assert_eq!(result.is_ok(), executable == "/usr/bin/true");
        }
    }

    #[test]
    fn polkit_check_uses_exact_subject_message_and_no_internal_agent() {
        let subject = Subject {
            pid: 42,
            start_time: 123,
            uid: 1000,
        };
        let message = "Allow root PID 99 started 555 key synthetic version 1 once?\n\nRequest: 0123456789abcdef0123456789abcdef/1";
        let command = check_command(
            Path::new("/usr/bin/pkcheck"),
            &subject,
            READ_ACTION,
            message,
        )
        .unwrap();
        let args: Vec<_> = command.get_args().map(|x| x.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--action-id",
                READ_ACTION,
                "--process",
                "42,123,1000",
                "--allow-user-interaction",
                "-d",
                "polkit.message",
                message
            ]
        );
    }

    #[test]
    fn defaults_are_absolute_and_bounded() {
        let c = Config::default();
        assert_eq!(
            c.approval_agent,
            Path::new("/usr/local/libexec/agent-keyring-approval")
        );
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
    fn window_close_is_denial_but_protocol_and_cleanup_failures_are_not() {
        assert_eq!(approval_outcome(Err(ApprovalClosed.into())).unwrap(), None);
        assert!(approval_outcome(Err(CleanupError.into())).is_err());
        assert!(approval_outcome(Err(anyhow::anyhow!("invalid protocol"))).is_err());
        assert_eq!(
            approval_outcome(Ok(Some(GrantChoice::Once))).unwrap(),
            Some(GrantChoice::Once)
        );
        assert_eq!(
            approval_outcome(Ok(Some(GrantChoice::Run))).unwrap(),
            Some(GrantChoice::Run)
        );
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
    fn sticky_ancestor_exception_never_allows_writable_executable_files() {
        assert!(trusted_helper_mode(libc::S_IFDIR | 0o1775));
        assert!(trusted_helper_mode(libc::S_IFDIR | 0o1777));
        assert!(trusted_helper_mode(libc::S_IFDIR | 0o755));
        assert!(trusted_helper_mode(libc::S_IFREG | 0o555));
        assert!(!trusted_helper_mode(libc::S_IFDIR | 0o775));
        assert!(!trusted_helper_mode(libc::S_IFREG | 0o1775));
        assert!(!trusted_helper_mode(libc::S_IFREG | 0o775));
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
    fn desktop_theme_paths_include_home_manager_without_forcing_a_theme() {
        let dirs = desktop_data_dirs(Path::new("/home/theme user")).unwrap();
        assert_eq!(
            std::env::split_paths(&dirs).collect::<Vec<_>>(),
            [
                PathBuf::from("/home/theme user/.nix-profile/share"),
                PathBuf::from("/usr/local/share"),
                PathBuf::from("/usr/share"),
            ]
        );
        assert!(desktop_data_dirs(Path::new("/home/invalid:path")).is_err());
        let command = check_command(
            Path::new("/usr/bin/pkcheck"),
            &Subject {
                pid: 42,
                uid: 1000,
                start_time: 77,
            },
            READ_ACTION,
            "synthetic message",
        )
        .unwrap();
        assert!(
            !command
                .get_envs()
                .any(|(name, _)| name == "XDG_DATA_DIRS" || name == "GTK_THEME")
        );
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
