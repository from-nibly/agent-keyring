//! Kernel-pinned process identity and live ancestry for normal desktop trust.
//!
//! PIDs and UIDs passed to `from_peer` must come from authenticated per-message
//! SCM_CREDENTIALS/SCM_PIDFD, never request JSON or environment variables. A pidfd
//! pins an identity, not its lifetime: exited processes are always rejected.
//!
//! Agent names are mutable UX hints, NOT grant authority. The daemon must gate
//! root/key grants with polkit `auth_admin`. Discover candidates in requester-to-
//! ancestor order and choose the highest recognized ancestor (or an existing
//! nearer registered root); never substitute an unrecognized shell/supervisor.
//! Retain the `Ancestry` through authorization and validate to that exact root
//! immediately before releasing bytes. There is no detached-helper fallback.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const MAX_ANCESTRY: usize = 128;
const MAX_PROC_METADATA: usize = 64 * 1024;
const MAX_CMDLINE: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: i32,
    /// Linux /proc stat field 22, in clock ticks since boot.
    pub start_time: u64,
    pub uid: u32,
}

// Deliberately no Debug implementation: do not accidentally log process details.
pub struct PinnedProcess {
    identity: ProcessIdentity,
    pidfd: OwnedFd,
}

impl PinnedProcess {
    /// Clone the kernel-authenticated peer handle, then bind procfs metadata to it.
    /// The caller retains ownership of the received SCM_PIDFD.
    pub fn from_peer(pid: i32, uid: u32, pidfd: &OwnedFd) -> Result<Self> {
        let process = Self::from_fd(pid, pidfd.try_clone().context("clone peer pidfd")?)?;
        ensure!(
            process.identity.uid == uid,
            "peer UID does not match process"
        );
        Ok(process)
    }

    /// Open an ancestor's pidfd before reading any identity metadata.
    /// This is not a replacement for `from_peer` when authenticating a requester.
    pub fn capture(pid: i32) -> Result<Self> {
        ensure!(pid > 0, "invalid process PID");
        // SAFETY: pidfd_open takes scalar arguments; flags=0 pins a thread group.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("open process pidfd");
        }
        // SAFETY: a successful syscall returned a new, exclusively owned fd.
        Self::from_fd(pid, unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    fn from_fd(pid: i32, pidfd: OwnedFd) -> Result<Self> {
        ensure!(pid > 0, "invalid process PID");
        ensure!(pidfd_alive(&pidfd)?, "process has exited");
        // fdinfo Pid is kernel-generated in the procfs mount's PID namespace.
        // It both rejects non-pidfds and binds this numeric lookup to the handle.
        let info = read_bounded(
            format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()),
            MAX_PROC_METADATA,
        )?;
        ensure!(
            fdinfo_pid(&info)? == pid,
            "pidfd does not match process PID"
        );
        check_proc_namespace()?;
        let snapshot = read_snapshot(pid)?;
        ensure!(pidfd_alive(&pidfd)?, "process exited during capture");
        Ok(Self {
            identity: ProcessIdentity {
                pid,
                start_time: snapshot.stat.start_time,
                uid: snapshot.uid,
            },
            pidfd,
        })
    }

    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// A fail-closed liveness snapshot, not a promise that the process stays alive.
    pub fn is_alive(&self) -> bool {
        pidfd_alive(&self.pidfd).unwrap_or(false)
    }

    /// Return the current executable path without reading or logging arguments.
    pub fn executable(&self) -> Result<String> {
        self.validate()?;
        let path = fs::read_link(format!("/proc/{}/exe", self.identity.pid))
            .context("read process executable")?;
        let path = path
            .into_os_string()
            .into_string()
            .map_err(|_| anyhow::anyhow!("process executable is not UTF-8"))?;
        self.validate()?;
        Ok(path)
    }

    /// Recognize native agents or the actual node/bun script operand, not arbitrary
    /// later arguments. A process can exec or rewrite argv: this is only a hint.
    /// Unknown runtime options deliberately yield no candidate.
    pub fn agent_name(&self) -> Result<Option<String>> {
        let executable = self.executable()?;
        let basename = Path::new(&executable)
            .file_name()
            .and_then(|name| name.to_str());
        let cmdline = if matches!(basename, Some("node" | "bun")) {
            read_bounded(format!("/proc/{}/cmdline", self.identity.pid), MAX_CMDLINE)?
        } else {
            Vec::new()
        };
        let name = match_agent(&executable, &cmdline).map(str::to_owned);
        self.validate()?;
        Ok(name)
    }

    pub fn validate(&self) -> Result<()> {
        self.snapshot().map(|_| ())
    }

    fn snapshot(&self) -> Result<Snapshot> {
        ensure!(pidfd_alive(&self.pidfd)?, "process has exited");
        check_proc_namespace()?;
        let snapshot = read_snapshot(self.identity.pid)?;
        ensure!(
            snapshot.stat.start_time == self.identity.start_time,
            "process start time changed"
        );
        ensure!(snapshot.uid == self.identity.uid, "process UID changed");
        // Reading a PID twice is insufficient. The retained handle must still be
        // live after procfs access, so that access cannot belong to a reused PID.
        ensure!(
            pidfd_alive(&self.pidfd)?,
            "process exited during validation"
        );
        Ok(snapshot)
    }
}

/// Pinned processes ordered requester first, highest visible ancestor last.
/// All identities, including intermediate shells, remain retained. Discovery is
/// bounded and fails rather than silently truncating an unknown ancestor chain.
pub struct Ancestry {
    processes: Vec<PinnedProcess>,
}

impl Ancestry {
    pub fn capture(peer_pid: i32, peer_uid: u32, peer_pidfd: &OwnedFd) -> Result<Self> {
        let mut processes = vec![PinnedProcess::from_peer(peer_pid, peer_uid, peer_pidfd)?];
        let mut seen = HashSet::from([peer_pid]);
        loop {
            let child = processes.last().expect("requester is present");
            let parent_pid = child.snapshot()?.stat.parent_pid;
            if parent_pid == 0 {
                break;
            }
            ensure!(
                processes.len() < MAX_ANCESTRY,
                "ancestry exceeds depth limit"
            );
            ensure!(seen.insert(parent_pid), "ancestry contains a cycle");
            let parent = PinnedProcess::capture(parent_pid)?;
            ensure!(
                child.snapshot()?.stat.parent_pid == parent_pid,
                "parent changed during ancestry capture"
            );
            ensure!(parent.is_alive(), "parent exited during ancestry capture");
            processes.push(parent);
        }
        let ancestry = Self { processes };
        ancestry.validate_to(
            ancestry
                .processes
                .last()
                .expect("requester is present")
                .identity(),
        )?;
        Ok(ancestry)
    }

    pub fn processes(&self) -> &[PinnedProcess] {
        &self.processes
    }

    /// Validate the live, current chain from the authenticated requester to an
    /// exact retained root. Ancestors above the chosen root are not required.
    ///
    /// Linearization point: the start of the final retained-pidfd liveness sweep.
    /// Every checked handle is live at that point (exit is irreversible). Each
    /// real-parent edge was checked beforehand; Linux cannot reparent a live
    /// child away from its still-live real parent. This proves a simultaneous
    /// chain, not an atomic snapshot of executable names or mutable credentials.
    /// A root/child may exit immediately afterwards: this cannot retract bytes
    /// released after authorization. Call again after any authorization wait.
    pub fn validate_to(&self, root_identity: &ProcessIdentity) -> Result<()> {
        let root_index = self
            .processes
            .iter()
            .position(|process| process.identity() == root_identity)
            .context("root is not in authenticated ancestry")?;
        let chain = &self.processes[..=root_index];
        for (index, process) in chain.iter().enumerate() {
            let snapshot = process.snapshot()?;
            if let Some(parent) = chain.get(index + 1) {
                ensure!(
                    snapshot.stat.parent_pid == parent.identity.pid,
                    "authenticated parent chain was lost"
                );
                ensure!(
                    parent.identity.start_time <= process.identity.start_time,
                    "parent identity is newer than child"
                );
            }
        }
        // Keep this last: all handles must survive the preceding edge checks.
        for process in chain {
            ensure!(pidfd_alive(&process.pidfd)?, "ancestry process has exited");
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Stat {
    pid: i32,
    parent_pid: i32,
    start_time: u64,
    state: u8,
}

struct Snapshot {
    stat: Stat,
    uid: u32,
}

fn pidfd_alive(pidfd: &OwnedFd) -> Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: descriptor points to one initialized pollfd for the whole call.
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("poll process pidfd");
        }
        ensure!(
            descriptor.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "invalid process pidfd"
        );
        return Ok(descriptor.revents == 0);
    }
}

fn read_bounded(path: impl AsRef<Path>, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .context("open process metadata")?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read process metadata")?;
    ensure!(bytes.len() <= limit, "process metadata exceeds size limit");
    Ok(bytes)
}

fn number<T: std::str::FromStr>(bytes: &[u8]) -> Result<T> {
    // Do not put the input in errors: comm/argv may contain sensitive text.
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse().ok())
        .context("invalid numeric process metadata")
}

fn fields(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
}

fn parse_stat(bytes: &[u8]) -> Result<Stat> {
    let open = bytes
        .iter()
        .position(|byte| *byte == b'(')
        .context("missing stat comm")?;
    let close = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .context("missing stat comm end")?;
    ensure!(
        open > 0 && close > open && bytes.get(close + 1) == Some(&b' '),
        "invalid stat comm boundaries"
    );
    let mut prefix = fields(&bytes[..open]);
    let pid = number(prefix.next().context("missing stat PID")?)?;
    ensure!(prefix.next().is_none() && pid > 0, "invalid stat PID");
    // comm is unescaped and may contain spaces, newlines, ')' and non-UTF-8.
    // All fields after its final ')' are kernel-generated ASCII numeric/state.
    let tail: Vec<_> = fields(&bytes[close + 2..]).collect();
    ensure!(
        tail.len() >= 20 && tail[0].len() == 1,
        "short or invalid stat"
    );
    let parent_pid = number(tail[1])?;
    ensure!(parent_pid >= 0, "invalid stat parent PID");
    Ok(Stat {
        pid,
        parent_pid,
        start_time: number(tail[19])?,
        state: tail[0][0],
    })
}

fn status_field<'a>(bytes: &'a [u8], key: &[u8]) -> Result<&'a [u8]> {
    let mut matches = bytes
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(key));
    let value = matches
        .next()
        .context("required process metadata unavailable")?;
    ensure!(matches.next().is_none(), "ambiguous process metadata");
    Ok(value)
}

fn fdinfo_pid(bytes: &[u8]) -> Result<i32> {
    let mut values = fields(status_field(bytes, b"Pid:")?);
    let pid = number(values.next().context("missing pidfd PID")?)?;
    ensure!(values.next().is_none(), "ambiguous pidfd PID");
    Ok(pid)
}

fn check_namespace_status(status: &[u8], pid: i32) -> Result<()> {
    let values: Vec<_> = fields(status_field(status, b"NSpid:")?).collect();
    // NSpid lists IDs from the procfs mount's PID namespace inward. Exactly one
    // ID proves membership in that namespace, without ptrace-gated ns symlinks.
    ensure!(
        values.len() == 1 && number::<i32>(values[0])? == pid,
        "unsupported or unknown PID namespace"
    );
    Ok(())
}

fn check_proc_namespace() -> Result<()> {
    // SAFETY: getpid has no preconditions or memory arguments.
    let pid = unsafe { libc::getpid() };
    let status = read_bounded("/proc/self/status", MAX_PROC_METADATA)?;
    check_namespace_status(&status, pid)
}

fn read_snapshot(pid: i32) -> Result<Snapshot> {
    let base = format!("/proc/{pid}");
    let stat = parse_stat(&read_bounded(format!("{base}/stat"), MAX_PROC_METADATA)?)?;
    ensure!(stat.pid == pid, "procfs PID mismatch");
    ensure!(
        matches!(
            stat.state,
            b'R' | b'S' | b'D' | b'T' | b't' | b'I' | b'W' | b'P'
        ),
        "process is dead or has unknown state"
    );
    let status = read_bounded(format!("{base}/status"), MAX_PROC_METADATA)?;
    check_namespace_status(&status, pid)?;
    let uid = fs::metadata(&base).context("stat process directory")?.uid();
    let uids: Vec<_> = fields(status_field(&status, b"Uid:")?).collect();
    ensure!(uids.len() == 4, "invalid process UID metadata");
    // Reject set-ID/credential-changing processes rather than conflating real,
    // effective, saved and filesystem UIDs with the authenticated desktop user.
    for value in uids {
        ensure!(number::<u32>(value)? == uid, "inconsistent process UIDs");
    }
    Ok(Snapshot { stat, uid })
}

fn match_agent(executable: &str, cmdline: &[u8]) -> Option<&'static str> {
    let basename = Path::new(executable).file_name()?.to_str()?;
    match basename {
        "pi" => return Some("pi"),
        "claude" => return Some("claude"),
        "codex" => return Some("codex"),
        "node" | "bun" => {}
        _ => return None,
    }
    if cmdline.last() != Some(&0) {
        return None;
    }
    let mut args = cmdline[..cmdline.len() - 1].split(|byte| *byte == 0);
    let title = args.next()?;
    // Pi sets process.title, replacing its visible argv with "pi" and NUL
    // padding while /proc/PID/exe remains node. This is only a discovery hint:
    // exact process identity and administrator approval still gate every grant.
    if args.clone().all(|argument| argument.is_empty()) {
        return match title {
            b"pi" => Some("pi"),
            b"claude" => Some("claude"),
            b"codex" => Some("codex"),
            _ => None,
        };
    }
    let mut script = args.next()?;
    if script == b"--" || (basename == "bun" && script == b"run") {
        script = args.next()?;
    }
    if script.is_empty() || script.starts_with(b"-") {
        return None;
    }
    for (suffix, name) in [
        (b"pi-coding-agent/dist/cli.js".as_slice(), "pi"),
        (b"@anthropic-ai/claude-code/cli.js".as_slice(), "claude"),
        (b"@openai/codex/bin/codex.js".as_slice(), "codex"),
    ] {
        if script
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with(b"/"))
        {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn runtime_titles_are_exact_discovery_hints() {
        assert_eq!(match_agent("/usr/bin/node", b"pi\0\0\0"), Some("pi"));
        assert_eq!(match_agent("/usr/bin/node", b"claude\0"), Some("claude"));
        assert_eq!(match_agent("/usr/bin/node", b"pi-helper\0\0"), None);
        assert_eq!(match_agent("/usr/bin/node", b"pi\0unrelated.js\0"), None);
        assert_eq!(match_agent("/usr/bin/bash", b"pi\0\0"), None);
    }

    #[test]
    fn real_node_title_mutation_is_discovered_without_registered_roots() {
        let child = Command::new("node")
            .args([
                "-e",
                "process.title='pi'; console.log('ready'); setInterval(()=>{},1000)",
            ])
            .stdout(Stdio::piped())
            .spawn();
        let child = match child {
            Ok(child) => child,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(error) => panic!("node fixture failed: {error}"),
        };
        let mut child = ChildGuard(child);
        let mut ready = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "ready");
        let process = PinnedProcess::capture(child.0.id() as i32).unwrap();
        assert_eq!(process.agent_name().unwrap().as_deref(), Some("pi"));
    }

    fn self_pid() -> i32 {
        std::process::id() as i32
    }

    fn stat_bytes(comm: &[u8]) -> Vec<u8> {
        let mut bytes = b"123 (".to_vec();
        bytes.extend_from_slice(comm);
        bytes.extend_from_slice(b") S 45");
        // Fields 5 through 21 precede starttime (field 22).
        for _ in 5..=21 {
            bytes.extend_from_slice(b" 0");
        }
        bytes.extend_from_slice(b" 987654 0 0\n");
        bytes
    }

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // A pidfd-based guard cannot accidentally kill a reused numeric PID.
    struct ProcessGuard(PinnedProcess);

    impl Drop for ProcessGuard {
        fn drop(&mut self) {
            // SAFETY: a live owned pidfd, scalar signal/flags and null siginfo.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.0.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0_u32,
                );
            }
        }
    }

    fn sleeping_child() -> ChildGuard {
        ChildGuard(Command::new("sleep").arg("60").spawn().unwrap())
    }

    fn ancestry_for(process: &PinnedProcess) -> Ancestry {
        Ancestry::capture(process.identity.pid, process.identity.uid, &process.pidfd).unwrap()
    }

    fn grandchild() -> (ChildGuard, ProcessGuard) {
        // Keep the intermediate shell alive until explicitly released. No
        // process-wide subreaper setting, and no fork in the threaded test runner.
        let mut parent = ChildGuard(
            Command::new("sh")
                .args([
                    "-c",
                    "sleep 60 & child=$!; printf '%s\\n' \"$child\"; read release; wait \"$child\"",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        BufReader::new(parent.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let pid = line.trim().parse().unwrap();
        (parent, ProcessGuard(PinnedProcess::capture(pid).unwrap()))
    }

    #[test]
    fn stat_comm_can_contain_spaces_parentheses_newlines_and_non_utf8() {
        for comm in [
            b"normal".as_slice(),
            b"pi (agent worker)",
            b") S 999 0 0 0 ) (( forged stat )\nUid:\t0 0 0 0",
            b"\xff\xfe ) nasty ( comm",
            b"",
        ] {
            assert_eq!(
                parse_stat(&stat_bytes(comm)).unwrap(),
                Stat {
                    pid: 123,
                    parent_pid: 45,
                    start_time: 987654,
                    state: b'S',
                }
            );
        }
    }

    #[test]
    fn malformed_stat_fails_closed() {
        for bytes in [
            b"".as_slice(),
            b"123 no-comm",
            b"123 (comm",
            b"123 (comm) S 45",
            b"123 extra (comm) S 45",
            b"123 (comm)S 45",
            b"-1 (comm) S 45",
        ] {
            assert!(parse_stat(bytes).is_err());
        }
        let invalid = String::from_utf8(stat_bytes(b"comm"))
            .unwrap()
            .replace(" S 45", " S -1");
        assert!(parse_stat(invalid.as_bytes()).is_err());
    }

    #[test]
    fn namespace_policy_rejects_nested_missing_or_ambiguous_ids() {
        assert!(check_namespace_status(b"NSpid:\t123\n", 123).is_ok());
        for bytes in [
            b"NSpid:\t123 1\n".as_slice(),
            b"NSpid:\t124\n",
            b"Uid:\t1000\n",
            b"NSpid:\t\n",
            b"NSpid:\t123\nNSpid:\t123\n",
        ] {
            assert!(check_namespace_status(bytes, 123).is_err());
        }
    }

    #[test]
    fn native_agent_matching_is_exact() {
        for name in ["pi", "claude", "codex"] {
            assert_eq!(match_agent(&format!("/opt/bin/{name}"), b""), Some(name));
        }
        for path in [
            "/bin/sh",
            "/bin/bash",
            "/sbin/init",
            "/bin/supervisord",
            "/bin/not-pi",
            "/bin/claude-helper",
            "/bin/codex.js",
            "/pi/not-node",
        ] {
            assert_eq!(match_agent(path, b"codex\0"), None);
        }
    }

    #[test]
    fn runtime_agent_matching_uses_only_the_script_operand() {
        for (script, name) in [
            (
                "/opt/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
                "pi",
            ),
            ("pi-coding-agent/dist/cli.js", "pi"),
            (
                "/opt/node_modules/@anthropic-ai/claude-code/cli.js",
                "claude",
            ),
            ("/opt/node_modules/@openai/codex/bin/codex.js", "codex"),
        ] {
            for executable in ["/usr/bin/node", "/usr/bin/bun"] {
                let argv = format!("arbitrary-argv-zero\0{script}\0--extra\0secret\0");
                assert_eq!(match_agent(executable, argv.as_bytes()), Some(name));
                let argv = format!("runtime\0--\0{script}\0");
                assert_eq!(match_agent(executable, argv.as_bytes()), Some(name));
            }
            let argv = format!("bun\0run\0{script}\0");
            assert_eq!(match_agent("/bin/bun", argv.as_bytes()), Some(name));
        }
    }

    #[test]
    fn random_runtime_arguments_do_not_turn_helpers_into_agents() {
        let script = "/opt/node_modules/pi-coding-agent/dist/cli.js";
        for argv in [
            format!("node\0/tmp/helper.js\0{script}\0"),
            format!("node\0-e\0console.log('hi')\0{script}\0"),
            format!("node\0--eval\0{script}\0"),
            format!("node\0--require\0{script}\0/tmp/helper.js\0"),
            format!("node\0/tmp/not-pi-coding-agent/dist/cli.js\0{script}\0"),
            format!("node\0{script}.backup\0"),
            format!("node\0{script}"),
            format!("node\0\0{script}\0"),
            format!("node\0--unknown-option\0{script}\0"),
        ] {
            assert_eq!(match_agent("/bin/node", argv.as_bytes()), None);
        }
        assert_eq!(
            match_agent("/bin/sh", format!("node\0{script}\0").as_bytes()),
            None
        );
        assert_eq!(match_agent("/bin/node", b""), None);
    }

    #[test]
    fn bounded_reads_reject_overflow_without_echoing_contents() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"private argument").unwrap();
        assert_eq!(read_bounded(file.path(), 16).unwrap(), b"private argument");
        let error = read_bounded(file.path(), 3).unwrap_err();
        assert!(!format!("{error:#}").contains("private"));
    }

    #[test]
    fn authenticated_peer_fd_is_cloned_and_bound_to_identity() {
        let original = PinnedProcess::capture(self_pid()).unwrap();
        let peer =
            PinnedProcess::from_peer(self_pid(), original.identity.uid, &original.pidfd).unwrap();
        assert_eq!(original.identity(), peer.identity());
        assert_ne!(original.pidfd.as_raw_fd(), peer.pidfd.as_raw_fd());
        let json = serde_json::to_string(peer.identity()).unwrap();
        assert_eq!(
            serde_json::from_str::<ProcessIdentity>(&json).unwrap(),
            *peer.identity()
        );
        drop(original);
        assert!(peer.is_alive());
        peer.validate().unwrap();
        assert!(!peer.executable().unwrap().is_empty());
    }

    #[test]
    fn mismatched_peer_pid_uid_and_non_pidfd_are_rejected() {
        let process = PinnedProcess::capture(self_pid()).unwrap();
        assert!(
            PinnedProcess::from_peer(self_pid() + 1, process.identity.uid, &process.pidfd).is_err()
        );
        assert!(
            PinnedProcess::from_peer(
                self_pid(),
                process.identity.uid.wrapping_add(1),
                &process.pidfd
            )
            .is_err()
        );
        let regular: OwnedFd = tempfile::tempfile().unwrap().into();
        assert!(PinnedProcess::from_peer(self_pid(), process.identity.uid, &regular).is_err());
        assert!(PinnedProcess::capture(0).is_err());
        assert!(PinnedProcess::capture(-1).is_err());
    }

    #[test]
    fn changed_start_time_or_uid_is_rejected() {
        let mut process = PinnedProcess::capture(self_pid()).unwrap();
        let original = process.identity.clone();
        process.identity.start_time = original.start_time.wrapping_add(1);
        assert!(process.validate().is_err());
        process.identity = original;
        process.identity.uid = process.identity.uid.wrapping_add(1);
        assert!(process.validate().is_err());
    }

    #[test]
    fn dead_retained_handle_cannot_authenticate_or_read_metadata() {
        let mut child = sleeping_child();
        let process = PinnedProcess::capture(child.0.id() as i32).unwrap();
        assert!(process.is_alive());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(!process.is_alive());
        assert!(process.validate().is_err());
        assert!(process.executable().is_err());
        assert!(process.agent_name().is_err());
        assert!(
            PinnedProcess::from_peer(process.identity.pid, process.identity.uid, &process.pidfd)
                .is_err()
        );
    }

    #[test]
    fn ordinary_child_parent_ancestry_is_pinned_and_validated() {
        let child = sleeping_child();
        let process = PinnedProcess::capture(child.0.id() as i32).unwrap();
        let parent = PinnedProcess::capture(self_pid()).unwrap();
        let ancestry = ancestry_for(&process);
        assert_eq!(ancestry.processes()[0].identity(), process.identity());
        assert_eq!(ancestry.processes()[1].identity(), parent.identity());
        ancestry.validate_to(parent.identity()).unwrap();
        ancestry.validate_to(process.identity()).unwrap();
        let mut wrong_root = parent.identity().clone();
        wrong_root.start_time = wrong_root.start_time.wrapping_add(1);
        assert!(ancestry.validate_to(&wrong_root).is_err());
        assert!(ancestry.processes().len() <= MAX_ANCESTRY);
    }

    #[test]
    fn intermediate_identity_and_parent_edge_tampering_are_rejected() {
        let child = sleeping_child();
        let process = PinnedProcess::capture(child.0.id() as i32).unwrap();
        let parent = PinnedProcess::capture(self_pid()).unwrap();
        let mut ancestry = ancestry_for(&process);
        ancestry.processes[0].identity.start_time += 1;
        assert!(ancestry.validate_to(parent.identity()).is_err());
        ancestry.processes[0].identity.start_time -= 1;
        // Replace the expected parent with a different, live process.
        let other_child = sleeping_child();
        ancestry.processes[1] = PinnedProcess::capture(other_child.0.id() as i32).unwrap();
        let wrong_root = ancestry.processes[1].identity().clone();
        assert!(ancestry.validate_to(&wrong_root).is_err());
    }

    #[test]
    fn grandchild_chain_requires_live_intermediate_parent() {
        let (mut parent, grandchild) = grandchild();
        let root = PinnedProcess::capture(self_pid()).unwrap();
        let ancestry = ancestry_for(&grandchild.0);
        assert_eq!(ancestry.processes()[1].identity.pid, parent.0.id() as i32);
        ancestry.validate_to(root.identity()).unwrap();
        drop(grandchild); // kill first; allow the shell to reap it normally
        parent
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(b"release\n")
            .unwrap();
        parent.0.wait().unwrap();
        assert!(ancestry.validate_to(root.identity()).is_err());
    }

    #[test]
    fn detached_live_grandchild_cannot_use_the_previous_root() {
        let (mut parent, grandchild) = grandchild();
        let root = PinnedProcess::capture(self_pid()).unwrap();
        let ancestry = ancestry_for(&grandchild.0);
        let parent_identity = ancestry.processes()[1].identity().clone();
        ancestry.validate_to(root.identity()).unwrap();
        parent.0.kill().unwrap();
        parent.0.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while grandchild.0.snapshot().unwrap().stat.parent_pid == parent_identity.pid {
            assert!(Instant::now() < deadline, "grandchild did not reparent");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(grandchild.0.is_alive());
        assert!(ancestry.validate_to(&parent_identity).is_err());
        assert!(ancestry.validate_to(root.identity()).is_err());
        // Processes above the explicitly chosen root are irrelevant.
        ancestry.validate_to(grandchild.0.identity()).unwrap();
    }

    #[test]
    fn a_plain_live_shell_is_not_an_agent_candidate() {
        let shell = ChildGuard(
            Command::new("sh")
                .args(["-c", "read hold"])
                .stdin(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let process = PinnedProcess::capture(shell.0.id() as i32).unwrap();
        assert_eq!(process.agent_name().unwrap(), None);
    }
}
