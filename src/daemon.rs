use crate::auth::{self, GrantChoice, Subject};
use crate::ipc::{Channel, Listener, Peer};
use crate::process::{Ancestry, PinnedProcess, ProcessIdentity};
use crate::protocol::*;
use crate::store::{self, Store};
use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Config {
    pub socket: PathBuf,
    pub state_dir: PathBuf,
    pub auth: auth::Config,
}

struct Root {
    owner: u32,
    process: PinnedProcess,
    agent: Agent,
}
struct Grant {
    owner: u32,
    root: ProcessIdentity,
    key: String,
    version: u64,
}
struct State {
    store: Store,
    roots: Vec<Root>,
    grants: Vec<Grant>,
    revocation_epochs: HashMap<u32, u64>,
}
struct Broker {
    state: Mutex<State>,
    prompting: Mutex<HashSet<u32>>,
    auth: auth::Config,
    clients: Mutex<HashMap<u32, usize>>,
}

impl State {
    fn prune(&mut self) {
        self.roots.retain(|root| root.process.is_alive());
        self.grants.retain(|grant| {
            self.roots
                .iter()
                .any(|root| root.owner == grant.owner && root.process.identity() == &grant.root)
        });
    }
}

pub fn run(config: Config) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("daemon must run as root via its system service");
    }
    // Neither a daemon core dump nor a debugger should expose vault contents.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        libc::umask(0o077);
    }
    let store = Store::open(&config.state_dir)?;
    let _lock = lock_state(&config.state_dir)?;
    let parent = config
        .socket
        .parent()
        .context("socket must have an absolute parent")?;
    if !parent.exists() {
        fs::create_dir(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
    }
    validate_socket_parent(&config.socket)?;
    if let Ok(metadata) = fs::symlink_metadata(&config.socket) {
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            bail!("refusing to replace an unsafe socket path");
        }
        match Channel::connect(&config.socket) {
            Ok(_) => bail!("another daemon is already listening at this socket"),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ECONNREFUSED | libc::ENOENT)
                ) =>
            {
                fs::remove_file(&config.socket)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let listener = Listener::bind(&config.socket)?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o666))?;
    let broker = Arc::new(Broker {
        state: Mutex::new(State {
            store,
            roots: Vec::new(),
            grants: Vec::new(),
            revocation_epochs: HashMap::new(),
        }),
        prompting: Mutex::new(HashSet::new()),
        auth: config.auth,
        clients: Mutex::new(HashMap::new()),
    });
    let cleanup = Arc::downgrade(&broker);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let Some(broker) = cleanup.upgrade() else {
                break;
            };
            if let Ok(mut state) = broker.state.lock() {
                state.prune();
            }
        }
    });
    eprintln!("agent-keyring {VERSION}: listening");
    loop {
        let channel = listener.accept()?;
        let connection_uid = match channel.connecting_uid() {
            Ok(uid) => uid,
            Err(_) => continue,
        };
        if !reserve_client(&broker.clients, connection_uid) {
            continue;
        }
        let broker = Arc::clone(&broker);
        std::thread::spawn(move || {
            struct ClientGuard {
                broker: Arc<Broker>,
                uid: u32,
            }
            impl Drop for ClientGuard {
                fn drop(&mut self) {
                    release_client(&self.broker.clients, self.uid);
                }
            }
            let guard = ClientGuard {
                broker,
                uid: connection_uid,
            };
            if let Ok((request, peer)) = channel.receive::<Request>() {
                let response = if peer.uid == connection_uid {
                    guard.broker.handle(&request, &peer)
                } else {
                    error(ErrorCode::Denied, "request sender changed user identity")
                };
                // One response consumes this request even if its client vanished.
                let _ = channel.send(&response);
            }
        });
    }
}

fn reserve_client(clients: &Mutex<HashMap<u32, usize>>, uid: u32) -> bool {
    let Ok(mut clients) = clients.lock() else {
        return false;
    };
    if clients.values().sum::<usize>() >= 64 || clients.get(&uid).copied().unwrap_or(0) >= 8 {
        return false;
    }
    *clients.entry(uid).or_default() += 1;
    true
}

fn release_client(clients: &Mutex<HashMap<u32, usize>>, uid: u32) {
    if let Ok(mut clients) = clients.lock() {
        if let Some(count) = clients.get_mut(&uid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                clients.remove(&uid);
            }
        }
    }
}

fn error(code: ErrorCode, message: impl Into<String>) -> Response {
    Response::Error {
        code,
        message: message.into(),
    }
}
fn storage_error(error_value: store::Error) -> Response {
    let code = match &error_value {
        store::Error::InvalidKey | store::Error::SecretTooLarge | store::Error::InvalidVersion => {
            ErrorCode::InvalidRequest
        }
        store::Error::AlreadyExists => ErrorCode::AlreadyExists,
        store::Error::NotFound | store::Error::Tombstoned => ErrorCode::NotFound,
        store::Error::VersionConflict { .. } => ErrorCode::Conflict,
        _ => {
            return error(
                ErrorCode::Internal,
                "vault operation failed; no secret was disclosed",
            );
        }
    };
    error(code, error_value.to_string())
}

impl Broker {
    fn handle(&self, request: &Request, peer: &Peer) -> Response {
        if !peer.is_alive().unwrap_or(false) {
            return error(ErrorCode::Denied, "requester exited");
        }
        let process = match PinnedProcess::from_peer(peer.pid, peer.uid, &peer.pidfd) {
            Ok(process) => process,
            Err(_) => {
                return error(
                    ErrorCode::Denied,
                    "could not authenticate the live requesting process",
                );
            }
        };
        if matches!(request, Request::Ping) {
            return Response::Pong {
                version: VERSION.into(),
            };
        }
        let subject = Subject {
            pid: peer.pid,
            uid: peer.uid,
            start_time: process.identity().start_time,
        };
        match request {
            Request::Get {
                key,
                non_interactive,
            } => self.get(peer, &subject, key, *non_interactive),
            Request::Create { key, value } => {
                let mut state = match self.state.lock() {
                    Ok(state) => state,
                    Err(_) => return error(ErrorCode::Internal, "state unavailable"),
                };
                match state.store.create(peer.uid, key, value) {
                    Ok(metadata) => Response::Written {
                        version: metadata.version,
                    },
                    Err(failure) => storage_error(failure),
                }
            }
            Request::Replace { key, value } => self.mutate(&process, &subject, key, Some(value)),
            Request::Delete { key } => self.mutate(&process, &subject, key, None),
            Request::Grants => {
                let mut state = match self.state.lock() {
                    Ok(state) => state,
                    Err(_) => return error(ErrorCode::Internal, "state unavailable"),
                };
                state.prune();
                let grants = state
                    .grants
                    .iter()
                    .filter(|g| g.owner == peer.uid)
                    .filter_map(|g| {
                        state
                            .roots
                            .iter()
                            .find(|r| r.owner == g.owner && r.process.identity() == &g.root)
                            .map(|r| GrantInfo {
                                key: g.key.clone(),
                                version: g.version,
                                agent: r.agent.clone(),
                            })
                    })
                    .collect();
                Response::Grants { grants }
            }
            Request::Revoke { all, key } => self.revoke(peer, *all, key.as_deref()),
            Request::Ping => unreachable!(),
        }
    }

    fn get(&self, peer: &Peer, subject: &Subject, key: &str, non_interactive: bool) -> Response {
        if let Err(failure) = store::validate_key(key) {
            return storage_error(failure);
        }
        let ancestry = match Ancestry::capture(peer.pid, peer.uid, &peer.pidfd) {
            Ok(value) => value,
            Err(_) => return error(ErrorCode::Denied, "cannot verify live ancestry"),
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error(ErrorCode::Internal, "state unavailable"),
        };
        state.prune();
        let root = match select_root(&state, &ancestry, peer.uid) {
            Some(root) => root,
            None => {
                return error(
                    ErrorCode::NotAgent,
                    "no live Pi, Claude Code or Codex ancestor; detached helpers are not supported",
                );
            }
        };
        if ancestry.validate_to(&root.0).is_err() {
            return error(ErrorCode::Denied, "agent ancestry changed");
        }
        let metadata = match state.store.metadata(peer.uid, key) {
            Ok(metadata) if !metadata.deleted => metadata,
            Ok(_) => return storage_error(store::Error::Tombstoned),
            Err(failure) => return storage_error(failure),
        };
        if state.grants.iter().any(|g| {
            g.owner == peer.uid && g.root == root.0 && g.key == key && g.version == metadata.version
        }) {
            return match state.store.read(peer.uid, key) {
                Ok(record) => Response::Value {
                    value: record.secret.as_bytes().to_vec(),
                },
                Err(failure) => storage_error(failure),
            };
        }
        if non_interactive {
            return error(
                ErrorCode::Denied,
                "no applicable grant; non-interactive mode never opens a prompt",
            );
        }
        let epoch = *state.revocation_epochs.get(&peer.uid).unwrap_or(&0);
        drop(state);
        let Some(mut prompt) = PromptGuard::acquire(&self.prompting, peer.uid) else {
            return error(
                ErrorCode::Unavailable,
                "another approval is pending or cleanup is unconfirmed for this user",
            );
        };
        let message = |scope| {
            format!(
                "Allow {} (PID {}, started {}) to read secret {} version {} for {}? The agent will receive the secret, not root privileges.",
                root.1.name, root.1.pid, root.1.start_time, key, metadata.version, scope
            )
        };
        let choice = match auth::approve_read(
            &self.auth,
            subject,
            &message("this one request"),
            &message("this agent process and its live descendants until it exits"),
        ) {
            Ok(Some(choice)) => choice,
            Ok(None) => return error(ErrorCode::Denied, "administrator authorization denied"),
            Err(failure) => {
                if failure.is::<auth::CleanupError>() {
                    prompt.keep();
                }
                eprintln!("approval unavailable for uid {}: {failure:#}", subject.uid);
                return error(
                    ErrorCode::Unavailable,
                    "approval unavailable; requires a local unlocked desktop, user manager and installed policy",
                );
            }
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error(ErrorCode::Internal, "state unavailable"),
        };
        state.prune();
        if *state.revocation_epochs.get(&peer.uid).unwrap_or(&0) != epoch {
            return error(
                ErrorCode::Denied,
                "grants were revoked while this approval was pending",
            );
        }
        if ancestry.validate_to(&root.0).is_err() {
            return error(
                ErrorCode::Denied,
                "requester detached or agent exited during approval",
            );
        }
        let current = match state.store.metadata(peer.uid, key) {
            Ok(value) => value,
            Err(failure) => return storage_error(failure),
        };
        if current.deleted || current.version != metadata.version {
            return error(
                ErrorCode::Conflict,
                "secret changed during approval; request again",
            );
        }
        if !state
            .roots
            .iter()
            .any(|r| r.owner == peer.uid && r.process.identity() == &root.0)
        {
            let pinned = match PinnedProcess::capture(root.0.pid) {
                Ok(value) => value,
                Err(_) => return error(ErrorCode::Denied, "agent exited"),
            };
            if pinned.identity() != &root.0 || ancestry.validate_to(&root.0).is_err() {
                return error(ErrorCode::Denied, "agent process identity changed");
            }
            state.roots.push(Root {
                owner: peer.uid,
                process: pinned,
                agent: root.1,
            });
        }
        if matches!(choice, GrantChoice::Run)
            && !state.grants.iter().any(|g| {
                g.owner == peer.uid
                    && g.root == root.0
                    && g.key == key
                    && g.version == metadata.version
            })
        {
            state.grants.push(Grant {
                owner: peer.uid,
                root: root.0,
                key: key.into(),
                version: metadata.version,
            });
        }
        // A one-time authorization is never stored or shared with another request.
        match state.store.read(peer.uid, key) {
            Ok(record) => Response::Value {
                value: record.secret.as_bytes().to_vec(),
            },
            Err(failure) => storage_error(failure),
        }
    }

    fn mutate(
        &self,
        process: &PinnedProcess,
        subject: &Subject,
        key: &str,
        value: Option<&Vec<u8>>,
    ) -> Response {
        if let Err(failure) = store::validate_key(key) {
            return storage_error(failure);
        }
        if value.is_some_and(|value| value.len() > store::MAX_SECRET_LEN) {
            return storage_error(store::Error::SecretTooLarge);
        }
        let metadata = {
            let state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return error(ErrorCode::Internal, "state unavailable"),
            };
            match state.store.metadata(subject.uid, key) {
                Ok(value) if !value.deleted => value,
                Ok(_) => return storage_error(store::Error::Tombstoned),
                Err(failure) => return storage_error(failure),
            }
        };
        let Some(mut prompt) = PromptGuard::acquire(&self.prompting, subject.uid) else {
            return error(
                ErrorCode::Unavailable,
                "another approval is pending for this user; retry afterward",
            );
        };
        let (verb, action) = if value.is_some() {
            ("Replace", "io.github.from-nibly.agent-keyring.replace")
        } else {
            ("Delete", "io.github.from-nibly.agent-keyring.delete")
        };
        let message = format!(
            "{verb} secret {key} version {} for user {}? Existing read grants will be invalidated.",
            metadata.version, subject.uid
        );
        match auth::authorize(&self.auth, subject, action, &message) {
            Ok(true) => {}
            Ok(false) => return error(ErrorCode::Denied, "administrator authorization denied"),
            Err(failure) => {
                if failure.is::<auth::CleanupError>() {
                    prompt.keep();
                }
                eprintln!(
                    "administrator authorization unavailable for uid {}: {failure:#}",
                    subject.uid
                );
                return error(
                    ErrorCode::Unavailable,
                    "administrator authorization unavailable",
                );
            }
        }
        if process.validate().is_err() {
            return error(ErrorCode::Denied, "requester exited or changed identity");
        }
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error(ErrorCode::Internal, "state unavailable"),
        };
        let current = match state.store.metadata(subject.uid, key) {
            Ok(value) => value,
            Err(failure) => return storage_error(failure),
        };
        if current.version != metadata.version || current.deleted {
            return error(
                ErrorCode::Conflict,
                "secret changed during authorization; request again",
            );
        }
        let result = match value {
            Some(value) => state
                .store
                .replace(subject.uid, key, metadata.version, value),
            None => state.store.delete(subject.uid, key),
        };
        match result {
            Ok(metadata) => {
                state
                    .grants
                    .retain(|g| g.owner != subject.uid || g.key != key);
                Response::Written {
                    version: metadata.version,
                }
            }
            Err(failure) => storage_error(failure),
        }
    }

    fn revoke(&self, peer: &Peer, all: bool, key: Option<&str>) -> Response {
        if let Some(key) = key {
            if let Err(failure) = store::validate_key(key) {
                return storage_error(failure);
            }
        }
        let ancestry = if all {
            None
        } else {
            match Ancestry::capture(peer.pid, peer.uid, &peer.pidfd) {
                Ok(value) => Some(value),
                Err(_) => return error(ErrorCode::Denied, "cannot verify live ancestry"),
            }
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error(ErrorCode::Internal, "state unavailable"),
        };
        state.prune();
        let selected = match ancestry.as_ref() {
            Some(chain) => match select_root(&state, chain, peer.uid) {
                Some((identity, _)) if chain.validate_to(&identity).is_ok() => Some(identity),
                _ => {
                    return error(
                        ErrorCode::NotAgent,
                        "no live agent ancestor; use --all to revoke your grants from a terminal",
                    );
                }
            },
            None => None,
        };
        let before = state.grants.len();
        let epoch = state.revocation_epochs.entry(peer.uid).or_default();
        let Some(next_epoch) = epoch.checked_add(1) else {
            return error(
                ErrorCode::Internal,
                "revocation counter exhausted; restart the daemon",
            );
        };
        *epoch = next_epoch;
        state.grants.retain(|g| {
            !(g.owner == peer.uid
                && selected.as_ref().is_none_or(|root| root == &g.root)
                && key.is_none_or(|key| key == g.key))
        });
        Response::Revoked {
            count: before - state.grants.len(),
        }
    }
}

fn select_root(state: &State, ancestry: &Ancestry, uid: u32) -> Option<(ProcessIdentity, Agent)> {
    // An explicitly approved nearer root is a separate scope; do not fall back
    // to an outer grant merely because the nearer root lacks this secret.
    for process in ancestry.processes() {
        if let Some(root) = state
            .roots
            .iter()
            .find(|r| r.owner == uid && r.process.identity() == process.identity())
        {
            return Some((process.identity().clone(), root.agent.clone()));
        }
    }
    ancestry.processes().iter().rev().find_map(|process| {
        if process.identity().uid != uid {
            return None;
        }
        let name = process.agent_name().ok()??;
        let identity = process.identity().clone();
        Some((
            identity.clone(),
            Agent {
                name,
                pid: identity.pid,
                start_time: identity.start_time,
                executable: process.executable().ok()?,
            },
        ))
    })
}

struct PromptGuard<'a> {
    prompts: &'a Mutex<HashSet<u32>>,
    uid: u32,
    keep: bool,
}
impl<'a> PromptGuard<'a> {
    fn acquire(prompts: &'a Mutex<HashSet<u32>>, uid: u32) -> Option<Self> {
        if !prompts.lock().ok()?.insert(uid) {
            return None;
        }
        Some(Self {
            prompts,
            uid,
            keep: false,
        })
    }
    fn keep(&mut self) {
        self.keep = true;
    }
}
impl Drop for PromptGuard<'_> {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if let Ok(mut prompts) = self.prompts.lock() {
            prompts.remove(&self.uid);
        }
    }
}

pub fn validate_socket_parent(socket: &Path) -> Result<()> {
    if !socket.is_absolute()
        || socket
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        bail!("socket path must be absolute without traversal");
    }
    let parent = socket.parent().context("socket has no parent")?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        let sticky_root =
            metadata.uid() == 0 && metadata.mode() & libc::S_ISVTX != 0 && ancestor != parent;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || (metadata.mode() & 0o022 != 0 && !sticky_root)
        {
            bail!("socket directory ancestry must be root-owned and not writable by other users");
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(socket) {
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            bail!("socket must be a root-owned Unix socket");
        }
    }
    Ok(())
}

fn lock_state(directory: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(directory.join("daemon.lock"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        bail!("unsafe daemon lock file");
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another daemon holds this vault's lock");
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Broker, Peer) {
        use std::os::fd::{FromRawFd, OwnedFd};
        let directory = tempfile::tempdir().unwrap();
        let pid = std::process::id() as i32;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        assert!(raw >= 0);
        let peer = Peer {
            pid,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            pidfd: unsafe { OwnedFd::from_raw_fd(raw as i32) },
        };
        let root = PinnedProcess::from_peer(peer.pid, peer.uid, &peer.pidfd).unwrap();
        let identity = root.identity().clone();
        let broker = Broker {
            state: Mutex::new(State {
                store: Store::open(directory.path().join("vault")).unwrap(),
                // Synthetic prior root confirmation: no GUI/polkit call occurs in
                // these grant-use tests; authentication is tested separately.
                roots: vec![Root {
                    owner: peer.uid,
                    process: root,
                    agent: Agent {
                        name: "test agent".into(),
                        pid,
                        start_time: identity.start_time,
                        executable: "/test/agent".into(),
                    },
                }],
                grants: Vec::new(),
                revocation_epochs: HashMap::new(),
            }),
            prompting: Mutex::new(HashSet::new()),
            auth: auth::Config::default(),
            clients: Mutex::new(HashMap::new()),
        };
        (directory, broker, peer)
    }

    fn seed_grant(broker: &Broker, peer: &Peer, key: &str, version: u64) {
        let mut state = broker.state.lock().unwrap();
        let root = state.roots[0].process.identity().clone();
        state.grants.push(Grant {
            owner: peer.uid,
            root,
            key: key.into(),
            version,
        });
    }

    #[test]
    fn create_never_grants_read_or_overwrites() {
        let (_directory, broker, peer) = fixture();
        let create = Request::Create {
            key: "test.key".into(),
            value: b"synthetic".to_vec(),
        };
        assert!(matches!(
            broker.handle(&create, &peer),
            Response::Written { version: 1 }
        ));
        assert!(matches!(
            broker.handle(&create, &peer),
            Response::Error {
                code: ErrorCode::AlreadyExists,
                ..
            }
        ));
        let get = Request::Get {
            key: "test.key".into(),
            non_interactive: true,
        };
        assert!(matches!(
            broker.handle(&get, &peer),
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ));
        assert!(broker.state.lock().unwrap().grants.is_empty());
    }

    #[test]
    fn run_grants_are_key_version_and_owner_scoped() {
        let (_directory, broker, peer) = fixture();
        {
            let mut state = broker.state.lock().unwrap();
            state.store.create(peer.uid, "test.one", b"one").unwrap();
            state.store.create(peer.uid, "test.two", b"two").unwrap();
        }
        seed_grant(&broker, &peer, "test.one", 1);
        let one = Request::Get {
            key: "test.one".into(),
            non_interactive: true,
        };
        let two = Request::Get {
            key: "test.two".into(),
            non_interactive: true,
        };
        assert!(
            matches!(&broker.handle(&one, &peer), Response::Value { value } if value == b"one")
        );
        assert!(matches!(
            broker.handle(&two, &peer),
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ));
        broker
            .state
            .lock()
            .unwrap()
            .store
            .replace(peer.uid, "test.one", 1, b"new")
            .unwrap();
        assert!(matches!(
            broker.handle(&one, &peer),
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ));
        broker.state.lock().unwrap().grants[0].owner = peer.uid.wrapping_add(1);
        assert!(matches!(
            broker.handle(&one, &peer),
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ));
    }

    #[test]
    fn revoke_removes_access_and_invalidates_pending_approval_epoch() {
        let (_directory, broker, peer) = fixture();
        broker
            .state
            .lock()
            .unwrap()
            .store
            .create(peer.uid, "test.key", b"synthetic")
            .unwrap();
        seed_grant(&broker, &peer, "test.key", 1);
        assert!(matches!(
            broker.handle(
                &Request::Revoke {
                    all: true,
                    key: None
                },
                &peer
            ),
            Response::Revoked { count: 1 }
        ));
        let state = broker.state.lock().unwrap();
        assert_eq!(state.revocation_epochs[&peer.uid], 1);
        assert!(state.grants.is_empty());
        drop(state);
        assert!(matches!(
            broker.handle(
                &Request::Get {
                    key: "test.key".into(),
                    non_interactive: true
                },
                &peer
            ),
            Response::Error {
                code: ErrorCode::Denied,
                ..
            }
        ));
    }

    #[test]
    fn connection_limits_leave_capacity_for_other_users() {
        let clients = Mutex::new(HashMap::new());
        for _ in 0..8 {
            assert!(reserve_client(&clients, 1000));
        }
        assert!(!reserve_client(&clients, 1000));
        assert!(reserve_client(&clients, 1001));
        release_client(&clients, 1000);
        assert!(reserve_client(&clients, 1000));
        release_client(&clients, 1001);
        assert!(!clients.lock().unwrap().contains_key(&1001));
    }

    #[test]
    fn one_prompt_per_owner_and_drop_releases_it() {
        let prompts = Mutex::new(HashSet::new());
        let first = PromptGuard::acquire(&prompts, 1000).unwrap();
        assert!(PromptGuard::acquire(&prompts, 1000).is_none());
        assert!(PromptGuard::acquire(&prompts, 1001).is_some());
        drop(first);
        assert!(PromptGuard::acquire(&prompts, 1000).is_some());
    }
    #[test]
    fn unconfirmed_cleanup_keeps_owner_fenced_after_request_returns() {
        let prompts = Mutex::new(HashSet::new());
        let mut guard = PromptGuard::acquire(&prompts, 1000).unwrap();
        guard.keep();
        drop(guard);
        assert!(PromptGuard::acquire(&prompts, 1000).is_none());
        assert!(PromptGuard::acquire(&prompts, 1001).is_some());
    }
    #[test]
    fn socket_paths_reject_user_owned_directories() {
        let directory = tempfile::tempdir().unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(validate_socket_parent(&directory.path().join("socket")).is_err());
        }
        assert!(validate_socket_parent(Path::new("relative.sock")).is_err());
        assert!(validate_socket_parent(Path::new("/run/../socket")).is_err());
    }
}
