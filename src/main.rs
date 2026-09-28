use agent_keyring::{daemon, ipc::Channel, protocol::*, store};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "GUI-approved, process-scoped secrets for coding agents"
)]
struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read a secret after administrator approval for the live agent ancestor.
    Get {
        key: String,
        /// Never open a prompt; require an existing run grant.
        #[arg(long)]
        non_interactive: bool,
    },
    /// Create a new secret; fails if this key has ever been used.
    Set { key: String },
    /// Replace an existing secret after administrator authentication.
    Replace { key: String },
    /// Delete an existing secret after administrator authentication.
    Delete { key: String },
    /// List this user's active grants (never secret values).
    Grants,
    /// Revoke grants for the current agent, or all of this user's agents.
    Revoke {
        #[arg(long)]
        all: bool,
        #[arg(long, conflicts_with = "all")]
        current: bool,
        #[arg(long)]
        key: Option<String>,
    },
    /// Verify that the root-owned daemon is reachable.
    Status,
    /// Run the privileged system service (normally started by systemd).
    Daemon {
        #[arg(long, default_value = "/var/lib/agent-keyring")]
        state_dir: PathBuf,
        #[arg(long, default_value = "/usr/local/libexec/agent-keyring-approval")]
        approval_agent: PathBuf,
        #[arg(long, default_value = "/usr/bin/pkcheck")]
        pkcheck: PathBuf,
        #[arg(long, default_value = "/usr/bin/loginctl")]
        loginctl: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("agent-keyring: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    if let Command::Daemon {
        state_dir,
        approval_agent,
        pkcheck,
        loginctl,
    } = &cli.command
    {
        return daemon::run(daemon::Config {
            socket: cli.socket,
            state_dir: state_dir.clone(),
            auth: agent_keyring::auth::Config {
                approval_agent: approval_agent.clone(),
                pkcheck: pkcheck.clone(),
                loginctl: loginctl.clone(),
                timeout: std::time::Duration::from_secs(60),
            },
        })
        .map(|()| 0);
    }
    let request = match cli.command {
        Command::Get {
            key,
            non_interactive,
        } => {
            store::validate_key(&key)?;
            Request::Get {
                key,
                non_interactive,
            }
        }
        Command::Set { key } => {
            store::validate_key(&key)?;
            Request::Create {
                key,
                value: read_value()?.to_vec(),
            }
        }
        Command::Replace { key } => {
            store::validate_key(&key)?;
            Request::Replace {
                key,
                value: read_value()?.to_vec(),
            }
        }
        Command::Delete { key } => {
            store::validate_key(&key)?;
            Request::Delete { key }
        }
        Command::Grants => Request::Grants,
        Command::Revoke { all, key, .. } => Request::Revoke { all, key },
        Command::Status => Request::Ping,
        Command::Daemon { .. } => unreachable!(),
    };
    // Authenticate the server before sending a secret-bearing request. Directory
    // ownership also prevents a same-user process replacing the endpoint.
    daemon::validate_socket_parent(&cli.socket)?;
    let channel = Channel::connect(&cli.socket)
        .context("connect to daemon; is agent-keyring.service installed and running?")?;
    channel.send(&Request::Ping)?;
    let (response, peer) = channel.receive::<Response>()?;
    if peer.uid != 0 || !peer.is_alive()? || !matches!(response, Response::Pong { .. }) {
        bail!("endpoint did not authenticate as the root-owned agent-keyring daemon");
    }
    // Each operation uses a fresh connection. The parent directory is immutable
    // to unprivileged callers; only root can replace the authenticated endpoint.
    let channel = Channel::connect(&cli.socket)?;
    channel.send(&request)?;
    let (response, peer) = channel.receive::<Response>()?;
    if peer.uid != 0 {
        bail!("refusing a response from a non-root peer");
    }
    match &response {
        Response::Value { value } => io::stdout().lock().write_all(value)?,
        Response::Written { version } => eprintln!("Saved version {version}."),
        Response::Grants { grants } => {
            serde_json::to_writer_pretty(io::stdout().lock(), grants)?;
            println!();
        }
        Response::Revoked { count } => eprintln!("Revoked {count} grant(s)."),
        Response::Pong { version } => println!("agent-keyring daemon {version}"),
        Response::Error { code, message } => {
            eprintln!("agent-keyring: {message}");
            return Ok(code.exit_status());
        }
    }
    Ok(0)
}

fn read_value() -> Result<Zeroizing<Vec<u8>>> {
    let stdin = io::stdin();
    let mut value = Zeroizing::new(Vec::new());
    if stdin.is_terminal() {
        eprint!("Secret: ");
        io::stderr().flush()?;
        let _echo = HiddenInput::new(stdin.as_raw_fd())?;
        // A terminal entry ends at its line delimiter; redirected input preserves
        // every byte, including trailing newlines and NULs.
        for byte in stdin.lock().bytes() {
            let byte = byte?;
            if byte == b'\n' {
                break;
            }
            value.push(byte);
            if value.len() > store::MAX_SECRET_LEN {
                bail!("secret exceeds 64 KiB");
            }
        }
        eprintln!();
    } else {
        stdin
            .lock()
            .take((store::MAX_SECRET_LEN + 1) as u64)
            .read_to_end(&mut value)?;
        if value.len() > store::MAX_SECRET_LEN {
            bail!("secret exceeds 64 KiB");
        }
    }
    Ok(value)
}

struct HiddenInput {
    fd: i32,
    previous: libc::termios,
}
impl HiddenInput {
    fn new(fd: i32) -> Result<Self> {
        let mut previous = std::mem::MaybeUninit::uninit();
        // SAFETY: valid terminal descriptor and initialized output on success.
        if unsafe { libc::tcgetattr(fd, previous.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let previous = unsafe { previous.assume_init() };
        let mut hidden = previous;
        hidden.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self { fd, previous })
    }
}
impl Drop for HiddenInput {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.previous);
        }
    }
}
