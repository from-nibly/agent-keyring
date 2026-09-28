//! Linux, per-message authenticated SOCK_SEQPACKET transport (kernel >= 6.5).
//!
//! Authentication describes the process sending each packet, not the process that
//! originally connected. This trusts the host kernel and privileged host processes.

use std::fmt;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

// Linux UAPI constants, including those missing from older libc crate versions.
const SO_PASSPIDFD: libc::c_int = 76;
const SCM_PIDFD: libc::c_int = 4;
const MAX_FRAME: usize = 300 * 1024;
// Read approval shares one 60-second deadline across GUI/check generations and
// session validation, followed by bounded service cleanup and response delivery.
const TIMEOUT_SECONDS: libc::c_int = 180;
// Aligned storage, with room for credentials, a pidfd, and malicious SCM_RIGHTS.
// Linux permits at most 253 SCM_RIGHTS descriptors in a message.
const CONTROL_WORDS: usize = 256;

pub struct Peer {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    pub pidfd: OwnedFd,
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("pid", &self.pid)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .finish_non_exhaustive()
    }
}

impl Peer {
    /// A snapshot of process liveness; the pidfd remains bound across PID reuse.
    pub fn is_alive(&self) -> io::Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: descriptor points to one initialized pollfd.
            let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("pidfd poll failed"));
            }
            return Ok(descriptor.revents & (libc::POLLIN | libc::POLLHUP) == 0);
        }
    }
}

pub struct Channel {
    fd: OwnedFd,
}

impl Channel {
    pub fn connect(path: &Path) -> io::Result<Self> {
        let (address, length) = address(path)?;
        let fd = socket()?;
        // Must precede connect: the server can respond before connect returns.
        configure(fd.as_raw_fd())?;
        // SAFETY: address is initialized and length describes its occupied bytes.
        let result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Connection-time identity for resource accounting only. Operation authority
    /// always comes from the per-message credentials returned by receive().
    pub fn connecting_uid(&self) -> io::Result<u32> {
        let mut credentials: libc::ucred = unsafe { zeroed() };
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || length as usize != size_of::<libc::ucred>()
        {
            return Err(io::Error::last_os_error());
        }
        Ok(credentials.uid)
    }

    pub fn send<T: Serialize>(&self, value: &T) -> anyhow::Result<()> {
        let mut frame = Zeroizing::new(Vec::new());
        // Serializer/deserializer error text can embed secret values.
        serde_json::to_writer(&mut *frame, value)
            .map_err(|_| anyhow!("could not serialize IPC frame"))?;
        if frame.is_empty() || frame.len() > MAX_FRAME {
            bail!("IPC frame length out of bounds");
        }
        loop {
            // SAFETY: frame is readable for its full length; send retains no pointer.
            let sent = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    frame.as_ptr().cast(),
                    frame.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if sent < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("send IPC frame");
            }
            if sent as usize != frame.len() {
                bail!("short IPC packet send");
            }
            return Ok(());
        }
    }

    pub fn receive<T: DeserializeOwned>(&self) -> anyhow::Result<(T, Peer)> {
        let mut frame = Zeroizing::new(vec![0_u8; MAX_FRAME]);
        loop {
            let mut control = [0_usize; CONTROL_WORDS];
            let mut iov = libc::iovec {
                iov_base: frame.as_mut_ptr().cast(),
                iov_len: frame.len(),
            };
            // SAFETY: all-zero msghdr is valid before setting its buffer fields.
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            // musl uses socklen_t here, while glibc uses size_t.
            message.msg_controllen = u32::try_from(size_of_val(&control))? as _;
            // SAFETY: all output buffers are live, writable, and correctly aligned.
            let received =
                unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("receive IPC frame");
            }
            // Adopt every delivered descriptor before examining payload or flags.
            // Even a truncated/invalid packet can carry descriptors we must close.
            // SAFETY: control came from recvmsg, and none of its fds were adopted yet.
            let peer =
                unsafe { parse_peer(&control, message.msg_controllen as _, message.msg_flags) }?;
            if received == 0 || received as usize > MAX_FRAME {
                bail!("empty or oversized IPC frame");
            }
            let value = serde_json::from_slice(&frame[..received as usize])
                .map_err(|_| anyhow!("invalid IPC JSON frame"))?;
            return Ok((value, peer));
        }
    }
}

pub struct Listener {
    fd: OwnedFd,
}

impl Listener {
    /// Bind without removing an existing filesystem entry or creating directories.
    pub fn bind(path: &Path) -> anyhow::Result<Self> {
        let (address, length) = address(path)?;
        let fd = socket()?;
        // Accepted sockets inherit authentication even for pre-accept packets.
        configure(fd.as_raw_fd())?;
        // SO_RCVTIMEO also affects accept4: an idle listener must not restart the
        // daemon and discard grants. Accepted channels get their own deadlines.
        set_option(
            fd.as_raw_fd(),
            libc::SO_RCVTIMEO,
            &libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        )?;
        // SAFETY: address is initialized and length is within its allocation.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error()).context("bind IPC listener");
        }
        // SAFETY: fd is a live SOCK_SEQPACKET socket.
        if unsafe { libc::listen(fd.as_raw_fd(), 128) } < 0 {
            return Err(io::Error::last_os_error()).context("listen on IPC socket");
        }
        Ok(Self { fd })
    }

    pub fn accept(&self) -> io::Result<Channel> {
        loop {
            // SAFETY: null address arguments request no peer address output.
            let raw = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if raw < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            // SAFETY: accept4 returned a new descriptor owned by this call.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            // Do not repair missing inheritance: queued packets may lack identity.
            validate_authentication(fd.as_raw_fd())?;
            configure_io(fd.as_raw_fd())?;
            // Clients send exactly one packet immediately. Only clients waiting
            // for GUI/polkit responses need the long receive timeout.
            set_option(
                fd.as_raw_fd(),
                libc::SO_RCVTIMEO,
                &libc::timeval {
                    tv_sec: 2,
                    tv_usec: 0,
                },
            )?;
            return Ok(Channel { fd });
        }
    }
}

fn socket() -> io::Result<OwnedFd> {
    // SAFETY: socket has no pointer arguments.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: zero initializes the entire sockaddr_un, including trailing NUL.
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Unix socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    Ok((address, length as libc::socklen_t))
}

fn set_option<T>(fd: RawFd, option: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: the option-specific callers supply the correct value type and size.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn int_option(fd: RawFd, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: value and length are writable and sized for an integer socket option.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::c_int>() {
        return Err(io::Error::other("invalid socket option size"));
    }
    Ok(value)
}

fn configure(fd: RawFd) -> io::Result<()> {
    set_option(fd, libc::SO_PASSCRED, &1_i32)?;
    // ENOPROTOOPT is fatal: never fall back to connection-time SO_PEERCRED.
    set_option(fd, SO_PASSPIDFD, &1_i32)?;
    validate_authentication(fd)?;
    configure_io(fd)
}

fn validate_authentication(fd: RawFd) -> io::Result<()> {
    if int_option(fd, libc::SO_PASSCRED)? != 1 || int_option(fd, SO_PASSPIDFD)? != 1 {
        return Err(io::Error::other(
            "per-message authentication is not enabled",
        ));
    }
    Ok(())
}

fn configure_io(fd: RawFd) -> io::Result<()> {
    for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        set_option(fd, option, &(MAX_FRAME as libc::c_int))?;
        // Linux doubles the requested value but may cap it at a sysctl limit.
        if int_option(fd, option)? < (MAX_FRAME + 32) as libc::c_int {
            return Err(io::Error::other(
                "socket buffer limit is too small for IPC frames",
            ));
        }
    }
    let timeout = libc::timeval {
        tv_sec: TIMEOUT_SECONDS.into(),
        tv_usec: 0,
    };
    set_option(fd, libc::SO_RCVTIMEO, &timeout)?;
    set_option(fd, libc::SO_SNDTIMEO, &timeout)
}

// SAFETY: control must contain kernel-produced ancillary data whose installed
// descriptors have not yet been adopted. This function takes ownership of them.
unsafe fn parse_peer(control: &[usize], length: usize, flags: libc::c_int) -> io::Result<Peer> {
    let mut credentials = None;
    let mut pidfds = Vec::new();
    let mut unexpected_fds = Vec::new();
    let mut invalid = flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
    let available = size_of_val(control);
    invalid |= length > available;
    let length = length.min(available);
    let mut offset = 0;
    // SAFETY: CMSG_LEN(0) is a constant-sized header calculation.
    let header_length = unsafe { libc::CMSG_LEN(0) } as usize;
    while offset + size_of::<libc::cmsghdr>() <= length {
        // SAFETY: header fits in the control allocation; unaligned read is permitted.
        let header = unsafe {
            std::ptr::read_unaligned(
                control
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<libc::cmsghdr>(),
            )
        };
        // Linux libc exposes this as either socklen_t or size_t; both fit usize.
        let cmsg_length: usize = header.cmsg_len as _;
        if cmsg_length < header_length || cmsg_length > length - offset {
            invalid = true;
            break;
        }
        let data_length = cmsg_length - header_length;
        // SAFETY: header and payload lengths were checked against the allocation.
        let data = unsafe { control.as_ptr().cast::<u8>().add(offset + header_length) };
        match (header.cmsg_level, header.cmsg_type) {
            (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) => {
                if data_length != size_of::<libc::ucred>() || credentials.is_some() {
                    invalid = true;
                } else {
                    // SAFETY: exactly one complete ucred is present.
                    credentials =
                        Some(unsafe { std::ptr::read_unaligned(data.cast::<libc::ucred>()) });
                }
            }
            (libc::SOL_SOCKET, kind) if kind == SCM_PIDFD || kind == libc::SCM_RIGHTS => {
                if kind == libc::SCM_RIGHTS || data_length != size_of::<RawFd>() {
                    invalid = true;
                }
                for index in 0..data_length / size_of::<RawFd>() {
                    // SAFETY: each complete descriptor fits in the payload.
                    let raw = unsafe {
                        std::ptr::read_unaligned(
                            data.add(index * size_of::<RawFd>()).cast::<RawFd>(),
                        )
                    };
                    if raw < 0 {
                        invalid = true;
                        continue;
                    }
                    // SAFETY: recvmsg installed a new owned fd for each entry.
                    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
                    if kind == SCM_PIDFD {
                        pidfds.push(fd);
                    } else {
                        unexpected_fds.push(fd);
                    }
                }
            }
            _ => invalid = true,
        }
        let alignment = size_of::<usize>();
        offset += (cmsg_length + alignment - 1) & !(alignment - 1);
    }
    if invalid || credentials.is_none() || pidfds.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IPC authentication or truncated packet",
        ));
    }
    let credentials = credentials.unwrap();
    if credentials.pid <= 0 || credentials.uid == u32::MAX || credentials.gid == u32::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IPC credentials",
        ));
    }
    Ok(Peer {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
        pidfd: pidfds.pop().unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;
    use std::os::unix::ffi::OsStringExt;

    fn channels() -> (tempfile::TempDir, Channel, Channel) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ipc.sock");
        let listener = Listener::bind(&path).unwrap();
        let client = Channel::connect(&path).unwrap();
        let server = listener.accept().unwrap();
        (directory, client, server)
    }

    fn assert_cloexec(fd: RawFd) {
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }

    fn assert_eof(fd: &OwnedFd) {
        // Concurrent process tests may fork while a CLOEXEC pipe is open. Their
        // transient copy closes at exec/exit; require EOF within a bound rather
        // than confusing that short inheritance window with a transport leak.
        let mut event = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut event, 1, 3000) };
        assert_eq!(ready, 1, "received ancillary fd remained open");
        let mut byte = 0_u8;
        assert_eq!(
            unsafe { libc::read(fd.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            0,
            "received ancillary fd leaked"
        );
    }

    fn send_raw(fd: RawFd, payload: &[u8]) {
        assert_eq!(
            unsafe {
                libc::send(
                    fd,
                    payload.as_ptr().cast(),
                    payload.len(),
                    libc::MSG_NOSIGNAL,
                )
            },
            payload.len() as isize,
            "raw packet send failed: {}",
            io::Error::last_os_error()
        );
    }

    fn push_control(control: &mut [usize], length: &mut usize, kind: i32, bytes: &[u8]) {
        let data_length = u32::try_from(bytes.len()).unwrap();
        let space = unsafe { libc::CMSG_SPACE(data_length) } as usize;
        assert!(*length + space <= size_of_val(control));
        unsafe {
            let header = control
                .as_mut_ptr()
                .cast::<u8>()
                .add(*length)
                .cast::<libc::cmsghdr>();
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = kind;
            (*header).cmsg_len = libc::CMSG_LEN(data_length) as _;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), libc::CMSG_DATA(header), bytes.len());
        }
        *length += space;
    }

    fn send_rights(socket: RawFd, descriptors: &[RawFd], payload: &[u8]) {
        let mut control = [0_usize; CONTROL_WORDS];
        let mut length = 0;
        let bytes = unsafe {
            std::slice::from_raw_parts(descriptors.as_ptr().cast::<u8>(), size_of_val(descriptors))
        };
        push_control(&mut control, &mut length, libc::SCM_RIGHTS, bytes);
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = u32::try_from(length).unwrap() as _;
        assert_eq!(
            unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) },
            payload.len() as isize
        );
    }

    #[test]
    fn queued_request_and_response_authenticate_and_support_64k_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ipc.sock");
        let listener = Listener::bind(&path).unwrap();
        let client = Channel::connect(&path).unwrap();
        let payload = vec![255_u8; 64 * 1024];
        // Authentication must work on data queued before the server accepts.
        client.send(&payload).unwrap();
        let server = listener.accept().unwrap();
        let (received, peer) = server.receive::<Vec<u8>>().unwrap();
        assert_eq!(received, payload);
        assert_eq!(peer.pid, unsafe { libc::getpid() });
        assert_eq!(peer.uid, unsafe { libc::getuid() });
        assert_eq!(peer.gid, unsafe { libc::getgid() });
        assert!(peer.is_alive().unwrap());
        for fd in [
            listener.fd.as_raw_fd(),
            client.fd.as_raw_fd(),
            server.fd.as_raw_fd(),
            peer.pidfd.as_raw_fd(),
        ] {
            assert_cloexec(fd);
        }
        server.send(&payload).unwrap();
        let (received, response_peer) = client.receive::<Vec<u8>>().unwrap();
        assert_eq!(received, payload);
        assert_eq!(response_peer.pid, peer.pid);
        assert_cloexec(response_peer.pidfd.as_raw_fd());
        assert!(!format!("{peer:?}").contains("pidfd"));
    }

    #[test]
    fn rejects_invalid_paths_and_preserves_existing_entries() {
        assert!(Channel::connect(Path::new(&"x".repeat(108))).is_err());
        assert!(Listener::bind(Path::new(&"x".repeat(108))).is_err());
        assert!(address(Path::new(&"x".repeat(107))).is_ok());
        assert!(address(Path::new("")).is_err());
        let nul = std::ffi::OsString::from_vec(b"bad\0path".to_vec());
        assert!(address(Path::new(&nul)).is_err());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("occupied");
        std::fs::write(&path, b"keep me").unwrap();
        assert!(Listener::bind(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
        let socket_path = directory.path().join("socket");
        let listener = Listener::bind(&socket_path).unwrap();
        assert!(Listener::bind(&socket_path).is_err());
        drop(listener);
        assert!(socket_path.exists());
        assert!(Listener::bind(&directory.path().join("missing/socket")).is_err());
        assert!(!directory.path().join("missing").exists());
    }

    #[test]
    fn rejects_malformed_empty_and_oversized_packets_without_merging_packets() {
        let (_directory, client, server) = channels();
        for payload in [b"{invalid".as_slice(), b"{}{}", b"\xff", b"", b"   "] {
            send_raw(client.fd.as_raw_fd(), payload);
            assert!(server.receive::<serde_json::Value>().is_err());
            client.send(&42).unwrap();
            assert_eq!(server.receive::<u32>().unwrap().0, 42);
        }
        send_raw(client.fd.as_raw_fd(), &vec![b' '; MAX_FRAME + 1]);
        assert!(server.receive::<serde_json::Value>().is_err());
        // A valid JSON packet at the exact limit is not a truncation.
        let mut maximum = vec![b' '; MAX_FRAME];
        maximum[0] = b'1';
        send_raw(client.fd.as_raw_fd(), &maximum);
        assert_eq!(server.receive::<u32>().unwrap().0, 1);
        assert!(client.send(&"x".repeat(MAX_FRAME)).is_err());
        client.send(&7).unwrap();
        assert_eq!(server.receive::<u32>().unwrap().0, 7);
    }

    #[test]
    fn deserialization_errors_do_not_disclose_payload_values() {
        let (_directory, client, server) = channels();
        client.send(&"private-secret-value").unwrap();
        let error = server.receive::<u32>().unwrap_err();
        assert_eq!(format!("{error:#}"), "invalid IPC JSON frame");
        assert!(!format!("{error:?}").contains("private-secret-value"));
    }

    #[test]
    fn rejected_rights_are_closed_even_with_malformed_or_truncated_payloads() {
        let (_directory, client, server) = channels();
        for payload in [b"{}".to_vec(), b"{bad".to_vec(), vec![b' '; MAX_FRAME + 1]] {
            let (read, write) = pipe();
            // Exercise the kernel maximum, not just a single unexpected fd.
            send_rights(client.fd.as_raw_fd(), &[write.as_raw_fd(); 253], &payload);
            drop(write);
            assert!(server.receive::<serde_json::Value>().is_err());
            assert_eof(&read);
        }
    }

    #[test]
    fn truncated_ancillary_data_closes_delivered_rights() {
        let (_directory, client, server) = channels();
        let (read, write) = pipe();
        send_rights(client.fd.as_raw_fd(), &[write.as_raw_fd(); 253], b"{}");
        drop(write);
        let mut control = [0_usize; 16];
        let mut payload = [0_u8; 2];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = u32::try_from(size_of_val(&control)).unwrap() as _;
        assert_eq!(
            unsafe { libc::recvmsg(server.fd.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) },
            2
        );
        assert_ne!(message.msg_flags & libc::MSG_CTRUNC, 0);
        assert!(
            unsafe { parse_peer(&control, message.msg_controllen as _, message.msg_flags) }
                .is_err()
        );
        assert_eof(&read);
    }

    #[test]
    fn missing_authentication_and_inheritance_fail_closed() {
        let (_directory, client, server) = channels();
        set_option(server.fd.as_raw_fd(), SO_PASSPIDFD, &0_i32).unwrap();
        client.send(&1).unwrap();
        assert!(server.receive::<u32>().is_err());
        set_option(server.fd.as_raw_fd(), SO_PASSPIDFD, &1_i32).unwrap();
        set_option(server.fd.as_raw_fd(), libc::SO_PASSCRED, &0_i32).unwrap();
        client.send(&2).unwrap();
        assert!(server.receive::<u32>().is_err());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let listener = Listener::bind(&path).unwrap();
        set_option(listener.fd.as_raw_fd(), SO_PASSPIDFD, &0_i32).unwrap();
        let _client = Channel::connect(&path).unwrap();
        assert!(listener.accept().is_err());
    }

    #[test]
    fn malformed_ancillary_lengths_are_rejected() {
        let mut control = [0_usize; CONTROL_WORDS];
        // Initialize in zeroed storage, including musl's private header padding.
        let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
        for length in [
            0,
            unsafe { libc::CMSG_LEN(0) } - 1,
            u32::try_from(size_of_val(&control)).unwrap() + 1,
        ] {
            unsafe { (*header).cmsg_len = length as _ };
            let error = unsafe { parse_peer(&control, size_of_val(&control), 0) }.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        // Exercise the native field maximum (u32 on musl, usize on glibc)
        // without narrowing it before the parser's bounds check.
        unsafe { (*header).cmsg_len = !0 };
        let error = unsafe { parse_peer(&control, size_of_val(&control), 0) }.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn ancillary_bounds_and_flags_preserve_descriptor_ownership() {
        for (flags, oversized) in [
            (0, false),
            (libc::MSG_TRUNC, false),
            (libc::MSG_CTRUNC, false),
            (0, true),
        ] {
            let mut control = [0_usize; CONTROL_WORDS];
            let mut length = 0;
            let credentials = libc::ucred {
                pid: unsafe { libc::getpid() },
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&credentials as *const libc::ucred).cast::<u8>(),
                    size_of::<libc::ucred>(),
                )
            };
            push_control(&mut control, &mut length, libc::SCM_CREDENTIALS, bytes);
            let (read, write) = pipe();
            // A synthetic owned fd lets EOF verify cleanup on both success and
            // rejection; this test never polls it as a real pidfd.
            let raw = write.into_raw_fd();
            push_control(&mut control, &mut length, SCM_PIDFD, &raw.to_ne_bytes());
            if oversized {
                length = size_of_val(&control) + 1;
            }
            let result = unsafe { parse_peer(&control, length, flags) };
            if flags == 0 && !oversized {
                let peer = result.unwrap();
                assert_eq!(
                    (peer.pid, peer.uid, peer.gid),
                    (credentials.pid, credentials.uid, credentials.gid)
                );
                assert_eq!(peer.pidfd.as_raw_fd(), raw);
                drop(peer);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
            assert_eof(&read);
        }
    }

    #[test]
    fn duplicate_authentication_closes_all_descriptors() {
        for duplicate_credentials in [false, true] {
            let mut control = [0_usize; CONTROL_WORDS];
            let mut length = 0;
            let credentials = libc::ucred {
                pid: unsafe { libc::getpid() },
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&credentials as *const libc::ucred).cast::<u8>(),
                    size_of::<libc::ucred>(),
                )
            };
            push_control(&mut control, &mut length, libc::SCM_CREDENTIALS, bytes);
            if duplicate_credentials {
                push_control(&mut control, &mut length, libc::SCM_CREDENTIALS, bytes);
            }
            let (read, write) = pipe();
            // Synthetic rejection-only ancillary data: pipe endpoints allow a
            // race-free EOF assertion that every adopted descriptor was closed.
            if !duplicate_credentials {
                let duplicate = write.try_clone().unwrap().into_raw_fd();
                push_control(
                    &mut control,
                    &mut length,
                    SCM_PIDFD,
                    &duplicate.to_ne_bytes(),
                );
            }
            let raw = write.into_raw_fd();
            push_control(&mut control, &mut length, SCM_PIDFD, &raw.to_ne_bytes());
            assert!(unsafe { parse_peer(&control, length, 0) }.is_err());
            assert_eof(&read);
        }
    }

    #[test]
    fn sockets_have_bounded_timeouts_and_sufficient_buffers() {
        let (_directory, client, server) = channels();
        assert_eq!(server.connecting_uid().unwrap(), unsafe { libc::getuid() });
        for (channel, receive_timeout) in [(client, 180), (server, 2)] {
            for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
                let mut timeout: libc::timeval = unsafe { zeroed() };
                let mut length = size_of::<libc::timeval>() as libc::socklen_t;
                assert_eq!(
                    unsafe {
                        libc::getsockopt(
                            channel.fd.as_raw_fd(),
                            libc::SOL_SOCKET,
                            option,
                            (&mut timeout as *mut libc::timeval).cast(),
                            &mut length,
                        )
                    },
                    0
                );
                assert_eq!(
                    timeout.tv_sec,
                    if option == libc::SO_RCVTIMEO {
                        receive_timeout
                    } else {
                        180
                    }
                );
                assert_eq!(timeout.tv_usec, 0);
            }
            for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
                assert!(
                    int_option(channel.fd.as_raw_fd(), option).unwrap() >= (MAX_FRAME + 32) as i32
                );
            }
        }
    }

    #[test]
    fn listener_does_not_expire_while_idle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("idle.sock");
        let listener = Listener::bind(&path).unwrap();
        let mut timeout: libc::timeval = unsafe { zeroed() };
        let mut length = size_of::<libc::timeval>() as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    listener.fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&mut timeout as *mut libc::timeval).cast(),
                    &mut length,
                )
            },
            0
        );
        assert_eq!((timeout.tv_sec, timeout.tv_usec), (0, 0));
        let acceptor = std::thread::spawn(move || listener.accept().unwrap());
        std::thread::sleep(std::time::Duration::from_millis(80));
        let client = Channel::connect(&path).unwrap();
        let server = acceptor.join().unwrap();
        client.send(&42).unwrap();
        assert_eq!(server.receive::<u32>().unwrap().0, 42);
    }

    struct Child(libc::pid_t);

    impl Drop for Child {
        fn drop(&mut self) {
            // Ensure a failed parent assertion cannot strand a blocked child.
            if self.0 > 0 {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                    loop {
                        if libc::waitpid(self.0, std::ptr::null_mut(), 0) >= 0
                            || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                        {
                            break;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn passed_connection_uses_actual_message_sender_and_pidfd_signals_exit() {
        let (_directory, client, server) = channels();
        let mut transfer = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    transfer.as_mut_ptr(),
                )
            },
            0
        );
        let (parent_transfer, child_transfer) = unsafe {
            (
                OwnedFd::from_raw_fd(transfer[0]),
                OwnedFd::from_raw_fd(transfer[1]),
            )
        };
        let client_fd = client.fd.as_raw_fd();
        let server_fd = server.fd.as_raw_fd();
        let parent_fd = parent_transfer.as_raw_fd();
        let child_fd = child_transfer.as_raw_fd();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // Only stack data and async-signal-safe syscalls after fork in this
            // multithreaded test process; never run Rust destructors in the child.
            unsafe {
                libc::close(client_fd);
                libc::close(server_fd);
                libc::close(parent_fd);
                let mut control = [0_usize; 8];
                let mut byte = 0_u8;
                let mut iov = libc::iovec {
                    iov_base: (&mut byte as *mut u8).cast(),
                    iov_len: 1,
                };
                let mut message: libc::msghdr = zeroed();
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                // This fixed eight-word buffer fits either libc length field.
                message.msg_controllen = size_of_val(&control) as _;
                if libc::recvmsg(child_fd, &mut message, libc::MSG_CMSG_CLOEXEC) != 1 {
                    libc::_exit(10);
                }
                let header = libc::CMSG_FIRSTHDR(&message);
                if header.is_null()
                    || (*header).cmsg_level != libc::SOL_SOCKET
                    || (*header).cmsg_type != libc::SCM_RIGHTS
                {
                    libc::_exit(11);
                }
                let passed_fd = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>());
                if libc::send(passed_fd, b"42".as_ptr().cast(), 2, libc::MSG_NOSIGNAL) != 2 {
                    libc::_exit(12);
                }
                // Stay alive until the parent inspects the received pidfd.
                if libc::read(child_fd, (&mut byte as *mut u8).cast(), 1) != 1 {
                    libc::_exit(13);
                }
                libc::_exit(0);
            }
        }
        let mut child = Child(pid);
        drop(child_transfer);
        send_rights(parent_transfer.as_raw_fd(), &[client_fd], b"x");
        let (value, peer) = server.receive::<u32>().unwrap();
        assert_eq!(value, 42);
        assert_eq!(peer.pid, pid);
        assert_ne!(peer.pid, unsafe { libc::getpid() });
        assert_eq!(peer.uid, unsafe { libc::getuid() });
        assert_eq!(peer.gid, unsafe { libc::getgid() });
        assert!(peer.is_alive().unwrap());
        assert_cloexec(peer.pidfd.as_raw_fd());
        send_raw(parent_transfer.as_raw_fd(), b"x");
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        child.0 = 0;
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert!(!peer.is_alive().unwrap());
        // Same connection, a different sender on the next packet.
        client.send(&43).unwrap();
        let (value, peer) = server.receive::<u32>().unwrap();
        assert_eq!(value, 43);
        assert_eq!(peer.pid, unsafe { libc::getpid() });
        assert!(peer.is_alive().unwrap());
    }
}
