#![forbid(unsafe_code)]

//! The `brd --server` side of the SSH hop, and the client half of the
//! management protocol. Nothing here is the daemon: this is the short-lived
//! process ssh starts, which finds or spawns a daemon and relays to it.

use crate::state::{owner, private_dir, socket_name, state_dir};
use crate::{FRAME_LENGTH_PREFIX, MANAGE_DEADLINE, RELAY_CHUNK, ServerError};
use braid_proto::{
    ClientMessage, DatagramOffer, MAX_CLIENT_FRAME, MAX_FRAME, MAX_SESSIONS, ServerMessage,
    SessionId, SessionSummary, Version, read_frame, write_message,
};
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::Duration;

/// Both directions of one session, a chunk at a time.
///
/// Not `io::copy`: a `File` source selects its `splice` fast path, and `splice`
/// from a pipe into an `AF_UNIX` stream blocks without ever transferring, which
/// silently strands every keystroke after the handshake.
///
/// `splice(2)` was tried again for the daemon-to-stdout direction, where the
/// bytes are untransformed and sshd has handed this process a pipe. It is not
/// used: it cost two of the end-to-end resilience checks and ran that suite
/// five times slower. Two syscalls per 32 KiB is not what is expensive on a
/// path whose whole traffic is one terminal's output.
fn relay(input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
    // Heap rather than stack: 32 KiB on a thread that also owns a whole relay.
    let mut buf = vec![0_u8; RELAY_CHUNK].into_boxed_slice();
    loop {
        match input.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(count) => output.write_all(&buf[..count])?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// `io::stdout()` is a `LineWriter`, so newline-free frames would be held until
/// its buffer fills and an embedded newline would flush mid-frame; both
/// directions use duplicated raw descriptors instead.
pub fn run_server() -> Result<(), ServerError> {
    let mut stdin = File::from(rustix::io::dup(io::stdin().as_fd()).map_err(io::Error::from)?);
    let mut stdout = File::from(rustix::io::dup(io::stdout().as_fd()).map_err(io::Error::from)?);
    let mut payload = read_frame(&mut stdin, MAX_CLIENT_FRAME)?;
    // Answered here rather than proxied, and spoken at the management version
    // at both ends: sshd resolved `brd --server` through PATH, so this process
    // is always the new binary and the daemon it answers for may be older.
    loop {
        let sessions = match ClientMessage::decode(&payload, Version::MANAGEMENT) {
            Ok(ClientMessage::ListSessions) => manage_daemon(None),
            Ok(ClientMessage::KillSession { session_id }) => manage_daemon(Some(session_id)),
            _ => break,
        };
        write_message(
            &mut stdout,
            &ServerMessage::SessionList { sessions }.encode(Version::MANAGEMENT)?,
        )?;
        // `brd kill` resolves an identifier and acts on it over one link, so
        // this connection stays a management connection until it hangs up.
        let Ok(next) = read_frame(&mut stdin, MAX_CLIENT_FRAME) else {
            return Ok(());
        };
        payload = next;
    }
    // A question about the daemon's sessions is not a reason to start one; a
    // search is the one message worth answering out of an empty host.
    let searching = matches!(
        ClientMessage::decode(&payload, Version::MANAGEMENT),
        Ok(ClientMessage::Search { .. })
    );
    let stream = if searching {
        let Some(stream) = connect_daemon()? else {
            let empty = ServerMessage::SearchResults {
                matches: Vec::new(),
            };
            write_message(&mut stdout, &empty.encode(Version::MANAGEMENT)?)?;
            return Ok(());
        };
        stream
    } else {
        connect_or_start_daemon()?
    };
    let mut to_daemon = stream.try_clone()?;
    let mut from_daemon = stream;
    let length = u32::try_from(payload.len())
        .map_err(|_| ServerError::Setup("handshake frame too large".into()))?;
    to_daemon.write_all(&length.to_be_bytes())?;
    to_daemon.write_all(&payload)?;
    to_daemon.flush()?;
    let response = addressed_offer(read_frame(&mut from_daemon, MAX_FRAME)?);
    let response_length = u32::try_from(response.len())
        .map_err(|_| ServerError::Setup("daemon response frame too large".into()))?;
    stdout.write_all(&response_length.to_be_bytes())?;
    stdout.write_all(&response)?;
    // `drop` cannot end the session because `from_daemon` is a duplicate of the
    // same socket, so the write half is shut down explicitly.
    thread::Builder::new()
        .name("brd-proxy-input".into())
        .spawn(move || {
            let _ = relay(&mut stdin, &mut to_daemon);
            let _ = to_daemon.shutdown(Shutdown::Write);
        })
        .map_err(|_| ServerError::Worker)?;
    relay(&mut from_daemon, &mut stdout)?;
    Ok(())
}

/// Put the address the client actually reached into the daemon's offer: the
/// daemon holds one socket and no idea which of this host's addresses a session
/// arrived on, and this process is the only part of the system sshd told.
///
/// Read at this build's newest and rewritten at the version the daemon
/// negotiated — this process is never older than the daemon it fronts — and
/// anything that is not a `Hello` is relayed byte for byte, undecoded.
fn addressed_offer(response: Vec<u8>) -> Vec<u8> {
    let Ok(ServerMessage::Hello {
        version,
        size,
        session_id,
        capability,
        offer: Some(offer),
    }) = ServerMessage::decode(&response, Version::LOCAL)
    else {
        return response;
    };
    let offer = ssh_local_address().map(|ip| DatagramOffer { ip, ..offer });
    let refilled = ServerMessage::Hello {
        version,
        size,
        session_id,
        capability,
        offer,
    }
    .encode(version);
    // `encode` produces a whole frame; this function traffics in payloads,
    // because the caller writes the length prefix itself.
    match refilled {
        Ok(frame) if frame.len() > FRAME_LENGTH_PREFIX => frame[FRAME_LENGTH_PREFIX..].to_vec(),
        _ => response,
    }
}

fn ssh_local_address() -> Option<[u8; 16]> {
    offer_address(env::var("SSH_CONNECTION").ok().as_deref())
}

/// The third field of `"<client ip> <client port> <server ip> <server port>"`,
/// taken as a value so a missing variable is a case a test can state.
fn offer_address(connection: Option<&str>) -> Option<[u8; 16]> {
    let address: IpAddr = connection?.split_whitespace().nth(2)?.parse().ok()?;
    // A zeroed address is what "the daemon does not know" already means on the
    // wire, and it is checked before the mapping that would make it non-zero.
    if address.is_unspecified() {
        return None;
    }
    Some(match address {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    })
}

pub(crate) fn daemon_socket_path() -> PathBuf {
    state_dir().join(socket_name())
}

/// Ties broken by identifier so the answer never depends on a hash map's
/// iteration order.
pub(crate) fn newest_first(a: &SessionSummary, b: &SessionSummary) -> std::cmp::Ordering {
    b.active_unix
        .cmp(&a.active_unix)
        .then_with(|| a.session_id.as_bytes().cmp(&b.session_id.as_bytes()))
}

/// One socket, because the socket name carries no protocol version: a stable
/// name plus a negotiated handshake keeps a user's shells reachable across an
/// upgrade.
fn manage_daemon(kill: Option<SessionId>) -> Vec<SessionSummary> {
    let directory = state_dir();
    // A socket in a directory someone else owns is not this user's daemon.
    if private_dir(directory).is_err() {
        return Vec::new();
    }
    let Some(mut sessions) = ask_daemon(&directory.join(socket_name()), kill) else {
        return Vec::new();
    };
    sessions.sort_by(newest_first);
    sessions.truncate(MAX_SESSIONS);
    sessions
}

/// `None` means this socket did not answer, which is not the same as a daemon
/// with no sessions.
fn ask_daemon(path: &std::path::Path, kill: Option<SessionId>) -> Option<Vec<SessionSummary>> {
    let Some(mut socket) = open_daemon_socket(path) else {
        // Nothing answered the connect, which is what makes the inode stale. A
        // socket that *did* connect is left alone whatever it does next.
        let _ = fs::remove_file(path);
        return None;
    };
    // `brd ls` waiting forever on a wedged daemon is the same failure as
    // `brd ls` not reaching it at all.
    let _ = socket.set_read_timeout(Some(MANAGE_DEADLINE));
    let sessions = exchange(&mut socket, &ClientMessage::ListSessions)?;
    let held = kill.filter(|wanted| sessions.iter().any(|summary| summary.session_id == *wanted));
    let Some(session_id) = held else {
        return Some(sessions);
    };
    exchange(&mut socket, &ClientMessage::KillSession { session_id })
}

/// Spoken at [`Version::MANAGEMENT`]: no version was negotiated on this connection.
pub(crate) fn exchange(
    socket: &mut UnixStream,
    message: &ClientMessage,
) -> Option<Vec<SessionSummary>> {
    write_message(socket, &message.encode(Version::MANAGEMENT).ok()?).ok()?;
    let payload = read_frame(socket, MAX_FRAME).ok()?;
    match ServerMessage::decode(&payload, Version::MANAGEMENT) {
        Ok(ServerMessage::SessionList { sessions }) => Some(sessions),
        _ => None,
    }
}

fn open_daemon_socket(path: &std::path::Path) -> Option<UnixStream> {
    use std::os::unix::fs::MetadataExt;
    // `symlink_metadata`, not `metadata`: a symlink planted here points at
    // something whose owner says nothing about who owns this path.
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.uid() != owner().as_raw() {
        return None;
    }
    UnixStream::connect(path).ok()
}

/// [`state_dir`] can fall back to a world-writable temp directory, and another
/// local user who binds the socket there is handed the whole session —
/// handshake, resume capability, every keystroke.
fn connect_daemon() -> Result<Option<UnixStream>, ServerError> {
    private_dir(state_dir())?;
    connect_in_private_dir()
}

/// Split from [`connect_daemon`] so a cold start proves the directory once
/// rather than paying [`private_dir`]'s two `mkdir` and two `stat` on every
/// attempt of the poll below.
fn connect_in_private_dir() -> Result<Option<UnixStream>, ServerError> {
    use std::os::unix::fs::MetadataExt;
    let path = daemon_socket_path();
    // `symlink_metadata`, not `metadata`: a symlink planted here points at
    // something whose owner says nothing about who owns this path.
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if meta.uid() != owner().as_raw() {
        return Err(ServerError::Setup(format!(
            "{} belongs to another user",
            path.display()
        )));
    }
    Ok(UnixStream::connect(&path).ok())
}

/// How a caller that has just spawned a daemon waits for it to bind. Backoff
/// rather than a flat 10 ms grid: a daemon that binds in one millisecond went
/// unnoticed for nine, on the one path a user waits through interactively. The
/// same second is still the whole budget.
const START_FIRST: Duration = Duration::from_micros(250);
const START_LONGEST: Duration = Duration::from_millis(10);
const START_BUDGET: Duration = Duration::from_secs(1);

fn connect_or_start_daemon() -> Result<UnixStream, ServerError> {
    private_dir(state_dir())?;
    if let Some(stream) = connect_in_private_dir()? {
        return Ok(stream);
    }
    let executable = env::current_exe()?;
    ProcessCommand::new(executable)
        .arg("--daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // sshd tears a connection down by signalling the whole process group,
        // so a daemon spawned inside it dies with the transport it was meant
        // to outlive.
        .process_group(0)
        .spawn()?;
    let mut nap = START_FIRST;
    let mut waited = Duration::ZERO;
    while waited < START_BUDGET {
        thread::sleep(nap);
        waited += nap;
        if let Some(stream) = connect_in_private_dir()? {
            return Ok(stream);
        }
        nap = (nap * 2).min(START_LONGEST);
    }
    Err(ServerError::Setup("session daemon did not start".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon does not know which of this host's addresses a client
    /// reached; the relay sshd started is the only part of the system told.
    #[test]
    fn the_offer_address_comes_from_the_ssh_connection() {
        assert_eq!(
            offer_address(Some("10.0.0.9 51234 192.0.2.7 22")),
            Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 7]),
            "a v4 server address travels in the mapped range"
        );
        assert_eq!(
            offer_address(Some("2001:db8::5 51234 2001:db8::1 22")),
            Some([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            offer_address(None),
            None,
            "a session with no ssh behind it offers nothing"
        );
        assert_eq!(offer_address(Some("10.0.0.9 51234")), None, "short");
        assert_eq!(
            offer_address(Some("10.0.0.9 51234 not-an-address 22")),
            None,
            "malformed"
        );
        assert_eq!(
            offer_address(Some("10.0.0.9 51234 0.0.0.0 22")),
            None,
            "a zeroed address is what absence already means on the wire"
        );
    }

    /// A stream fed from a socket the way the daemon feeds this one, with an
    /// EOF at the end of it.
    fn spoken(payload: Vec<u8>) -> UnixStream {
        let (mut feeder, source) = UnixStream::pair().expect("a socket pair");
        thread::spawn(move || {
            let _ = feeder.write_all(&payload);
            let _ = feeder.shutdown(Shutdown::Write);
        });
        source
    }

    fn counted(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i % 251).expect("under a byte"))
            .collect()
    }

    /// A pipe is what sshd hands this process and a file is what a redirect
    /// does, and the relay owes both every byte in order across more than one
    /// chunk. Pinned because this is the path a whole session's output takes:
    /// a clever copy that stopped early here would strand it with no
    /// diagnostic at all, which is what both notes on [`relay`] record.
    #[test]
    fn the_outbound_relay_delivers_to_a_pipe_and_to_a_file_alike() {
        let payload = counted(RELAY_CHUNK * 3 / 2);

        let (read_end, write_end) = rustix::pipe::pipe().expect("a pipe");
        let mut drain = File::from(read_end);
        let drained = thread::spawn(move || {
            let mut seen = Vec::new();
            drain.read_to_end(&mut seen).expect("the pipe drains");
            seen
        });
        let mut through_pipe = File::from(write_end);
        relay(&mut spoken(payload.clone()), &mut through_pipe).expect("relayed onto a pipe");
        // The reader parks on EOF, which is this descriptor going away.
        drop(through_pipe);
        assert_eq!(drained.join().expect("the drain thread"), payload);

        let path = std::env::temp_dir().join(format!("brd-relay-{}.out", std::process::id()));
        let mut redirected = File::create(&path).expect("a temporary sink");
        relay(&mut spoken(payload.clone()), &mut redirected).expect("relayed onto a file");
        let landed = fs::read(&path).expect("the sink");
        let _ = fs::remove_file(&path);
        assert_eq!(landed, payload);
    }
}
