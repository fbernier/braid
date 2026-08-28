#![deny(unsafe_code)]

//! Whether the peer on a socket is the user who owns the daemon: a connection
//! from another uid is refused before the handshake. It matters most on macOS,
//! where `XDG_RUNTIME_DIR` is unset and the `/tmp` fallback is always taken, so
//! the directory's mode guards nothing.

use crate::state::owner;
use std::os::unix::net::UnixStream;

#[cfg(target_os = "linux")]
pub(crate) fn is_owner(stream: &UnixStream) -> bool {
    rustix::net::sockopt::socket_peercred(stream).is_ok_and(|peer| peer.uid == owner())
}

/// `getpeereid(3)`, which is `SO_PEERCRED`'s equivalent here and which rustix
/// does not expose.
#[cfg(not(target_os = "linux"))]
#[allow(unsafe_code, reason = "getpeereid has no safe binding")]
pub(crate) fn is_owner(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `stream` owns the descriptor for the whole call, and both
    // out-parameters are live, correctly typed, and read only when the call
    // reports success.
    let queried = unsafe { libc::getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) };
    queried == 0 && uid == owner().as_raw()
}
