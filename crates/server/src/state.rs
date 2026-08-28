#![forbid(unsafe_code)]

//! Where one daemon's socket, lock, log and capability files live: durable
//! rather than runtime, private at creation rather than a chmod later, and
//! short enough that `sockaddr_un` can name it.

use crate::{SUN_PATH_MAX, ServerError, sessions};
use braid_proto::{Capability, SessionId};
use rustix::process::Uid;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Stable across upgrades: naming this after the protocol version leaves an
/// upgraded binary unable to see the daemon holding the user's shells.
pub(crate) const fn socket_name() -> &'static str {
    "brd.sock"
}

/// The uid this daemon answers for. Cached because it cannot change: altering
/// it takes `setuid`, which nothing here calls, and rustix's `linux_raw`
/// backend issues a real `getuid` every time rather than serving the cached
/// copy glibc used to keep.
pub(crate) fn owner() -> Uid {
    static OWNER: LazyLock<Uid> = LazyLock::new(rustix::process::getuid);
    *OWNER
}

/// Durable, not runtime: logind deletes `XDG_RUNTIME_DIR` at last logout, and
/// while the daemon survives that, its socket, lock and hashed capabilities do
/// not. When the socket would not fit [`SUN_PATH_MAX`] the fallback is a
/// per-uid temp directory; see [`private_dir`].
///
/// Resolved once: session teardown and every daemon connect ask for this, and
/// the answer costs six `env::var_os` — each taking std's environment lock —
/// for inputs a running process cannot see change.
pub(crate) fn state_dir() -> &'static Path {
    static STATE_DIR: LazyLock<PathBuf> =
        LazyLock::new(|| chosen_state_dir(durable_state_dir(), temp_state_dir()));
    &STATE_DIR
}

/// Takes both rather than reading the environment, so a `$HOME` too deep for
/// `sun_path` is a case a test can state.
fn chosen_state_dir(durable: Option<PathBuf>, temp: PathBuf) -> PathBuf {
    match durable {
        Some(durable) if fits_sun_path(&durable.join(socket_name())) => durable,
        _ => temp,
    }
}

/// Relative paths are refused rather than resolved: the daemon chdirs to `/`,
/// and the XDG specification says to ignore one anyway.
fn durable_state_dir() -> Option<PathBuf> {
    named_state_dir(|key| env::var_os(key))
}

fn named_state_dir(named: impl Fn(&str) -> Option<std::ffi::OsString>) -> Option<PathBuf> {
    let absolute = |key: &str| {
        named(key)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    absolute("BRD_STATE_DIR")
        .or_else(|| absolute("XDG_STATE_HOME").map(|state| state.join("brd")))
        .or_else(|| absolute("HOME").map(|home| home.join(".local/state/brd")))
}

/// A per-uid directory under the system temp area, for when the durable one
/// cannot hold a bindable socket.
///
/// `/tmp` alone is a persistent denial of service: it is world-writable, so any
/// local user can pre-create `/tmp/brd-<uid>` and [`private_dir`]'s owner check
/// then refuses to start a daemon for that uid forever.
pub(crate) fn temp_state_dir() -> PathBuf {
    named_temp_dir(|key| env::var_os(key))
}

/// Takes the environment rather than reading it, so a host with no per-uid temp
/// area at all is a case a test can state.
fn named_temp_dir(named: impl Fn(&str) -> Option<std::ffi::OsString>) -> PathBuf {
    let absolute = |key: &str| {
        named(key)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let root = absolute("TMPDIR")
        .or_else(|| absolute("XDG_RUNTIME_DIR"))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    root.join(format!("brd-{}", owner().as_raw()))
}

fn fits_sun_path(path: &std::path::Path) -> bool {
    path.as_os_str().len() < SUN_PATH_MAX
}

/// A directory another local user can write to is a socket they can pre-create,
/// and then every keystroke of the session is theirs. The mode goes on at
/// creation: a `create_dir_all` then `chmod` leaves a world-writable window.
pub(crate) fn private_dir(path: &std::path::Path) -> Result<(), ServerError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    // Only the leaf holds this daemon's secrets, and only the leaf is proved: a
    // recursive create answers `Ok` for a directory that already exists.
    if let Some(parent) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    // `symlink_metadata`, not `metadata`: a symlink someone else planted here
    // points at a directory whose mode says nothing about who owns this path.
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return Err(ServerError::Setup(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    if meta.uid() != owner().as_raw() {
        return Err(ServerError::Setup(format!(
            "{} belongs to another user",
            path.display()
        )));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(ServerError::Setup(format!(
            "{} is readable or writable by other users",
            path.display()
        )));
    }
    Ok(())
}

/// Stable like the socket: a version in the name would hide the running
/// daemon's files from the binary that replaces it.
pub(crate) fn session_name(id: SessionId) -> String {
    let mut name = String::from("brd-");
    name.reserve(2 * id.as_bytes().len());
    for byte in id.as_bytes() {
        let _ = write!(name, "{byte:02x}");
    }
    name
}

pub(crate) fn ticket_path(id: SessionId) -> PathBuf {
    state_dir().join(session_name(id) + ".cap")
}

pub(crate) fn persist_ticket(ticket: &sessions::SessionTicket) -> Result<(), ServerError> {
    private_dir(state_dir())?;
    let path = ticket_path(ticket.session_id);
    fs::write(&path, blake3::hash(&ticket.capability).as_bytes())?;
    fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(())
}

pub(crate) fn load_ticket(
    id: SessionId,
    capability: Capability,
) -> Result<sessions::SessionTicket, ServerError> {
    let expected = fs::read(ticket_path(id))?;
    // Both operands are BLAKE3 digests of input the caller already holds, so
    // there is no secret here whose comparison timing could leak one.
    if expected != blake3::hash(capability.as_bytes()).as_bytes() {
        return Err(ServerError::Setup("invalid resume capability".into()));
    }
    Ok(sessions::SessionTicket {
        session_id: id,
        capability: *capability.as_bytes(),
    })
}

/// Environment variables a client may set on the shell this daemon starts,
/// applied again on the side an attacker cannot replace. Everything here
/// describes the SSH connection; nothing changes how a program is found.
pub(crate) const FORWARDED_ENV: [&str; 8] = [
    "SSH_AUTH_SOCK",
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "SSH_TTY",
    "DISPLAY",
    // Names a cookie file rather than anything executable, and a `DISPLAY`
    // without it is a display every X client is refused by.
    "XAUTHORITY",
    "XDG_SESSION_ID",
    "XDG_SESSION_TYPE",
];

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Control bytes become spaces: dropping them would let a hostile string close
/// up into another one.
pub(crate) fn printable(text: &str, limit: usize) -> String {
    let mut out = String::with_capacity(text.len().min(limit));
    for ch in text.chars() {
        let ch = if ch.is_control() { ' ' } else { ch };
        if out.len() + ch.len_utf8() > limit {
            break;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The environment a case runs under.
    type Env<'a> = &'a [(&'a str, &'a str)];

    fn named(values: &[(&str, &str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        let owned: Vec<(String, String)> = values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        move |key: &str| {
            owned
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| std::ffi::OsString::from(value))
        }
    }

    /// `XDG_RUNTIME_DIR` is what logind deletes at last logout, and the daemon
    /// chdirs to `/`, so a relative path would put every session's capability
    /// in the root directory rather than where the user asked.
    #[test]
    fn the_durable_state_directory_is_absolute_and_named_by_the_environment() {
        let cases: &[(&str, Env<'_>, Option<&str>)] = &[
            (
                "the specification's own default",
                &[("HOME", "/home/u")],
                Some("/home/u/.local/state/brd"),
            ),
            (
                "an explicit XDG_STATE_HOME",
                &[
                    ("XDG_STATE_HOME", "/home/u/.local/state"),
                    ("HOME", "/home/u"),
                ],
                Some("/home/u/.local/state/brd"),
            ),
            (
                "an override outranks both",
                &[("BRD_STATE_DIR", "/srv/brd"), ("HOME", "/home/u")],
                Some("/srv/brd"),
            ),
            (
                "a relative path is ignored rather than resolved",
                &[("XDG_STATE_HOME", "relative/state")],
                None,
            ),
        ];
        for (case, environment, expected) in cases {
            assert_eq!(
                named_state_dir(named(environment)),
                expected.map(PathBuf::from),
                "{case}"
            );
        }
    }

    /// `bind` answers `ENAMETOOLONG` rather than truncating: the daemon would
    /// be unreachable with no other symptom.
    #[test]
    fn a_state_directory_too_deep_for_a_socket_falls_back_to_the_temp_one() {
        let temp = PathBuf::from("/tmp/brd-1000");
        let shallow = PathBuf::from("/home/u/.local/state/brd");
        assert_eq!(
            chosen_state_dir(Some(shallow.clone()), temp.clone()),
            shallow
        );

        let deep = PathBuf::from(format!(
            "/home/{}/.local/state/brd",
            "u".repeat(SUN_PATH_MAX)
        ));
        assert_eq!(chosen_state_dir(Some(deep), temp.clone()), temp);
        // A user with no `$HOME` at all still gets a daemon.
        assert_eq!(chosen_state_dir(None, temp.clone()), temp);
        assert!(fits_sun_path(&temp.join(socket_name())));
    }

    /// The parents may not exist yet; only the leaf holds the daemon's secrets,
    /// and only the leaf is proved.
    #[test]
    fn a_state_directory_is_created_private_under_parents_that_did_not_exist() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_state_dir().join(format!("brd-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let leaf = root.join("a/b/brd");
        private_dir(&leaf).expect("a fresh state directory");
        let mode = fs::symlink_metadata(&leaf)
            .expect("the leaf exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "created private, not chmodded private");
        // Idempotent, and the second call is the one that runs the checks.
        private_dir(&leaf).expect("an existing private directory is accepted");
        fs::set_permissions(&leaf, PermissionsExt::from_mode(0o755)).expect("widen");
        assert!(
            private_dir(&leaf).is_err(),
            "a directory others can read is refused"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A squatter pre-creating `/tmp/brd-<uid>` makes `private_dir` refuse to
    /// start a daemon for that uid forever, so `/tmp` is the last resort.
    #[test]
    fn the_temp_fallback_prefers_a_directory_no_other_user_can_pre_create() {
        let uid = owner().as_raw();
        let cases: &[(&str, Env<'_>, String)] = &[
            (
                "logind's per-uid runtime directory",
                &[("XDG_RUNTIME_DIR", "/run/user/1000")],
                format!("/run/user/1000/brd-{uid}"),
            ),
            (
                "Darwin's per-uid TMPDIR outranks it",
                &[
                    ("TMPDIR", "/var/folders/xx/T"),
                    ("XDG_RUNTIME_DIR", "/run/user/1000"),
                ],
                format!("/var/folders/xx/T/brd-{uid}"),
            ),
            (
                "nothing per-uid at all: the squattable path, and only then",
                &[],
                format!("/tmp/brd-{uid}"),
            ),
        ];
        for (case, environment, expected) in cases {
            assert_eq!(
                named_temp_dir(named(environment)),
                PathBuf::from(expected),
                "{case}"
            );
        }
    }
}
