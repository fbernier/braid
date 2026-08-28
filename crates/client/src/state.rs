#![forbid(unsafe_code)]

//! What outlives one transport: the id this process answers to, and the
//! per-destination file a resume is read back out of.

use braid_proto::{
    ByteOff, CAPABILITY_BYTES, Capability, ClientId, ClientMessage, CmdSeq, ConfirmedOutput,
    Generation, ResumeRequest, SessionId, VersionRange,
};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// What this process calls itself to the daemon, for as long as it runs.
///
/// A `Resume` carrying this is what lets the server tell a client back on a
/// new transport from a second client joining: it replaces the attachment
/// holding this id. Never stored - two `brd host` are two clients.
pub(crate) static CLIENT_ID: LazyLock<ClientId> = LazyLock::new(|| {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).expect("entropy should be available");
    ClientId::from_bytes(bytes)
});

/// Client-owned resume metadata kept independently from the transport process.
#[derive(Clone, Copy)]
pub(crate) struct ReconnectState {
    pub(crate) session_id: SessionId,
    pub(crate) capability: Capability,
    pub(crate) confirmed_output: ConfirmedOutput,
}

impl ReconnectState {
    pub(crate) fn new(session_id: SessionId, capability: Capability) -> Self {
        Self {
            session_id,
            capability,
            confirmed_output: ConfirmedOutput {
                generation: Generation::initial(),
                next_off: ByteOff::zero(),
            },
        }
    }

    /// Record the position the terminal is known to be at.
    pub(crate) fn confirm(&mut self, generation: Generation, next_off: ByteOff) {
        self.confirmed_output = ConfirmedOutput {
            generation,
            next_off,
        };
    }

    pub(crate) fn resume_message(&self, sequence: CmdSeq) -> ClientMessage {
        ClientMessage::Resume {
            versions: VersionRange::LOCAL,
            seq: sequence,
            request: ResumeRequest {
                session_id: self.session_id,
                capability: self.capability,
                confirmed_output: self.confirmed_output,
                client: *CLIENT_ID,
            },
        }
    }

    pub(crate) fn note_output(&mut self, next_off: ByteOff) {
        self.confirmed_output.next_off = next_off;
    }

    pub(crate) fn next_output_offset(&self) -> ByteOff {
        self.confirmed_output.next_off
    }
}

/// Where this user's state tree lives, or `None` when nothing names one.
///
/// Deliberately no `/tmp` fallback: that writes a live session's bearer token
/// into a directory any local user can pre-create and read.
pub(crate) fn state_root(
    xdg_state_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    xdg_state_home.or_else(|| home.map(|home| home.join(".local/state")))
}

/// The resume checkpoint for `destination`, or `None` when there is nowhere
/// private to keep one - a capability another local user can read is worse
/// than a session that cannot be reattached.
pub(crate) fn reconnect_path(destination: &str) -> Option<PathBuf> {
    let root = state_root(
        std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )?;
    let name = blake3::hash(destination.as_bytes()).to_hex();
    Some(
        root.join("brd")
            .join("reconnect")
            .join(format!("{name}.state")),
    )
}

/// Create `<root>/brd/reconnect` as directories only this user can reach.
///
/// The two components holding capabilities are created *with* their mode; a
/// `create_dir_all` then `chmod` leaves a window.
fn private_state_dir(directory: &Path) -> io::Result<()> {
    let brd = directory
        .parent()
        .ok_or_else(|| io::Error::other("state directory has no parent"))?;
    if let Some(root) = brd.parent() {
        fs::create_dir_all(root)?;
    }
    private_dir(brd)?;
    private_dir(directory)
}

/// Sessions one destination's state file remembers, newest first.
///
/// More than one, or a second `brd host` overwrites the first session's
/// capability and orphans it: still running, impossible to reattach to.
pub(crate) const REMEMBERED_SESSIONS: usize = 16;

/// Bytes one remembered session occupies: id, capability, generation, offset.
/// Fixed width, and the file is nothing but records, so a length no whole
/// number of records fills is not this format.
const STATE_RECORD: usize = 16 + CAPABILITY_BYTES + 16;

/// Remove staging files left behind by processes that are gone.
///
/// A pid that no longer exists cannot be mid-write. Only `ESRCH` counts as
/// gone: a pid this side may not signal still belongs to someone.
pub(crate) fn sweep_staging(path: &Path) {
    let (Some(parent), Some(stem)) = (path.parent(), path.file_stem()) else {
        return;
    };
    let Some(stem) = stem.to_str() else {
        return;
    };
    let prefix = format!("{stem}.tmp");
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|name| name.strip_prefix(&prefix))
            .and_then(|pid| pid.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw)
        else {
            continue;
        };
        if rustix::process::test_kill_process(pid) == Err(rustix::io::Errno::SRCH) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

pub(crate) fn save_sessions(path: &Path, sessions: &[ReconnectState]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let kept = &sessions[..sessions.len().min(REMEMBERED_SESSIONS)];
    let mut bytes = Vec::with_capacity(kept.len() * STATE_RECORD);
    for state in kept {
        bytes.extend_from_slice(&state.session_id.as_bytes());
        bytes.extend_from_slice(state.capability.as_bytes());
        bytes.extend_from_slice(&state.confirmed_output.generation.get().to_be_bytes());
        bytes.extend_from_slice(&state.confirmed_output.next_off.get().to_be_bytes());
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("state file has no directory"))?;
    private_state_dir(parent)?;
    // Staged and renamed: a truncate-then-write leaves a window where a reader
    // sees a short file, decides there is no session, and strands the shell.
    // The name carries this process's pid, which is why the unlink is safe.
    let staging = path.with_extension(format!("tmp{}", std::process::id()));
    // 0600 at creation rather than create-then-chmod: the bytes are a bearer
    // token for a live session. `create_new` refuses a symlink planted where
    // the staging file goes, including one older than the directory's mode.
    let _ = fs::remove_file(&staging);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staging)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&staging, path)
}

pub(crate) fn load_sessions(path: &Path) -> io::Result<Vec<ReconnectState>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    // Written by rename, so a partial record is a foreign or older format
    // rather than a torn write: there is no session to resume in it.
    if bytes.len() % STATE_RECORD != 0 {
        return Ok(Vec::new());
    }
    let (records, _) = bytes.as_chunks::<STATE_RECORD>();
    let mut sessions = Vec::with_capacity(records.len());
    for record in records {
        let invalid = || io::Error::other("invalid session state");
        let session_id = SessionId::from_bytes(record[..16].try_into().map_err(|_| invalid())?);
        let capability = Capability::from_bytes(
            record[16..16 + CAPABILITY_BYTES]
                .try_into()
                .map_err(|_| invalid())?,
        );
        let rest = &record[16 + CAPABILITY_BYTES..];
        let take_u64 = |offset: usize| -> u64 {
            let mut value = [0; 8];
            value.copy_from_slice(&rest[offset..offset + 8]);
            u64::from_be_bytes(value)
        };
        let Some(generation) = Generation::from_u64(take_u64(0)) else {
            return Ok(Vec::new());
        };
        let mut state = ReconnectState::new(session_id, capability);
        state.confirm(generation, ByteOff::from_u64(take_u64(8)));
        sessions.push(state);
    }
    Ok(sessions)
}

/// Create `path` as a directory only this user can reach, or refuse it: a
/// directory another user can write to is one they can pre-create, and the
/// staging file a capability goes through is a symlink they can plant.
pub(crate) fn private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    // `symlink_metadata`, not `metadata`: a symlink someone else planted here
    // points at a directory whose mode says nothing about who owns this path.
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    if meta.uid() != rustix::process::getuid().as_raw() {
        return Err(io::Error::other(format!(
            "{} belongs to another user",
            path.display()
        )));
    }
    // Not the create-then-chmod window the mode above avoids: the path exists
    // and is ours. Versions before 7 made this tree with no mode, so refusing
    // here would strand every upgrade over a directory `brd` wrote itself.
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, PermissionsExt::from_mode(0o700))?;
    }
    Ok(())
}
