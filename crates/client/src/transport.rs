#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{self, IoSlice, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("cannot start ssh: {0}")]
    Spawn(#[source] io::Error),
    #[error("ssh stdio pipe unavailable")]
    MissingPipe,
}

/// A login shell started by sshd is not interactive on every distribution, so
/// `install.sh`'s `~/.local/bin` prefix is routinely absent from PATH. A
/// fallback, not a PATH prepend: nothing here outlives the connection.
const SERVER_COMMAND: &str =
    r#"command -v brd >/dev/null && exec brd --server || exec "$HOME/.local/bin/brd" --server"#;

const STDERR_TAIL: usize = 4096;

/// Whether an invocation may read the user's terminal for credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    /// A first attach or a management query, where a passphrase prompt is fine.
    Interactive,
    /// A resume: `ssh` must fail rather than prompt.
    Batch,
}

/// The pipes come out through [`Self::take_io`] while the child stays here to
/// be reaped: a dropped half-moved transport leaks an `ssh` per failed resume.
pub struct SshTransport {
    child: Child,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    stderr: Arc<Mutex<String>>,
}

impl SshTransport {
    pub fn connect(destination: &str, auth: Auth) -> Result<Self, TransportError> {
        let mut command = Command::new("ssh");
        command.arg("-T");
        for option in Self::options(auth) {
            command.arg("-o").arg(option);
        }
        // `-oProxyCommand=...` is a local command; `--` forecloses that.
        command
            .arg("--")
            .arg(destination)
            .arg(SERVER_COMMAND)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Not inherited: "Connection closed by ..." mid-screen corrupts a
            // raw-mode display nothing repaints.
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(TransportError::Spawn)?;
        let input = child.stdin.take().ok_or(TransportError::MissingPipe)?;
        let output = child.stdout.take().ok_or(TransportError::MissingPipe)?;
        let errors = child.stderr.take().ok_or(TransportError::MissingPipe)?;
        let stderr = Arc::new(Mutex::new(String::new()));
        drain_stderr(errors, Arc::clone(&stderr));
        Ok(Self {
            child,
            input: Some(input),
            output: Some(output),
            stderr,
        })
    }

    /// Options every invocation carries, and why each is not a default.
    fn options(auth: Auth) -> Vec<String> {
        let mut options = vec![
            // Otherwise a black-holed SYN blocks a resume for about two minutes
            // of TCP retries, with nothing polling the quit key.
            "ConnectTimeout=10".into(),
            // Three unanswered probes is fifteen seconds; TCP alone takes
            // minutes to notice a suspended laptop.
            "ServerAliveInterval=5".into(),
            "ServerAliveCountMax=3".into(),
            // Otherwise every reconnect pays four to six round trips of
            // handshake on a link that just proved it is bad.
            "ControlMaster=auto".into(),
            format!("ControlPath={}", control_path().display()),
            "ControlPersist=60".into(),
            // A 200x50 repaint is ~10.4 KB of redundant ASCII at up to 30 Hz;
            // not an ssh default because zlib loses on fast opaque links.
            "Compression=yes".into(),
        ];
        if auth == Auth::Batch {
            // `ssh` reads a passphrase from `/dev/tty` rather than its pipe, so
            // it would race `brd-input`, and the bytes `brd` wins are replayed
            // verbatim into the remote shell.
            options.push("BatchMode=yes".into());
        }
        options
    }

    /// Take the pipes, leaving the child to be reaped by `Drop`.
    pub fn take_io(&mut self) -> Option<(ChildStdin, ChildStdout)> {
        Some((self.input.take()?, self.output.take()?))
    }

    /// What `ssh` said, for the message a failure turns into.
    pub fn diagnostics(&self) -> String {
        self.stderr
            .lock()
            .map(|text| strip_own_prefix(text.trim()))
            .unwrap_or_default()
    }
}

impl Drop for SshTransport {
    fn drop(&mut self) {
        // `take_io` moved both pipes out at connect time, so nothing here can
        // close the stdin `ssh` would exit on; reaping is all that stops a leak.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Only the first line: a multi-line diagnostic carries its own shape.
fn strip_own_prefix(text: &str) -> String {
    let (first, rest) = text.split_once('\n').unwrap_or((text, ""));
    let first = first.strip_prefix("ssh: ").unwrap_or(first);
    if rest.is_empty() {
        first.to_owned()
    } else {
        format!("{first}\n{rest}")
    }
}

/// Retrying cannot help, so this is what stops the reconnect loop.
pub(crate) fn needs_credentials(diagnostics: &str) -> bool {
    diagnostics.contains("Permission denied")
        || diagnostics.contains("Host key verification failed")
        || diagnostics.contains("Too many authentication failures")
}

/// `sun_path` is 104 bytes on macOS, and `ssh` binds `<path>.XXXXXXXXXXXXXXXX`
/// before renaming it, so seventeen characters are spent before the path is.
const CONTROL_PATH_MAX: usize = 104 - 17 - 1;

/// Characters `%C` expands to: `ssh` substitutes a hex digest.
const CONTROL_TOKEN: usize = 40;

/// Where the multiplexing master's socket lives, or `none` when nowhere fits.
/// Not `temp_dir()`: macOS's per-user `/var/folders/…` overruns `sun_path` once
/// the digest and `ssh`'s own suffix are added, which `ssh` treats as fatal.
fn control_path() -> PathBuf {
    let root =
        std::env::var_os("XDG_RUNTIME_DIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
    let directory = root.join(format!("brd-{}", rustix::process::getuid().as_raw()));
    // A control socket anyone can pre-create is worse than no socket.
    if crate::state::private_dir(&directory).is_err() {
        return PathBuf::from("none");
    }
    let path = directory.join("ssh-%C");
    // Multiplexing is an optimisation; a session is not.
    if fits_sun_path(&path) {
        path
    } else {
        PathBuf::from("none")
    }
}

fn fits_sun_path(path: &Path) -> bool {
    let literal = path.as_os_str().len();
    literal.saturating_sub("%C".len()) + CONTROL_TOKEN <= CONTROL_PATH_MAX
}

/// The tail only, so a chatty server cannot grow this without bound.
fn drain_stderr(mut errors: ChildStderr, into: Arc<Mutex<String>>) {
    let _ = thread::Builder::new()
        .name("brd-ssh-stderr".into())
        .spawn(move || {
            let mut buf = [0_u8; 1024];
            loop {
                match errors.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        let Ok(mut text) = into.lock() else { break };
                        text.push_str(&String::from_utf8_lossy(&buf[..count]));
                        if text.len() > STDERR_TAIL {
                            let cut = text.len() - STDERR_TAIL;
                            let cut = (cut..text.len())
                                .find(|index| text.is_char_boundary(*index))
                                .unwrap_or(text.len());
                            text.drain(..cut);
                        }
                    }
                }
            }
        });
}

/// A framed writer that never blocks the thread that hands it a message.
///
/// A stalled link fills the pipe buffer and `write_all` would block holding the
/// lock every ack and repaint request also wants. Overrunning the bounded queue
/// drops no keystroke: closing the pipe forces the reconnect that replays.
pub struct Outbox {
    queue: Arc<Mutex<Queue>>,
    ready: Arc<Condvar>,
}

struct Queue {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
    closed: bool,
}
/// Necessarily larger than the client's own pending-input bound, since `drain`
/// hands over everything it has buffered in one go.
const OUTBOX_LIMIT: usize = 1024 * 1024;

/// Room past [`OUTBOX_LIMIT`] for `Close` and `Detach`: reporting a close that
/// was never transmitted leaves the remote shell running and unnamed.
const CONTROL_SLACK: usize = 64 * 1024;

impl Outbox {
    pub fn new(mut output: ChildStdin) -> Self {
        let queue = Arc::new(Mutex::new(Queue {
            frames: VecDeque::new(),
            bytes: 0,
            closed: false,
        }));
        let ready = Arc::new(Condvar::new());
        let worker_queue = Arc::clone(&queue);
        let worker_ready = Arc::clone(&ready);
        let _ = thread::Builder::new()
            .name("brd-outbox".into())
            .spawn(move || {
                // A fresh vector per burst allocates on the keystroke path.
                let mut batch: Vec<Vec<u8>> = Vec::new();
                loop {
                    {
                        let Ok(mut queue) = worker_queue.lock() else {
                            return;
                        };
                        loop {
                            if !queue.frames.is_empty() {
                                batch.extend(queue.frames.drain(..));
                                // In flight does not count against the limit.
                                queue.bytes = 0;
                                break;
                            }
                            if queue.closed {
                                return;
                            }
                            let Ok(next) = worker_ready.wait(queue) else {
                                return;
                            };
                            queue = next;
                        }
                    }
                    if write_batch(&mut output, &batch).is_err() {
                        return;
                    }
                    batch.clear();
                }
            });
        Self { queue, ready }
    }

    /// Queue one encoded frame. `false` means the link is not draining.
    pub fn send(&self, frame: Vec<u8>) -> bool {
        self.push(frame, OUTBOX_LIMIT)
    }

    /// Queue a message the session cannot end without, from reserved room.
    pub fn send_reserved(&self, frame: Vec<u8>) -> bool {
        self.push(frame, OUTBOX_LIMIT + CONTROL_SLACK)
    }

    fn push(&self, frame: Vec<u8>, limit: usize) -> bool {
        let Ok(mut queue) = self.queue.lock() else {
            return false;
        };
        if queue.closed || queue.bytes.saturating_add(frame.len()) > limit {
            return false;
        }
        queue.bytes += frame.len();
        queue.frames.push_back(frame);
        self.ready.notify_one();
        true
    }
}

/// One `write(2)` where it takes one: `ChildStdin` is unbuffered, so a frame at
/// a time is a syscall apiece. Vectored rather than gathered because copying a
/// paste is the larger half of the work.
fn write_batch<W: Write>(output: &mut W, batch: &[Vec<u8>]) -> io::Result<()> {
    let mut buffers: Vec<IoSlice<'_>> = batch.iter().map(|frame| IoSlice::new(frame)).collect();
    let mut rest = &mut buffers[..];
    while !rest.is_empty() {
        match output.write_vectored(rest) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => IoSlice::advance_slices(&mut rest, count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    output.flush()
}

impl Drop for Outbox {
    fn drop(&mut self) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.closed = true;
        }
        self.ready.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A pipe that never takes more than `at_most` bytes at a time.
    struct Grudging {
        taken: Vec<u8>,
        at_most: usize,
    }

    impl Write for Grudging {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let count = buf.len().min(self.at_most);
            self.taken.extend_from_slice(&buf[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The whole outbox goes out in one vectored write, so a short one lands
    /// mid-frame routinely and a mismeasured cursor repeats or drops a frame.
    #[test]
    fn a_short_write_neither_repeats_nor_drops_a_frame() {
        let batch: Vec<Vec<u8>> = (0..6_u8)
            .map(|frame| vec![b'a' + frame; usize::from(frame) + 1])
            .collect();
        let whole: Vec<u8> = batch.concat();
        for at_most in 1..=whole.len() {
            let mut pipe = Grudging {
                taken: Vec::new(),
                at_most,
            };
            write_batch(&mut pipe, &batch).expect("a grudging pipe still takes it all");
            assert_eq!(
                pipe.taken, whole,
                "taking {at_most} bytes at a time changed the byte stream"
            );
        }
    }

    /// `ssh` prefixes some diagnostics with its own name and some — macOS's
    /// `unix_listener: path too long` — with nothing.
    #[test]
    fn ssh_own_prefix_is_not_repeated() {
        assert_eq!(
            strip_own_prefix("ssh: Could not resolve hostname host.invalid"),
            "Could not resolve hostname host.invalid"
        );
        assert_eq!(
            strip_own_prefix("unix_listener: path too long for Unix domain socket"),
            "unix_listener: path too long for Unix domain socket"
        );
        assert_eq!(
            strip_own_prefix("ssh: first\nsecond\nthird"),
            "first\nsecond\nthird"
        );
        assert_eq!(strip_own_prefix(""), "");
    }

    /// What batch mode refuses to ask for, no later attempt can supply.
    #[test]
    fn a_refusal_for_want_of_credentials_is_not_worth_retrying() {
        assert!(needs_credentials(
            "user@host: Permission denied (publickey,password)."
        ));
        assert!(needs_credentials("Host key verification failed."));
        assert!(needs_credentials(
            "Received disconnect from 10.0.0.1 port 22:2: Too many authentication failures"
        ));
        assert!(!needs_credentials("Connection closed by 10.0.0.1 port 22"));
        assert!(!needs_credentials(""));
    }

    /// The first attach is at the user's own shell prompt.
    #[test]
    fn only_a_resume_refuses_to_prompt() {
        assert!(
            SshTransport::options(Auth::Batch).contains(&"BatchMode=yes".to_owned()),
            "a resume must never race the terminal for a password"
        );
        assert!(!SshTransport::options(Auth::Interactive).contains(&"BatchMode=yes".to_owned()));
    }

    /// The budget is the expanded digest: a check against the literal two
    /// characters of `%C` passes everything and proves nothing.
    #[test]
    fn a_control_path_is_measured_by_the_digest_ssh_expands_it_to() {
        let room = CONTROL_PATH_MAX - CONTROL_TOKEN;
        let exact = format!("{}/ssh-%C", "x".repeat(room - "/ssh-".len()));
        for (path, fits) in [
            (
                "/var/folders/l7/yq_xpv_s4ld75dyxp6w_yszw0000gp/T/brd-502/ssh-%C".to_owned(),
                false,
            ),
            ("/tmp/brd-502/ssh-%C".to_owned(), true),
            ("/run/user/1000/brd-1000/ssh-%C".to_owned(), true),
            (exact.clone(), true),
            (format!("x{exact}"), false),
        ] {
            assert_eq!(fits_sun_path(Path::new(&path)), fits, "{path}");
        }
    }

    /// The login shell sshd starts decides what resolves, so this runs `/bin/sh`.
    /// A `brd` on PATH must win, and a host with none must reach the prefix.
    #[test]
    fn the_server_command_prefers_path_and_falls_back_to_the_install_prefix() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        /// Enough to outlast a `fork` waiting to be scheduled onto its
        /// `execve` on a loaded two-core runner.
        const ETXTBSY_ATTEMPTS: u32 = 200;

        let root = std::env::temp_dir().join(format!("brd-command-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let on_path = root.join("bin");
        let home = root.join("home");
        for (directory, which) in [(&on_path, "PATH"), (&home.join(".local/bin"), "FALLBACK")] {
            fs::create_dir_all(directory).expect("test directory");
            let brd = directory.join("brd");
            fs::write(&brd, format!("#!/bin/sh\nprintf '{which} %s' \"$*\"\n")).expect("fake brd");
            fs::set_permissions(&brd, fs::Permissions::from_mode(0o755)).expect("executable");
        }

        // A sibling's fork between `fs::write` and `exec` holds a writable
        // descriptor on the script, and the kernel will not run a file anyone
        // can still write. 126 is "found but could not be executed".
        let resolves_to = |path: String| {
            for _ in 0..ETXTBSY_ATTEMPTS {
                let run = Command::new("/bin/sh")
                    .arg("-c")
                    .arg(SERVER_COMMAND)
                    .env("HOME", &home)
                    .env("PATH", &path)
                    .output()
                    .expect("sh");
                if run.status.code() != Some(126) {
                    return String::from_utf8_lossy(&run.stdout).into_owned();
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("the fake brd stayed unexecutable across every attempt");
        };

        assert_eq!(
            resolves_to(format!("{}:/usr/bin:/bin", on_path.display())),
            "PATH --server"
        );
        assert_eq!(
            resolves_to(root.join("nowhere").display().to_string()),
            "FALLBACK --server"
        );

        let _ = fs::remove_dir_all(&root);
    }
}
