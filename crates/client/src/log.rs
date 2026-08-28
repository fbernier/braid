#![forbid(unsafe_code)]

//! An append-only diagnostic file, off unless `BRD_LOG` names a path. Never the
//! terminal: the terminal belongs to the session, and a line on it corrupts it.

use std::ffi::OsString;
use std::fmt::{Arguments, Write as _};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt as _;
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

const VARIABLE: &str = "BRD_LOG";

/// Bytes the log may reach before it starts again.
const LIMIT: u64 = 1024 * 1024;

struct Log {
    file: File,
    /// Carried rather than `stat`ed per line; the writer already holds the lock.
    written: u64,
}

static LOG: LazyLock<Option<Mutex<Log>>> = LazyLock::new(|| open(std::env::var_os(VARIABLE)));

impl Log {
    fn record(&mut self, line: &str) {
        let cost = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if self.written.saturating_add(cost) > LIMIT {
            // Opened `O_APPEND`, so the next write lands at zero without a seek.
            if self.file.set_len(0).is_ok() {
                self.written = 0;
            }
        }
        if self.file.write_all(line.as_bytes()).is_ok() {
            self.written = self.written.saturating_add(cost);
        }
    }
}

/// A log is exactly as sensitive as the session it records, so it is private.
fn open(path: Option<OsString>) -> Option<Mutex<Log>> {
    let path = path.filter(|path| !path.is_empty())?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .ok()?;
    let written = file.metadata().map_or(0, |meta| meta.len());
    Some(Mutex::new(Log { file, written }))
}

pub(crate) fn write(args: Arguments<'_>) {
    let Some(log) = LOG.as_ref() else {
        return;
    };
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    // Formatted before the lock: `writeln!` on a `File` is a syscall per
    // fragment, and assembling inside it holds every other thread behind.
    let mut line = String::new();
    if writeln!(line, "{stamp} {args}").is_err() {
        return;
    }
    // A `File` has no invariant a panic can break, and honouring the poison
    // would disable the client's only diagnostic channel from that panic on.
    let mut log = log.lock().unwrap_or_else(PoisonError::into_inner);
    log.record(&line);
}

macro_rules! log {
    ($($arg:tt)*) => { $crate::log::write(format_args!($($arg)*)) };
}

pub(crate) use log;

#[cfg(test)]
mod tests {
    use super::{LIMIT, Log, open};

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "brd-client-log-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    /// A log this client creates holds what the session held.
    #[test]
    fn only_a_named_path_opens_a_log_and_it_is_private_to_its_user() {
        use std::os::unix::fs::PermissionsExt as _;

        assert!(open(None).is_none());
        assert!(
            open(Some(String::new().into())).is_none(),
            "an empty variable names no path"
        );

        let path = scratch("mode");
        let _ = std::fs::remove_file(&path);
        let sink = open(Some(path.clone().into())).expect("a path names a log");
        sink.lock().expect("a fresh log").record("attached\n");
        let mode = std::fs::metadata(&path)
            .expect("the log is there")
            .permissions()
            .mode();
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode & 0o777, 0o600, "a session's log was left readable");
    }

    /// In a child process: the sink is resolved once per process, so resolving
    /// it here would decide the answer for every other test in this binary.
    #[test]
    fn brd_log_names_where_the_client_writes() {
        const CHILD: &str = "BRD_TEST_LOG_CHILD";
        const NAME: &str = "log::tests::brd_log_names_where_the_client_writes";
        if std::env::var_os(CHILD).is_some() {
            super::write(format_args!("attached to example.invalid"));
            return;
        }
        let path = scratch("variable");
        let _ = std::fs::remove_file(&path);
        let child = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(["--exact", NAME])
            .env(CHILD, "1")
            .env(super::VARIABLE, &path)
            .output()
            .expect("re-execute this test binary");
        assert!(child.status.success(), "the child half failed");
        let written = std::fs::read_to_string(&path).expect("the file the client was told to open");
        let _ = std::fs::remove_file(&path);
        assert!(
            written.contains("attached to example.invalid"),
            "the client wrote nothing the variable asked for: {written:?}"
        );
        assert!(
            written
                .split_whitespace()
                .next()
                .and_then(|stamp| stamp.parse::<u64>().ok())
                .is_some_and(|stamp| stamp > 0),
            "a line nothing dates is a line no report can be ordered by: {written:?}"
        );
    }

    /// The bound cannot be a check made once on the way in.
    #[test]
    fn a_client_that_runs_all_day_still_bounds_what_it_writes() {
        let path = scratch("bound");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .truncate(false)
            .open(&path)
            .expect("a temporary log");
        let mut log = Log { file, written: 0 };
        let line = format!("{}\n", "x".repeat(255));
        let mut peak = 0;
        for _ in 0..(3 * LIMIT / 256) {
            log.record(&line);
            peak = peak.max(
                std::fs::metadata(&path)
                    .expect("the log is still there")
                    .len(),
            );
        }
        let _ = std::fs::remove_file(&path);
        assert!(
            peak <= LIMIT,
            "three megabytes of lines left a {peak}-byte log against a {LIMIT}-byte bound"
        );
    }
}
