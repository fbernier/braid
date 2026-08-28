#![forbid(unsafe_code)]

//! The daemon's only voice: its standard streams are `/dev/null` by
//! construction, so without this a failed spawn or an `EMFILE` from `accept`
//! happens silently. Not a logging framework, and it must not become one.

use crate::state::session_name;
use braid_proto::SessionId;
use std::cell::Cell;
use std::fmt::{Arguments, Write as _};
use std::fs::File;
use std::io::Write;
use std::panic::PanicHookInfo;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Bytes one file may reach before it is rotated, so at most two on disk.
const LIMIT: u64 = 1024 * 1024;

/// Counted here rather than read back: a daemon never exits, so a bound checked
/// in [`open`] alone bounds what the *previous* daemon left.
struct Log {
    file: File,
    written: u64,
    /// So the history can be moved aside rather than dropped.
    path: PathBuf,
}

static LOG: OnceLock<Mutex<Log>> = OnceLock::new();

impl Log {
    fn record(&mut self, line: &str) {
        let cost = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if self.written.saturating_add(cost) > LIMIT {
            self.rotate();
        }
        if self.file.write_all(line.as_bytes()).is_ok() {
            self.written = self.written.saturating_add(cost);
        }
    }

    /// A `set_len(0)` would drop the whole history, so the megabyte of chatter
    /// it takes to reproduce a bug would delete the preamble explaining it.
    /// Truncation is still what happens when nothing can be moved aside: the
    /// bound is a promise about the user's disk.
    fn rotate(&mut self) {
        let previous = self.path.with_extension("log.1");
        match std::fs::rename(&self.path, &previous).and_then(|()| append_to(&self.path)) {
            Ok(file) => {
                self.file = file;
                self.written = 0;
            }
            Err(_) => {
                if self.file.set_len(0).is_ok() {
                    self.written = 0;
                }
            }
        }
    }
}

/// Private from the instant the file exists.
fn append_to(path: &Path) -> std::io::Result<File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    Ok(file)
}

/// Called once, after the directory has been proved private: the log is exactly
/// as sensitive as the session it records.
pub fn open(path: &Path) {
    let Ok(file) = append_to(path) else {
        return;
    };
    let written = file.metadata().map_or(0, |meta| meta.len());
    let _ = LOG.set(Mutex::new(Log {
        file,
        written,
        path: path.to_path_buf(),
    }));
}

thread_local! {
    /// A thread-local rather than an argument because the reporting sites are
    /// spread across the actor, the sink, the PTY and the forwards, and one
    /// session owns its threads for their whole lives.
    static SESSION: Cell<Option<SessionId>> = const { Cell::new(None) };
}

pub(crate) fn attribute(id: SessionId) {
    SESSION.with(|session| session.set(Some(id)));
}

/// A daemon with no log file says nothing, which is never a reason to fail.
pub fn write(args: Arguments<'_>) {
    let Some(log) = LOG.get() else {
        return;
    };
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    // Formatted before the lock and written as one buffer: `writeln!` on a
    // `File` is a syscall per fragment, and a line assembled inside the
    // critical section holds every other thread's diagnostic behind it.
    let mut line = String::new();
    let written = match SESSION.with(Cell::get) {
        Some(id) => writeln!(line, "{stamp} {} {args}", session_name(id)),
        None => writeln!(line, "{stamp} {args}"),
    };
    if written.is_err() {
        return;
    }
    // A `File` has no invariant a panic can break, and staying quiet on the
    // poison would disable the daemon's only diagnostic channel for the rest of
    // its life — starting with the panic that set it.
    let mut log = log.lock().unwrap_or_else(PoisonError::into_inner);
    log.record(&line);
}

/// `set_hook` replaces whatever is there, so installing twice would chain this
/// daemon's hook onto its own copy and record every panic twice.
static HOOKED: AtomicBool = AtomicBool::new(false);

/// The daemon keeps `panic = unwind` so one session's panic cannot take the
/// others down, but its standard streams go nowhere.
pub fn install_panic_hook() {
    if HOOKED.swap(true, Ordering::Relaxed) {
        return;
    }
    let inherited = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        write(format_args!("{}", panicked(info)));
        inherited(info);
    }));
}

fn panicked(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("a payload of no type this daemon knows");
    let thread = std::thread::current();
    let name = thread.name().unwrap_or("unnamed").to_owned();
    match info.location() {
        Some(at) => format!(
            "panic on {name} at {}:{}:{}: {message}",
            at.file(),
            at.line(),
            at.column()
        ),
        None => format!("panic on {name}: {message}"),
    }
}

macro_rules! log {
    ($($arg:tt)*) => { $crate::log::write(format_args!($($arg)*)) };
}

pub(crate) use log;

/// Milliseconds since the first thing that asked, which is monotonic: a wall
/// clock stepping backwards would gag a [`Throttle`] for the length of the
/// step, and the sites that need one are the ones a stranger drives.
fn elapsed_ms() -> u64 {
    static ORIGIN: LazyLock<Instant> = LazyLock::new(Instant::now);
    u64::try_from(ORIGIN.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// One line per window for a site an unauthenticated stranger can reach: at
/// [`LIMIT`] with a single generation kept, a connect loop costs the operator
/// their whole history in well under a minute.
///
/// Suppression is two relaxed atomics and a clock read — no allocation, and
/// nothing formatted — so the cost of being shouted at stays flat.
pub(crate) struct Throttle {
    /// [`elapsed_ms`] of the last line, biased by one so a zero means no line
    /// has been emitted yet and the very first call is never swallowed.
    last: AtomicU64,
    suppressed: AtomicU64,
    /// Milliseconds, not a `Duration`: the comparison is on the suppression
    /// path, and a `Duration` would only be converted back.
    window: u64,
}

impl Throttle {
    pub(crate) const fn new(window_ms: u64) -> Self {
        Self {
            last: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
            window: window_ms,
        }
    }

    /// `None` while the window holds; `Some(n)` for the caller that should
    /// speak, carrying how many events it speaks for.
    pub(crate) fn admit(&self) -> Option<u64> {
        let now = elapsed_ms().saturating_add(1);
        let last = self.last.load(Ordering::Relaxed);
        if last != 0 && now - last < self.window {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // Exactly one winner per window: a loser counts itself suppressed
        // rather than emitting the line the window exists to collapse.
        if self
            .last
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(self.suppressed.swap(0, Ordering::Relaxed))
    }
}

/// [`log!`] for a site a stranger can drive: at most one line per window, and
/// what the window swallowed is reported by the line that ends it rather than
/// lost.
macro_rules! log_throttled {
    ($throttle:expr, $($arg:tt)*) => {
        if let Some(suppressed) = $throttle.admit() {
            if suppressed == 0 {
                $crate::log::write(format_args!($($arg)*));
            } else {
                $crate::log::write(format_args!(
                    "{} ({suppressed} more since)",
                    format_args!($($arg)*)
                ));
            }
        }
    };
}

pub(crate) use log_throttled;

#[cfg(test)]
mod tests {
    use super::{LIMIT, Log, Throttle, append_to};
    use std::path::PathBuf;

    /// Long enough that the burst below cannot outrun it on a loaded host, and
    /// short enough that crossing it is not a test anyone waits for.
    const WINDOW: u64 = 500;

    /// A log file no other test shares.
    fn temporary(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "brd-log-{name}-{}-{:?}.log",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    fn log_at(path: &std::path::Path) -> Log {
        Log {
            file: append_to(path).expect("a temporary log"),
            written: 0,
            path: path.to_path_buf(),
        }
    }

    /// A bound read once, in `open`, bounds only what the previous daemon left,
    /// and then lets this one write onto the user's real disk forever.
    #[test]
    fn a_daemon_that_never_exits_still_bounds_what_it_writes() {
        let path = temporary("bound");
        let mut log = log_at(&path);
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
        let _ = std::fs::remove_file(path.with_extension("log.1"));
        assert!(
            peak <= LIMIT,
            "three megabytes of lines left a {peak}-byte log against a {LIMIT}-byte bound"
        );
    }

    /// Truncating to zero would destroy the preamble of whatever a bug takes a
    /// megabyte of chatter to reach, at the moment it finally reproduces.
    #[test]
    fn an_overflow_keeps_the_history_it_moves_aside() {
        let path = temporary("rotate");
        let rotated = path.with_extension("log.1");
        let mut log = log_at(&path);
        log.record("the first thing that happened\n");
        let line = format!("{}\n", "x".repeat(255));
        for _ in 0..=(LIMIT / 256) {
            log.record(&line);
        }
        let kept = std::fs::read_to_string(&rotated).expect("the overflow was moved aside");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&rotated);
        assert!(
            kept.starts_with("the first thing that happened"),
            "the line that explains the overflow went with it"
        );
    }

    /// A local non-owner can drive a refusal site as fast as it can `connect`,
    /// and a line each costs the operator every diagnostic the log held. What
    /// the window swallowed still has to reach the line that ends it, or the
    /// bound would hide the attack it exists to survive.
    #[test]
    fn a_throttled_site_speaks_once_a_window_and_says_what_it_stood_for() {
        // The shape every refusal site uses: a `static` window beside the
        // format string, quiet when this daemon has no log file at all.
        static SITE: Throttle = Throttle::new(WINDOW);

        let throttle = Throttle::new(WINDOW);
        assert_eq!(
            throttle.admit(),
            Some(0),
            "the first event is never swallowed"
        );
        for _ in 0..999 {
            assert_eq!(throttle.admit(), None, "inside the window, nothing is said");
        }
        std::thread::sleep(std::time::Duration::from_millis(WINDOW + 50));
        assert_eq!(
            throttle.admit(),
            Some(999),
            "the line that ends the window reports the burst it stood for"
        );
        assert_eq!(
            throttle.admit(),
            None,
            "and the count it reported is not reported again"
        );
        log_throttled!(SITE, "refused a connection from another user");
        log_throttled!(SITE, "refused a connection from another user");
    }
}
