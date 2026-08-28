#![forbid(unsafe_code)]

//! Bytes on their way into the PTY.
//!
//! `write_all` on a PTY master blocks whenever the child has stopped reading
//! its standard input, and a write on the session actor's own thread wedges
//! with no escape at all:
//!
//! ```text
//! actor blocks writing input -> actor stops draining events
//!   -> the PTY reader blocks handing it output
//!   -> the PTY output buffer fills -> the child blocks writing stdout
//!   -> the child never reads its input again
//! ```

use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

/// Bytes of unwritten input a session may hold; the daemon's memory budget is
/// computed from it. A human types at ten bytes a second, so a megabyte is a
/// paste into a program that is not reading.
pub const BACKLOG: usize = 1024 * 1024;

pub struct PtyInput {
    buffer: Arc<Mutex<Buffer>>,
    ready: Arc<Condvar>,
}

struct Buffer {
    bytes: Vec<u8>,
    /// Charged against [`BACKLOG`] beside the queue: the writer writes its
    /// batch outside the lock, so ignoring these would admit a second backlog.
    writing: usize,
    closed: bool,
    failed: bool,
}

impl PtyInput {
    pub fn new(mut writer: Box<dyn Write + Send>) -> Result<Self, crate::ServerError> {
        let buffer = Arc::new(Mutex::new(Buffer {
            bytes: Vec::new(),
            writing: 0,
            closed: false,
            failed: false,
        }));
        let ready = Arc::new(Condvar::new());
        let worker_buffer = Arc::clone(&buffer);
        let worker_ready = Arc::clone(&ready);
        thread::Builder::new()
            .stack_size(crate::IO_STACK)
            .name("brd-pty-input".into())
            .spawn(move || {
                let mut batch = Vec::new();
                loop {
                    {
                        let Ok(mut buffer) = worker_buffer.lock() else {
                            return;
                        };
                        // Before the wait, not after the write: the room the
                        // last batch held is usable the moment the PTY has
                        // taken it.
                        buffer.writing = 0;
                        batch.clear();
                        while buffer.bytes.is_empty() {
                            if buffer.closed {
                                return;
                            }
                            let Ok(next) = worker_ready.wait(buffer) else {
                                return;
                            };
                            buffer = next;
                        }
                        std::mem::swap(&mut batch, &mut buffer.bytes);
                        buffer.bytes.clear();
                        buffer.writing = batch.len();
                    }
                    if writer.write_all(&batch).is_err() || writer.flush().is_err() {
                        if let Ok(mut buffer) = worker_buffer.lock() {
                            buffer.failed = true;
                        }
                        return;
                    }
                }
            })
            .map_err(|_| crate::ServerError::Worker)?;
        Ok(Self { buffer, ready })
    }

    /// `false` means they were not queued: the descriptor is gone, or a child
    /// that is not reading has let a megabyte accumulate. The caller must not
    /// acknowledge input this refused — the client replays it on the next
    /// attachment, and the gate only reads a replay as a duplicate if the
    /// original was admitted.
    pub fn write(&self, bytes: &[u8]) -> bool {
        let Ok(mut buffer) = self.buffer.lock() else {
            return false;
        };
        if buffer.closed
            || buffer.failed
            || buffer.bytes.len() + buffer.writing + bytes.len() > BACKLOG
        {
            return false;
        }
        buffer.bytes.extend_from_slice(bytes);
        self.ready.notify_one();
        true
    }
}

impl Drop for PtyInput {
    fn drop(&mut self) {
        if let Ok(mut buffer) = self.buffer.lock() {
            buffer.closed = true;
        }
        self.ready.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::holding;
    use std::sync::mpsc;

    fn stalled() -> (PtyInput, mpsc::Receiver<usize>, mpsc::Sender<()>) {
        let (writer, took, release) = holding();
        let input = PtyInput::new(Box::new(writer)).expect("writer");
        (input, took, release)
    }

    /// Input past the backlog is refused rather than dropped, because the
    /// caller uses the refusal to withhold the acknowledgement.
    #[test]
    fn an_unread_backlog_is_refused_rather_than_absorbed() {
        let (input, _took, release) = stalled();
        let chunk = vec![b'x'; 64 * 1024];
        let mut refused = false;
        for _ in 0..64 {
            if !input.write(&chunk) {
                refused = true;
                break;
            }
        }
        assert!(refused, "the backlog must be bounded");
        let _ = release.send(());
    }

    /// Counted only in the queue, the batch the writer holds outside the lock
    /// would let a second whole backlog in beside it.
    #[test]
    fn what_the_writer_is_holding_is_charged_against_the_backlog_too() {
        let (input, took, release) = stalled();
        let chunk = vec![b'x'; 64 * 1024];
        assert!(input.write(&chunk), "an empty queue must take the first");
        let mut admitted = took.recv().expect("the writer takes the first batch");
        while input.write(&chunk) {
            admitted += chunk.len();
            assert!(
                admitted <= BACKLOG,
                "{admitted} bytes are queued or in flight against a {BACKLOG}-byte ceiling"
            );
        }
        let _ = release.send(());
    }
}
