#![forbid(unsafe_code)]

//! `brd ls`, `brd kill` and `brd grep`.
//!
//! Every message here is spoken at [`Version::MANAGEMENT`]: none runs on a
//! connection that handshook, and the daemon a user most needs to enumerate is
//! the one their upgraded binary has not agreed a version with.

use crate::ClientError;
use crate::inbound::{Deadline, DeadlineReader, RESUME_TIMEOUT};
use crate::transport::{Auth, SshTransport};
use braid_proto::{
    ClientMessage, DecodeError, MAX_FRAME, MAX_MATCHES, SearchMatch, ServerMessage, SessionId,
    SessionSummary, Version, read_frame, write_message,
};
use std::fmt::Write as _;
use std::process::{ChildStdin, ChildStdout};
use std::time::{SystemTime, UNIX_EPOCH};
use unicode_width::UnicodeWidthStr;

/// Hex characters `brd ls` prints and `brd kill` matches on: long enough that
/// two live sessions collide about once in 65536.
const SHORT_ID: usize = 8;

/// One `ssh` invocation carrying management frames both ways: `brd --server`
/// relays until either side hangs up, so `kill` is two round trips on one.
struct Management {
    transport: SshTransport,
    input: ChildStdin,
    output: DeadlineReader<ChildStdout>,
}

impl Management {
    fn open(destination: &str) -> Result<Self, ClientError> {
        let mut transport = SshTransport::connect(destination, Auth::Interactive)?;
        let (input, output) = transport
            .take_io()
            .ok_or(ClientError::Transport(crate::TransportError::MissingPipe))?;
        Ok(Self {
            transport,
            input,
            // The same budget a resume gets; a `brd ls` that hangs has no quit
            // key at all.
            output: DeadlineReader::new(output, Deadline::new(RESUME_TIMEOUT))?,
        })
    }

    fn ask(&mut self, request: &ClientMessage) -> Result<ServerMessage, ClientError> {
        write_message(&mut self.input, &request.encode(Version::MANAGEMENT)?)?;
        let payload = match read_frame(&mut self.output, MAX_FRAME) {
            Ok(payload) => payload,
            // `ssh`'s diagnostics went to a pipe rather than to the terminal.
            Err(error) if error.is_transport_loss() => {
                let diagnostics = self.transport.diagnostics();
                return Err(if diagnostics.is_empty() {
                    ClientError::Protocol(error)
                } else {
                    ClientError::Ssh(diagnostics)
                });
            }
            Err(error) => return Err(ClientError::Protocol(error)),
        };
        match ServerMessage::decode(&payload, Version::MANAGEMENT)? {
            ServerMessage::Reject { reason } => Err(ClientError::Remote(reason)),
            answer => Ok(answer),
        }
    }

    fn sessions(&mut self, request: &ClientMessage) -> Result<Vec<SessionSummary>, ClientError> {
        match self.ask(request)? {
            ServerMessage::SessionList { sessions } => Ok(sessions),
            _ => Err(ClientError::Protocol(DecodeError::InvalidField)),
        }
    }
}

/// List the sessions the daemon on `destination` is holding.
pub fn list(destination: &str) -> Result<(), ClientError> {
    let sessions = Management::open(destination)?.sessions(&ClientMessage::ListSessions)?;
    print_sessions(&sessions);
    Ok(())
}

/// End one session on `destination`, and the shell inside it.
pub fn kill(destination: &str, prefix: &str) -> Result<(), ClientError> {
    let mut daemon = Management::open(destination)?;
    let sessions = daemon.sessions(&ClientMessage::ListSessions)?;
    let ids: Vec<SessionId> = sessions.iter().map(|session| session.session_id).collect();
    let session_id = resolve(&ids, prefix)?;
    let remaining = daemon.sessions(&ClientMessage::KillSession { session_id })?;
    // The list the daemon has left is the only confirmation there is.
    if remaining
        .iter()
        .any(|session| session.session_id == session_id)
    {
        return Err(ClientError::Management(format!(
            "session {} is still running",
            short_id(session_id)
        )));
    }
    Ok(())
}

/// Search every session's scrollback: the pattern travels, the history does not.
pub fn grep(destination: &str, pattern: &str) -> Result<(), ClientError> {
    let limit = u16::try_from(MAX_MATCHES).unwrap_or(u16::MAX);
    let answer = Management::open(destination)?.ask(&ClientMessage::Search {
        pattern: pattern.to_owned(),
        limit,
    })?;
    let ServerMessage::SearchResults { matches } = answer else {
        return Err(ClientError::Protocol(DecodeError::InvalidField));
    };
    if matches.is_empty() {
        println!("no matches");
        return Ok(());
    }
    print!("{}", match_lines(&matches));
    Ok(())
}

/// The one session id starting with `prefix`. Shared with the resume path,
/// which resolves the same way against the sessions this client remembers.
pub(crate) fn resolve(ids: &[SessionId], prefix: &str) -> Result<SessionId, ClientError> {
    let prefix = prefix.to_ascii_lowercase();
    // The one input where "unique prefix" would quietly pick an arbitrary one.
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ClientError::Management(
            "a session id is hexadecimal; run `brd ls <destination>` for the list".into(),
        ));
    }
    let mut matched = ids.iter().filter(|id| hex_id(**id).starts_with(&prefix));
    let Some(first) = matched.next() else {
        return Err(ClientError::Management(format!(
            "no session matches {prefix}"
        )));
    };
    if matched.next().is_some() {
        return Err(ClientError::Management(format!(
            "{prefix} matches more than one session; use more characters"
        )));
    }
    Ok(*first)
}

fn hex_id(id: SessionId) -> String {
    let bytes = id.as_bytes();
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn short_id(id: SessionId) -> String {
    let mut hex = hex_id(id);
    hex.truncate(SHORT_ID);
    hex
}

/// One line per match, under the id width `brd ls` prints so the two agree.
fn match_lines(matches: &[SearchMatch]) -> String {
    let mut out = String::new();
    for found in matches {
        let _ = writeln!(out, "{}  {}", short_id(found.session_id), found.line);
    }
    out
}

/// How long ago the session last did anything, in one coarsening unit.
fn idle(seconds: u64) -> String {
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3_600 => format!("{}m", seconds / 60),
        3_600..86_400 => format!("{}h", seconds / 3_600),
        _ => format!("{}d", seconds / 86_400),
    }
}

/// A session is shared rather than owned, so the client column is a count.
const HEADERS: [&str; 5] = ["ID", "SIZE", "CLIENTS", "IDLE", "COMMAND"];

fn print_sessions(sessions: &[SessionSummary]) {
    if sessions.is_empty() {
        println!("no sessions");
        return;
    }
    // Wall clock on both sides: `active_unix` is what the wire carries.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    print!("{}", table(sessions, now));
}

fn table(sessions: &[SessionSummary], now: u64) -> String {
    let rows: Vec<[String; 5]> = sessions
        .iter()
        .map(|session| {
            [
                short_id(session.session_id),
                format!("{}x{}", session.size.cols, session.size.rows),
                session.attachments.to_string(),
                idle(now.saturating_sub(session.active_unix)),
                session.command.clone(),
            ]
        })
        .collect();
    // A column is measured in cells; `cell.len()` is neither cells nor chars.
    let mut widths = HEADERS.map(UnicodeWidthStr::width);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.width());
        }
    }
    let mut out = String::new();
    write_row(&mut out, &widths, &HEADERS.map(str::to_owned));
    for row in &rows {
        write_row(&mut out, &widths, row);
    }
    out
}

/// Trailing spaces after a command are invisible until someone copies the line.
fn write_row(out: &mut String, widths: &[usize; 5], cells: &[String; 5]) {
    for (index, cell) in cells.iter().enumerate() {
        out.push_str(cell);
        if index + 1 == cells.len() {
            continue;
        }
        for _ in 0..widths[index].saturating_sub(cell.width()) {
            out.push(' ');
        }
        out.push_str("  ");
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use braid_proto::GridSize;

    fn summary(id: u8, command: &str) -> SessionSummary {
        SessionSummary {
            session_id: SessionId::from_bytes([id; 16]),
            size: GridSize {
                cols: 120,
                rows: 40,
            },
            attachments: 0,
            active_unix: 0,
            command: command.into(),
        }
    }

    fn ids(bytes: &[u8]) -> Vec<SessionId> {
        bytes
            .iter()
            .map(|byte| SessionId::from_bytes([*byte; 16]))
            .collect()
    }

    /// A user retypes what `brd ls` printed, and the refusals are the inputs
    /// where "unique prefix" would kill an arbitrary session.
    #[test]
    fn a_session_is_named_by_a_unique_prefix_and_by_nothing_else() {
        let sessions = ids(&[0x1a, 0x2b, 0xaa, 0xab]);
        for (prefix, expected, why) in [
            ("1a1a", Some(0), "a unique prefix"),
            ("2B", Some(1), "case is not the user's problem"),
            ("ab", Some(3), "a prefix long enough to disambiguate"),
            ("", None, "an empty prefix names every session"),
            ("a", None, "two sessions start with a"),
            ("zz", None, "not hexadecimal"),
            ("ffff", None, "matches nothing"),
        ] {
            match expected {
                Some(index) => assert_eq!(
                    resolve(&sessions, prefix).expect(why),
                    sessions[index],
                    "{prefix}: {why}"
                ),
                None => assert!(resolve(&sessions, prefix).is_err(), "{prefix}: {why}"),
            }
        }
    }

    #[test]
    fn idle_coarsens_as_it_grows() {
        assert_eq!(idle(0), "0s");
        assert_eq!(idle(59), "59s");
        assert_eq!(idle(60), "1m");
        assert_eq!(idle(3_599), "59m");
        assert_eq!(idle(3_600), "1h");
        assert_eq!(idle(86_400), "1d");
    }

    /// Widest-cell columns, a client count, and no trailing space to copy.
    #[test]
    fn the_table_aligns_every_column_but_the_last() {
        let mut shared = summary(0x1a, "-bash");
        shared.attachments = 2;
        shared.active_unix = 3_600;
        let mut idle = summary(0xbe, "vim a-very-long-file-name.rs");
        idle.size = GridSize { cols: 80, rows: 24 };
        idle.active_unix = 3_500;
        assert_eq!(
            table(&[shared, idle], 3_600 + 90),
            "\
ID        SIZE    CLIENTS  IDLE  COMMAND
1a1a1a1a  120x40  2        1m    -bash
bebebebe  80x24   0        3m    vim a-very-long-file-name.rs
"
        );
    }

    /// A cell padded to a byte count is a column that stops being one.
    #[test]
    fn a_cell_is_padded_to_its_display_width() {
        let row = |first: &str| {
            let mut out = String::new();
            let cells = [
                first.to_owned(),
                "1".to_owned(),
                "1".to_owned(),
                "1".to_owned(),
                "cmd".to_owned(),
            ];
            write_row(&mut out, &[6, 1, 1, 1, 0], &cells);
            out
        };
        assert_eq!(
            row("\u{4e2d}\u{6587}"),
            "\u{4e2d}\u{6587}    1  1  1  cmd\n"
        );
        assert_eq!(row("abcdef"), "abcdef  1  1  1  cmd\n");
    }

    /// The short id is the one `brd ls` prints.
    #[test]
    fn search_results_render_one_line_per_match() {
        let matches = [
            SearchMatch {
                session_id: SessionId::from_bytes([0x1a; 16]),
                distance: 12,
                line: "error: no such file".into(),
            },
            SearchMatch {
                session_id: SessionId::from_bytes([0xbe; 16]),
                distance: 0,
                line: "error: connection refused".into(),
            },
        ];
        assert_eq!(
            match_lines(&matches),
            "1a1a1a1a  error: no such file\nbebebebe  error: connection refused\n"
        );
    }
}
