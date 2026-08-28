#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::iter::Peekable;
use std::num::{NonZeroU32, NonZeroU64};
use thiserror::Error;

pub mod screen;
pub mod wire;
use screen::{
    CHUNK_FIXED, MAX_CLUSTER_BYTES, decode_row_frame, decode_sticky, encode_row_chunk,
    encode_sticky, has_control, reject_control, sticky_bytes,
};
pub use screen::{
    CellStyle, CursorShape, MAX_DEFERRED, MAX_DEFERRED_BYTES, MAX_RUN_BYTES, MAX_TITLE, ModeSet,
    REPAINT_MODES, RESET_ON_EXIT, RowChunk, RowChunks, RowFrame, ScrollBand, StickyState,
    StyleAttrs, StyleColor, StyleRun, UnderlineStyle,
};

pub const PROTOCOL_VERSION: u16 = 15;

/// The oldest frame layout this build decodes. Appending a field or a message raises
/// [`PROTOCOL_VERSION`] and leaves this alone; raising *this* is a flag day.
pub const MIN_PROTOCOL_VERSION: u16 = 14;

/// The dialect `brd ls`, `brd kill` and `brd grep` are spoken in, on a connection that
/// never handshook. **It never moves.**
///
/// Deliberately its own constant rather than [`MIN_PROTOCOL_VERSION`]: those two were
/// equal, so management silently inherited the floor, and the day the floor rises the
/// two ends are speaking different management dialects with no negotiation to notice.
/// The whole point of answering management without a handshake is that an upgraded
/// binary can still enumerate and kill the daemon holding the user's shells — which is
/// a promise about a *fixed* layout, not about whatever this build's floor happens to be.
pub const MANAGEMENT_VERSION: u16 = 14;

/// Management is a frozen dialect, so its messages may never gain a version-gated field:
/// there is no negotiated version at which to decide whether one is present.
const _: () = assert!(MANAGEMENT_VERSION <= MIN_PROTOCOL_VERSION);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionRange {
    oldest: u16,
    newest: u16,
}

impl VersionRange {
    pub const LOCAL: Self = Self {
        oldest: MIN_PROTOCOL_VERSION,
        newest: PROTOCOL_VERSION,
    };

    pub const fn new(oldest: u16, newest: u16) -> Option<Self> {
        if oldest == 0 || oldest > newest {
            return None;
        }
        Some(Self { oldest, newest })
    }

    pub const fn oldest(self) -> u16 {
        self.oldest
    }

    pub const fn newest(self) -> u16 {
        self.newest
    }

    /// Answer a client's range: the version to speak, or the refusal to send.
    pub const fn negotiate(self, client: Self) -> Result<Version, RejectReason> {
        let newest = if self.newest < client.newest {
            self.newest
        } else {
            client.newest
        };
        let oldest = if self.oldest > client.oldest {
            self.oldest
        } else {
            client.oldest
        };
        if oldest > newest {
            return Err(RejectReason::Version {
                server: self,
                client,
            });
        }
        Ok(Version(newest))
    }
}

impl std::fmt::Display for VersionRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.oldest == self.newest {
            write!(f, "{}", self.newest)
        } else {
            write!(f, "{}-{}", self.oldest, self.newest)
        }
    }
}

/// A negotiated version, or one of the two fixed points a connection that never
/// negotiated speaks at. Constructible nowhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u16);

impl Version {
    /// The oldest version this build decodes.
    pub const FLOOR: Self = Self(MIN_PROTOCOL_VERSION);

    /// What management is spoken at, at both ends, for ever. See [`MANAGEMENT_VERSION`].
    pub const MANAGEMENT: Self = Self(MANAGEMENT_VERSION);

    /// The newest version this build speaks, and the one a *handshake* frame is read
    /// and written at: a `Hello` is the frame that does the negotiating.
    pub const LOCAL: Self = Self(PROTOCOL_VERSION);

    pub const fn get(self) -> u16 {
        self.0
    }

    /// Whether a peer at this version understands [`ServerMessage::OutputSkipped`].
    ///
    /// A *message*, unlike a field, carries no version gate in the codec — an unknown
    /// tag is a hard [`DecodeError::BadTag`], not a skip — so the sender is the only
    /// thing that can keep one away from a peer too old to read it.
    pub const fn carries_output_skipped(self) -> bool {
        self.0 >= OUTPUT_SKIPPED_VERSION
    }
}

/// The version [`ServerMessage::OutputSkipped`] was appended in.
const OUTPUT_SKIPPED_VERSION: u16 = 15;

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The only size bound on the wire.
pub const MAX_FRAME: u32 = 1024 * 1024;

/// Bytes of a `braid` frame that fit one datagram on an unprobed path: the IPv6
/// minimum MTU, less the datagram transport's own header and authentication tag.
pub const MIN_DATAGRAM_FRAME: usize = 1200 - 40;

pub const MAX_OUTPUT_CHUNK: usize = 64 * 1024;
/// Bound on one `Input` message, deliberately not sized by a server output constant.
pub const MAX_INPUT_CHUNK: usize = 64 * 1024;
/// A resume capability is exactly this long; the wire field carries no other length.
pub const CAPABILITY_BYTES: usize = 32;
/// Bound on a frame this side will accept from a *client*. The largest legal client
/// message is an `Input` chunk, so a daemon must not size its read buffer by [`MAX_FRAME`].
pub const MAX_CLIENT_FRAME: u32 = 68 * 1024;
pub const MAX_TERM: usize = 64;
/// Bytes and count of the environment a client forwards: a whitelist, not a copy.
pub const MAX_ENV: usize = 4096;
pub const MAX_ENV_VARS: usize = 16;
pub const MAX_SESSIONS: usize = 256;
pub const MAX_COMMAND: usize = 128;
pub const MAX_COMMAND_WORDS: usize = 16;
/// Attachments one session will carry at once: each costs a thread, a sink and a
/// screen ledger holding two row snapshots.
pub const MAX_ATTACHMENTS: usize = 8;
pub const MAX_PATTERN: usize = 256;
pub const MAX_MATCHES: usize = 256;
pub const MAX_MATCH_LINE: usize = 512;
pub const MAX_FORWARDS: usize = 8;
/// Bytes of a forward target's host name: a DNS name's limit, which is also the `u8` field's.
pub const MAX_FORWARD_HOST: usize = 255;
/// Bytes of forwarded payload one message carries: the reorder unit as well as the
/// transmit cut, so it is smaller than [`MAX_INPUT_CHUNK`].
pub const MAX_FORWARD_CHUNK: usize = 32 * 1024;

/// Runs of a forwarded stream one acknowledgement may name past its gap. Eight bytes
/// each, so the whole list still fits the datagram everything else on the path fits.
pub const MAX_ACK_RUNS: usize = 32;

/// Bytes of big-endian length in front of every frame's body. The one place the
/// width is decided: a peer that framed to its own number would be reading a
/// different protocol.
pub const LENGTH_PREFIX: usize = 4;

/// Where each direction's message tags start: disjoint halves, so a frame that reached
/// the wrong end is an unknown tag rather than a different message read as if it belonged.
const CLIENT_TAG_BASE: u8 = 1;
const SERVER_TAG_BASE: u8 = 0x81;

/// A client's position in the ordered command stream. Non-zero by construction:
/// absence is `Option<CmdSeq>`, parsed at the wire and never carried past it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct CmdSeq(NonZeroU64);
impl CmdSeq {
    pub const fn first() -> Self {
        Self(NonZeroU64::new(1).unwrap())
    }
    pub const fn get(self) -> u64 {
        self.0.get()
    }
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
    pub const fn from_u64(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
    fn decode(value: u64) -> Result<Self, DecodeError> {
        Self::from_u64(value).ok_or(DecodeError::InvalidField)
    }
}

/// A forwarded connection, numbered by the client that opened it. Non-zero for
/// [`CmdSeq`]'s reason; only the client allocates one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StreamId(NonZeroU32);
impl StreamId {
    pub const fn first() -> Self {
        Self(NonZeroU32::new(1).unwrap())
    }
    pub const fn get(self) -> u32 {
        self.0.get()
    }
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
    pub const fn from_u32(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
    fn decode(value: u32) -> Result<Self, DecodeError> {
        Self::from_u32(value).ok_or(DecodeError::InvalidField)
    }
}

/// One run of bytes a receiver holds past the gap its acknowledgement names.
/// `gap` is measured from the end of the previous run — from the cumulative offset
/// itself, for the first — so a list of these is ordered and disjoint by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SackRun {
    pub gap: NonZeroU32,
    pub len: NonZeroU32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SackRuns(Vec<SackRun>);

impl SackRuns {
    pub const EMPTY: Self = Self(Vec::new());

    pub fn new(runs: Vec<SackRun>) -> Option<Self> {
        (runs.len() <= MAX_ACK_RUNS).then_some(Self(runs))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[SackRun] {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The runs as absolute `[start, end)` byte ranges above `base`.
    pub fn absolute(&self, base: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        let mut cursor = base;
        self.0.iter().map(move |run| {
            let start = cursor.saturating_add(u64::from(run.gap.get()));
            let end = start.saturating_add(u64::from(run.len.get()));
            cursor = end;
            (start, end)
        })
    }
}

/// A session's bearer credential, exactly as long as the only value it may hold.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Capability([u8; CAPABILITY_BYTES]);
impl Capability {
    pub const fn from_bytes(bytes: [u8; CAPABILITY_BYTES]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; CAPABILITY_BYTES] {
        &self.0
    }
}

/// Opaque: a bearer credential must not reach a log line through a `Debug`.
impl std::fmt::Debug for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Capability(..)")
    }
}

/// Where this daemon will accept datagrams, and the secret that authenticates them.
///
/// `ip` is the address the *ssh connection* arrived on, filled in by the relay under
/// `sshd`: a daemon behind NAT or a `ProxyJump` cannot know which of its addresses the
/// client reached. Zero means the relay could not tell, and a zero address is no offer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DatagramOffer {
    /// IPv6, with IPv4 in the mapped range.
    pub ip: [u8; 16],
    pub port: u16,
    pub cid: [u8; 8],
    pub secret: [u8; 32],
}

/// Opaque for [`Capability`]'s reason: `secret` authenticates every datagram.
impl std::fmt::Debug for DatagramOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatagramOffer(..)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ByteOff(u64);
impl ByteOff {
    pub const fn zero() -> Self {
        Self(0)
    }
    pub const fn get(self) -> u64 {
        self.0
    }
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }
    pub fn checked_add(self, amount: usize) -> Option<Self> {
        self.0.checked_add(amount.try_into().ok()?).map(Self)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Generation(NonZeroU64);
impl Generation {
    pub const fn initial() -> Self {
        Self(NonZeroU64::new(1).unwrap())
    }
    pub const fn get(self) -> u64 {
        self.0.get()
    }
    pub fn from_u64(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
    fn decode(value: u64) -> Result<Self, DecodeError> {
        Self::from_u64(value).ok_or(DecodeError::InvalidField)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ScreenVersion(NonZeroU64);
impl ScreenVersion {
    pub const fn initial() -> Self {
        Self(NonZeroU64::new(1).unwrap())
    }
    pub const fn get(self) -> u64 {
        self.0.get()
    }
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
    fn decode(value: u64) -> Result<Self, DecodeError> {
        Self::from_u64(value).ok_or(DecodeError::InvalidField)
    }
    pub const fn from_u64(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GridSize {
    pub cols: u16,
    pub rows: u16,
}
impl GridSize {
    pub const MAX_COLS: u16 = 1024;
    pub const MAX_ROWS: u16 = 512;
    pub fn new(cols: u16, rows: u16) -> Option<Self> {
        if !(1..=Self::MAX_COLS).contains(&cols) || !(1..=Self::MAX_ROWS).contains(&rows) {
            return None;
        }
        Some(Self { cols, rows })
    }
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("stream ended before a complete frame")]
    Truncated,
    #[error("frame length {actual} exceeds limit {limit}")]
    Oversize { actual: u32, limit: u32 },
    #[error("invalid protocol version {0}")]
    Version(u16),
    #[error("unknown message tag {0:#x}")]
    BadTag(u8),
    #[error("invalid message field")]
    InvalidField,
    #[error("invalid UTF-8")]
    BadUtf8,
    #[error("trailing bytes in frame")]
    TrailingBytes,
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
}

impl DecodeError {
    /// Whether the frame was lost with the stream rather than malformed by the peer:
    /// `read_frame` reports a closed transport as `Truncated`, not as `Io`.
    #[must_use]
    pub const fn is_transport_loss(&self) -> bool {
        matches!(self, Self::Truncated | Self::Io(_))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodeError {
    #[error("frame is larger than the protocol limit")]
    Oversize,
    #[error("not a terminfo name")]
    BadTerm,
    #[error("environment is not forwardable")]
    BadEnv,
    #[error("command is not runnable")]
    BadCommand,
    #[error("session command contains control characters")]
    BadSessionName,
    #[error("not a searchable pattern")]
    BadPattern,
    #[error("search result contains control characters")]
    BadMatch,
    #[error("not a forwardable destination")]
    BadForwardTarget,
    #[error("screen names {actual} rows for a {expected}-row grid")]
    RowCount { expected: u16, actual: usize },
    #[error("delta names row {0} outside its own grid")]
    RowIndex(u16),
    #[error("deferred sequence carries a control byte")]
    BadDeferred,
    #[error("scroll band {0:?} is not a movement inside its own grid")]
    BadScroll(ScrollBand),
}

/// What a client forwards from the SSH connection it arrived on: the per-connection
/// half of the environment, whitelisted at the client and applied over the daemon's base.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionEnv(pub Vec<(String, String)>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    pub session_id: SessionId,
    pub size: GridSize,
    /// Clients watching right now; a session is shared, not owned.
    pub attachments: u16,
    /// Wall-clock seconds, because this is printed to a human.
    pub active_unix: u64,
    pub command: String,
}

/// One `brd` process, stable across every reconnect it makes. A resume replaces the
/// attachment carrying the same id; anything else joins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientId([u8; 16]);
impl ClientId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMessage {
    Hello {
        versions: VersionRange,
        size: GridSize,
        term: String,
        env: SessionEnv,
        /// argv to run instead of a login shell; empty means the login shell.
        command: Vec<String>,
        client: ClientId,
    },
    /// Open a session that carries forwarded connections and nothing else: no grid, no
    /// `TERM`, no environment and no argv.
    HelloForward {
        versions: VersionRange,
        client: ClientId,
    },
    Input {
        seq: CmdSeq,
        bytes: Vec<u8>,
    },
    Resize {
        seq: CmdSeq,
        size: GridSize,
    },
    RequestRepaint {
        seq: CmdSeq,
    },
    /// Confirm the screen the client is now holding. Unsequenced: idempotent state rather
    /// than a command, so a dropped one costs nothing — the next screen brings another.
    ScreenAck {
        generation: Generation,
        version: ScreenVersion,
    },
    Close {
        seq: CmdSeq,
    },
    Resume {
        /// Carried here as well as in [`Self::Hello`]: a resume is an establishment message,
        /// refused on the range before it can reach the session.
        versions: VersionRange,
        seq: CmdSeq,
        request: ResumeRequest,
    },
    /// Leave the session without terminating it.
    Detach {
        seq: CmdSeq,
    },
    /// Answer to [`ServerMessage::Ping`], echoing its token. Unsequenced, so it never
    /// queues behind input the link has not carried yet.
    Pong {
        token: u64,
        /// The next output byte this client wants: the receive window. A datagram send never
        /// blocks, so without this the server fires at full rate at a client that cannot draw it.
        consumed: ByteOff,
    },
    /// The next output byte this client wants, sent when the client has drawn enough to
    /// move it rather than when the server next probes. Unsequenced and idempotent: the
    /// server keeps the largest it has seen.
    Consumed {
        off: ByteOff,
    },
    /// Enumerate the daemon's sessions. Spoken at [`Version::MANAGEMENT`] at both ends,
    /// because the connection answering it never handshook.
    ListSessions,
    /// End one session and the shell inside it.
    KillSession {
        session_id: SessionId,
    },
    /// Search every session's scrollback on this daemon, where the history lives. Spoken
    /// at [`Version::MANAGEMENT`] beside the other management messages.
    Search {
        pattern: String,
        limit: u16,
    },
    /// Open a forwarded connection to `target`, under a number this client allocated. The
    /// only sequenced message a forward has; a lost payload must not stall the command gate.
    ForwardOpen {
        seq: CmdSeq,
        stream: StreamId,
        target: ForwardTarget,
    },
    /// Payload for a forwarded connection, in the client's direction. `off` positions these
    /// bytes in that connection's own byte stream and `fin` marks the last byte of this
    /// direction, so a close that overtakes its own data still ends the stream at the right byte.
    ForwardData {
        stream: StreamId,
        off: ByteOff,
        fin: bool,
        bytes: Vec<u8>,
    },
    /// How much of the server's direction this client has written out, how much room is left
    /// behind it, and what it is holding past the gap. Idempotent: each end keeps the largest
    /// offset it has seen, and `held` is what makes the repair selective.
    ForwardAck {
        stream: StreamId,
        off: ByteOff,
        window: u32,
        held: SackRuns,
    },
    /// This stream is over, in both directions and at once. Repeatable and idempotent: a peer
    /// holding no such stream answers anything naming it with one of these, and never answers
    /// a reset with a reset.
    ForwardReset {
        stream: StreamId,
        reason: ForwardResetReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchMatch {
    pub session_id: SessionId,
    /// Rows back from the bottom of that session's history.
    pub distance: u32,
    pub line: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetachReason {
    Requested,
    /// The same client came back on a newer transport and replaced this attachment. A
    /// *different* client joining never displaces anyone.
    Replaced,
}

impl DetachReason {
    const fn to_wire(self) -> u8 {
        match self {
            Self::Requested => 0,
            Self::Replaced => 1,
        }
    }

    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Requested),
            1 => Some(Self::Replaced),
            _ => None,
        }
    }
}

/// Where a forwarded connection is to be made. Resolved at the far end: the point of a
/// forward is to reach a name that only means something on the daemon's host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardResetReason {
    /// Nothing is listening on the destination port.
    Refused,
    /// The destination host did not resolve, or nothing routes to it.
    Unreachable,
    /// The connection behind this end closed, or the stream was already gone.
    Closed,
    /// This end is already carrying [`MAX_FORWARDS`] streams.
    Limit,
    /// The forward failed for a reason neither end can act on.
    Internal,
}

impl ForwardResetReason {
    const fn to_wire(self) -> u8 {
        match self {
            Self::Refused => 0,
            Self::Unreachable => 1,
            Self::Closed => 2,
            Self::Limit => 3,
            Self::Internal => 4,
        }
    }

    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Refused),
            1 => Some(Self::Unreachable),
            2 => Some(Self::Closed),
            3 => Some(Self::Limit),
            4 => Some(Self::Internal),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);
impl SessionId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Where a resuming client's terminal already is in the output stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmedOutput {
    pub generation: Generation,
    pub next_off: ByteOff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResumeRequest {
    pub session_id: SessionId,
    pub capability: Capability,
    pub confirmed_output: ConfirmedOutput,
    /// Which attachment this replaces, if the session still holds one.
    pub client: ClientId,
}

/// One row entry inside a screen piece. When `chunk` is set, the frames of every entry
/// naming that row concatenate, in piece order, into the whole row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowSpan {
    pub row: u16,
    pub chunk: bool,
    /// Column this span starts at; the client keeps the columns before it.
    pub col: u16,
    /// Byte offset of `frame.text` within the whole row's text. A span boundary is always
    /// a style-run boundary, the only offset where both a column and a byte position are known.
    pub byte: u32,
    /// Erase from the end of this span to the end of the line after writing it.
    pub clear_tail: bool,
    pub frame: RowFrame,
}

impl RowSpan {
    fn encoded_len(&self) -> usize {
        PART_ROW_HEAD + self.frame.encoded_len()
    }

    fn borrow(&self) -> RowEntry<'_> {
        RowEntry {
            row: self.row,
            chunk: self.chunk,
            clear_tail: self.clear_tail,
            frame: RowChunk {
                col: self.col,
                byte: self.byte,
                ..self.frame.whole()
            },
        }
    }
}

/// One row a screen is sending, and how much of that row it is sending: a repaint sends
/// whole rows, a delta may name only the style runs that changed.
#[derive(Clone, Copy, Debug)]
pub struct RowUpdate<'a> {
    pub row: u16,
    pub frame: &'a RowFrame,
    /// Half-open style-run range of `frame` to send. The row's unstyled tail
    /// belongs to a range ending at `frame.runs.len()` and to no other.
    pub runs: (usize, usize),
    pub clear_tail: bool,
}

impl<'a> RowUpdate<'a> {
    pub fn whole(row: u16, frame: &'a RowFrame) -> Self {
        Self {
            row,
            frame,
            runs: (0, frame.runs.len()),
            clear_tail: false,
        }
    }
}

struct RowEntry<'a> {
    row: u16,
    chunk: bool,
    clear_tail: bool,
    frame: RowChunk<'a>,
}

/// A screen minus its rows, shared by every piece of that screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScreenHeader {
    pub generation: Generation,
    pub version: ScreenVersion,
    /// Stream position this screen reflects, and where passthrough resumes: without it a
    /// client leaving sync mode rejects the next `Output` as out of order.
    pub next_off: ByteOff,
    pub size: GridSize,
    pub cursor: Option<(u16, u16)>,
    pub cursor_visible: bool,
    pub cursor_shape: CursorShape,
    pub cursor_blinking: bool,
    /// Modes the application turned on and will not turn on again.
    pub modes: ModeSet,
    /// What the byte stream set that is neither grid, style nor mode.
    pub sticky: StickyState,
}

/// One piece of a screen, sized to the transport carrying it.
///
/// The only screen message: a screen that fits one frame is one `Head` with every row in
/// it, and a screen that does not is a `Head` and the `Tail`s after it. Losing a piece
/// costs those rows rather than the screen; the next screen names them again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScreenPart {
    /// The first piece: everything that is not rows, and the rows that fit beside it.
    Head {
        header: ScreenHeader,
        /// The screen a delta applies to, or `None` for a whole screen.
        base: Option<ScreenVersion>,
        /// A band of rows that moved up, applied before `rows`. Only representable on a
        /// single-piece screen: a client that applied a scroll and then lost a piece holds
        /// every row at an offset the server cannot name.
        scroll: Option<ScrollBand>,
        /// Pieces this screen was cut into, this one included. Never zero.
        pieces: u16,
        rows: Vec<RowSpan>,
    },
    Tail {
        generation: Generation,
        version: ScreenVersion,
        pieces: u16,
        /// `1 <= index < pieces`.
        index: u16,
        rows: Vec<RowSpan>,
    },
}

/// What the session promises about the echo of the next keystroke: decided by the side
/// that owns the terminal, and carried as a budget rather than the state it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputCue {
    /// Typed bytes must not be drawn locally. A full-screen application owns
    /// the grid, the cursor is hidden, or the next character wraps.
    Opaque,
    /// The application echoes printable input at the cursor, and `room` columns are free
    /// before the row's last cell. The last cell is excluded: a character predicted into it
    /// commits the terminal to a wrap the session may never make.
    Echoing { room: u16 },
}

/// Why the server is ending this attachment. Nothing free-form crosses the wire, so a
/// hostile server has no string with which to paint the user's terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RejectReason {
    #[error("this server speaks protocol {server}, this client speaks {client}")]
    Version {
        server: VersionRange,
        client: VersionRange,
    },
    #[error("session is no longer available")]
    UnknownSession,
    #[error("command sequence gap")]
    SequenceGap,
    #[error("the session is not reading input fast enough to keep this stream ordered")]
    InputBacklog,
    #[error("the session failed")]
    Internal,
    #[error("this daemon is already running its maximum number of sessions")]
    TooManySessions,
    #[error("this session is already carrying its maximum number of clients")]
    TooManyAttachments,
}

impl RejectReason {
    /// Whether reconnecting could possibly help.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Version { .. }
                | Self::UnknownSession
                | Self::TooManySessions
                | Self::TooManyAttachments
        )
    }

    const fn to_wire(self) -> u8 {
        match self {
            Self::Version { .. } => 0,
            Self::UnknownSession => 1,
            Self::SequenceGap => 2,
            Self::InputBacklog => 3,
            Self::Internal => 4,
            Self::TooManySessions => 5,
            Self::TooManyAttachments => 6,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerMessage {
    Hello {
        /// The version the server picked out of the client's range.
        version: Version,
        size: GridSize,
        session_id: SessionId,
        capability: Capability,
        /// Where this session will also take datagrams, when it takes them at all.
        offer: Option<DatagramOffer>,
    },
    /// Answer to [`ClientMessage::HelloForward`]: [`Self::Hello`] without the grid, because
    /// there is no terminal here to describe.
    HelloForward {
        version: Version,
        session_id: SessionId,
        capability: Capability,
        offer: Option<DatagramOffer>,
    },
    Output {
        off: ByteOff,
        bytes: Vec<u8>,
        /// Where echo stands as of the last byte in `bytes`.
        cue: InputCue,
        /// Newest command the application has had long enough to echo: a client cannot otherwise
        /// tell a wrong prediction from an application that has not answered yet.
        echo_ack: Option<CmdSeq>,
    },
    Exit {
        code: i32,
    },
    Reject {
        reason: RejectReason,
    },
    CommandAck {
        highest: Option<CmdSeq>,
    },
    Detached {
        reason: DetachReason,
    },
    /// Liveness probe, answered with [`ClientMessage::Pong`] carrying the same token.
    /// Outside the command sequence: a journalled heartbeat measures the age of a reconnect
    /// rather than the link.
    Ping {
        token: u64,
        /// Carried here too, so an application that has fallen silent still
        /// releases the predictions a client is holding against it.
        echo_ack: Option<CmdSeq>,
        /// How long the client may wait for the next one of these. The server owns pacing and
        /// the client owns patience; without it the client's silence deadline is a constant
        /// sized for the worst link anyone might have.
        interval_ms: u16,
    },
    /// Answer to [`ClientMessage::ListSessions`], spoken at the floor.
    SessionList {
        sessions: Vec<SessionSummary>,
    },
    SearchResults {
        matches: Vec<SearchMatch>,
    },
    Screen {
        part: ScreenPart,
    },
    /// Payload for a forwarded connection, in the destination's direction. `off` and `fin`
    /// position it exactly as in [`ClientMessage::ForwardData`].
    ForwardData {
        stream: StreamId,
        off: ByteOff,
        fin: bool,
        bytes: Vec<u8>,
    },
    /// The [`ClientMessage::ForwardAck`] of this direction, idempotent for the same reason.
    ForwardAck {
        stream: StreamId,
        off: ByteOff,
        window: u32,
        held: SackRuns,
    },
    /// The [`ClientMessage::ForwardReset`] of this direction. A server never opens a stream.
    ForwardReset {
        stream: StreamId,
        reason: ForwardResetReason,
    },
    /// Output this attachment will never be handed, counted in bytes of the session's
    /// stream. Sent when a resume is answered with a screen instead of the history it
    /// asked for: the screen converges the *grid*, but those bytes never reach the
    /// user's own scrollback, and silence there is indistinguishable from having seen
    /// everything. Diagnostic only — nothing is repaired by it.
    OutputSkipped {
        bytes: u64,
    },
}
pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}
pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// The one flag a forward payload carries; every other bit is reserved and refused.
const FORWARD_FIN: u8 = 1;

/// A host name reaches a resolver and a diagnostic, and port zero is not a destination.
fn encode_forward_target(out: &mut Vec<u8>, target: &ForwardTarget) -> Result<(), EncodeError> {
    let host = target.host.as_bytes();
    if host.is_empty()
        || host.len() > MAX_FORWARD_HOST
        || has_control(&target.host)
        || target.port == 0
    {
        return Err(EncodeError::BadForwardTarget);
    }
    let len = u8::try_from(host.len()).map_err(|_| EncodeError::BadForwardTarget)?;
    out.push(len);
    out.extend_from_slice(host);
    put_u16(out, target.port);
    Ok(())
}

/// The `u8` length field is [`MAX_FORWARD_HOST`]'s own bound, not a second one checked against it.
fn decode_forward_target(c: &mut Cursor<'_>) -> Result<ForwardTarget, DecodeError> {
    let len = usize::from(c.u8()?);
    let host = c.str(len)?.to_owned();
    reject_control(&host)?;
    let port = c.u16()?;
    if host.is_empty() || port == 0 {
        return Err(DecodeError::InvalidField);
    }
    Ok(ForwardTarget { host, port })
}

pub(crate) fn encode_cursor(out: &mut Vec<u8>, cursor: Option<(u16, u16)>) {
    match cursor {
        Some((x, y)) => {
            out.push(1);
            put_u16(out, x);
            put_u16(out, y);
        }
        None => out.push(0),
    }
}

pub(crate) fn decode_cursor(c: &mut Cursor<'_>) -> Result<Option<(u16, u16)>, DecodeError> {
    match c.u8()? {
        0 => Ok(None),
        1 => Ok(Some((c.u16()?, c.u16()?))),
        _ => Err(DecodeError::InvalidField),
    }
}

fn encode_cue(out: &mut Vec<u8>, cue: InputCue) {
    match cue {
        InputCue::Opaque => out.push(0),
        InputCue::Echoing { room } => {
            out.push(1);
            put_u16(out, room);
        }
    }
}

fn decode_cue(c: &mut Cursor<'_>) -> Result<InputCue, DecodeError> {
    match c.u8()? {
        0 => Ok(InputCue::Opaque),
        1 => Ok(InputCue::Echoing { room: c.u16()? }),
        _ => Err(DecodeError::InvalidField),
    }
}

fn encode_scroll(out: &mut Vec<u8>, scroll: Option<ScrollBand>) {
    match scroll {
        None => out.push(0),
        Some(band) => {
            out.push(1);
            put_u16(out, band.top);
            put_u16(out, band.bottom);
            put_u16(out, band.lines);
        }
    }
}

fn decode_scroll(c: &mut Cursor<'_>, rows: u16) -> Result<Option<ScrollBand>, DecodeError> {
    match c.u8()? {
        0 => Ok(None),
        1 => {
            let band = ScrollBand {
                top: c.u16()?,
                bottom: c.u16()?,
                lines: c.u16()?,
            };
            // The client hands these three numbers to `CSI r`, so a band naming no movement it
            // could apply is a corrupted terminal rather than a wrong repaint.
            if !band.is_applicable(rows) {
                return Err(DecodeError::InvalidField);
            }
            Ok(Some(band))
        }
        _ => Err(DecodeError::InvalidField),
    }
}

pub(crate) fn decode_bool(c: &mut Cursor<'_>) -> Result<bool, DecodeError> {
    match c.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::InvalidField),
    }
}

/// A datagram offer past its presence byte: an address, a port, a connection id and a secret.
const OFFER_BYTES: usize = 16 + 2 + 8 + 32;

fn encode_offer(out: &mut Vec<u8>, offer: Option<DatagramOffer>) {
    match offer {
        None => out.push(0),
        Some(offer) => {
            out.push(1);
            out.extend_from_slice(&offer.ip);
            put_u16(out, offer.port);
            out.extend_from_slice(&offer.cid);
            out.extend_from_slice(&offer.secret);
        }
    }
}

fn decode_offer(c: &mut Cursor<'_>) -> Result<Option<DatagramOffer>, DecodeError> {
    match c.u8()? {
        0 => Ok(None),
        1 => Ok(Some(DatagramOffer {
            ip: c.array()?,
            port: c.u16()?,
            cid: c.array()?,
            secret: c.array()?,
        })),
        _ => Err(DecodeError::InvalidField),
    }
}

fn encode_header(out: &mut Vec<u8>, header: &ScreenHeader) -> Result<(), EncodeError> {
    put_u64(out, header.generation.get());
    put_u64(out, header.version.get());
    put_u64(out, header.next_off.get());
    put_u16(out, header.size.cols);
    put_u16(out, header.size.rows);
    encode_cursor(out, header.cursor);
    out.push(u8::from(header.cursor_visible));
    out.push(header.cursor_shape.to_wire());
    out.push(u8::from(header.cursor_blinking));
    put_u32(out, header.modes.bits());
    encode_sticky(out, &header.sticky)
}

fn decode_header(c: &mut Cursor<'_>) -> Result<ScreenHeader, DecodeError> {
    let generation = Generation::decode(c.u64()?)?;
    let version = ScreenVersion::decode(c.u64()?)?;
    let next_off = ByteOff(c.u64()?);
    let size = GridSize::new(c.u16()?, c.u16()?).ok_or(DecodeError::InvalidField)?;
    let cursor = decode_cursor(c)?;
    // Validated rather than clamped at render: a cursor outside the grid means the server
    // computed something wrong, and a clamp is what makes that invisible.
    if let Some((x, y)) = cursor
        && (x >= size.cols || y >= size.rows)
    {
        return Err(DecodeError::InvalidField);
    }
    let cursor_visible = decode_bool(c)?;
    let cursor_shape = CursorShape::from_wire(c.u8()?).ok_or(DecodeError::InvalidField)?;
    let cursor_blinking = decode_bool(c)?;
    let modes = ModeSet::decode(c.u32()?).ok_or(DecodeError::InvalidField)?;
    let sticky = decode_sticky(c)?;
    // A saved cursor is restored by positioning the terminal there, so it is bounded like the live one.
    if let Some((x, y)) = sticky.saved_cursor
        && (x >= size.cols || y >= size.rows)
    {
        return Err(DecodeError::InvalidField);
    }
    Ok(ScreenHeader {
        generation,
        version,
        next_off,
        size,
        cursor,
        cursor_visible,
        cursor_shape,
        cursor_blinking,
        modes,
        sticky,
    })
}

/// Bytes a screen needs before its rows. Counted exactly rather than bounded: the cut is
/// computed against this number, and an estimate that is merely generous produces pieces
/// that fragment on the path they were sized for.
fn screen_prefix(header: &ScreenHeader) -> usize {
    64 + sticky_bytes(&header.sticky)
}

// `encode_screen_parts` cuts a screen against the sum of these.
const PART_TAG: usize = 1;
const PART_KIND: usize = 1;
const PART_BASE: usize = 8;
const PART_SCROLL: usize = 7;
const PART_PIECES: usize = 2;
const PART_INDEX: usize = 2;
const PART_GENERATION: usize = 8;
const PART_VERSION: usize = 8;
const PART_ROW_COUNT: usize = 2;
/// What a piece writes before one row's chunk: the named index, the column and the byte offset.
const PART_ROW_HEAD: usize = 8;

/// Set on a row index to mark the entry as one cut of a row too wide for a piece, and to
/// mark the row as shortened past the span. Free by construction: [`GridSize::MAX_ROWS`]
/// is 512, so no legal row index reaches bit 14.
const ROW_CHUNK_FLAG: u16 = 0x8000;
const ROW_CLEAR_TAIL_FLAG: u16 = 0x4000;
const ROW_INDEX_MASK: u16 = !(ROW_CHUNK_FLAG | ROW_CLEAR_TAIL_FLAG);

/// What a `Head` costs beside the screen prefix it shares with every screen message.
const HEAD_FIXED: usize =
    LENGTH_PREFIX + PART_TAG + PART_KIND + PART_BASE + PART_SCROLL + PART_PIECES + PART_ROW_COUNT;

/// What a `Tail` costs whole: it carries no header, which is the point of it.
const TAIL_FIXED: usize = LENGTH_PREFIX
    + PART_TAG
    + PART_KIND
    + PART_GENERATION
    + PART_VERSION
    + PART_PIECES
    + PART_INDEX
    + PART_ROW_COUNT;

/// Cut one screen into pieces that each fit `budget` bytes, which is the caller's path
/// rather than a protocol constant: a stream gives a screen a megabyte, a datagram an MTU.
///
/// A row too wide for a piece of its own is cut at style-run boundaries and carried as
/// several chunks, so this cannot fail on a colourful row. `scroll` survives only when the
/// screen turns out to be a single piece; a multi-piece scroll is refused rather than dropped.
pub fn encode_screen_parts<'a, I>(
    header: &ScreenHeader,
    base: Option<ScreenVersion>,
    scroll: Option<ScrollBand>,
    rows: I,
    budget: usize,
) -> Result<Vec<Vec<u8>>, EncodeError>
where
    I: Iterator<Item = RowUpdate<'a>> + Clone,
{
    if let Some(band) = scroll
        && !band.is_applicable(header.size.rows)
    {
        return Err(EncodeError::BadScroll(band));
    }
    let head_fixed = HEAD_FIXED + screen_prefix(header);
    // A screen with no rows still costs a `Head`.
    if head_fixed > budget {
        return Err(EncodeError::Oversize);
    }
    // Chunks are sized for a `Tail`, the smaller of the two pieces. A chunk that then does
    // not fit the `Head` simply starts the next piece.
    let chunk_budget = budget - TAIL_FIXED - PART_ROW_HEAD;
    // Chunks per piece and its size, decided before a byte is written: a `Head` carries the total.
    let mut cuts: Vec<(usize, usize)> = Vec::new();
    let mut used = head_fixed;
    let mut count = 0_usize;
    for entry in spans(rows.clone(), chunk_budget) {
        let cost = PART_ROW_HEAD + entry.frame.encoded_len();
        if used + cost > budget && !(count == 0 && used == TAIL_FIXED) {
            cuts.push((count, used));
            used = TAIL_FIXED;
            count = 0;
        }
        // One chunk is the indivisible unit, bounded by [`MAX_RUN_BYTES`]: reaching this means
        // a single style run larger than a whole piece, which the emulator does not build.
        if used + cost > budget {
            return Err(EncodeError::Oversize);
        }
        used += cost;
        count += 1;
    }
    cuts.push((count, used));

    let pieces = u16::try_from(cuts.len()).map_err(|_| EncodeError::Oversize)?;
    // `Oversize` is the whole vocabulary the caller has here.
    if scroll.is_some() && pieces != 1 {
        return Err(EncodeError::Oversize);
    }

    let mut cut = spans(rows, chunk_budget);
    let mut parts = Vec::with_capacity(cuts.len());
    for (index, (count, size)) in (0..pieces).zip(cuts) {
        let mut out = open_frame(size - LENGTH_PREFIX);
        out.push(ServerTag::Screen as u8 + SERVER_TAG_BASE);
        if index == 0 {
            out.push(0);
            encode_header(&mut out, header)?;
            put_u64(&mut out, base.map_or(0, ScreenVersion::get));
            encode_scroll(&mut out, scroll);
            put_u16(&mut out, pieces);
        } else {
            out.push(1);
            put_u64(&mut out, header.generation.get());
            put_u64(&mut out, header.version.get());
            put_u16(&mut out, pieces);
            put_u16(&mut out, index);
        }
        encode_part_rows(&mut out, count, cut.by_ref().take(count))?;
        parts.push(finish(out)?);
    }
    Ok(parts)
}

/// Every row update as the spans a piece can carry, in row order. Borrowed throughout, so
/// cutting a screen costs no allocation per row however wide the rows are.
fn spans<'a, I>(rows: I, budget: usize) -> Spans<'a, I>
where
    I: Iterator<Item = RowUpdate<'a>>,
{
    Spans {
        rows,
        budget,
        current: None,
    }
}

#[derive(Clone)]
struct Spans<'a, I> {
    rows: I,
    budget: usize,
    current: Option<Cutting<'a>>,
}

#[derive(Clone)]
struct Cutting<'a> {
    row: u16,
    cut: bool,
    clear_tail: bool,
    /// Where the span starts, kept for the row that shrank to nothing past it: such a row
    /// yields no chunk at all, and the erase it still owes has to name a column.
    start: (u16, u32),
    emitted: bool,
    chunks: Peekable<RowChunks<'a>>,
}

impl<'a, I> Iterator for Spans<'a, I>
where
    I: Iterator<Item = RowUpdate<'a>>,
{
    type Item = RowEntry<'a>;

    fn next(&mut self) -> Option<RowEntry<'a>> {
        loop {
            if let Some(cutting) = &mut self.current {
                if let Some(frame) = cutting.chunks.next() {
                    cutting.emitted = true;
                    // The erase belongs to the last span of the row and to no other.
                    let last = cutting.chunks.peek().is_none();
                    return Some(RowEntry {
                        row: cutting.row,
                        chunk: cutting.cut,
                        clear_tail: cutting.clear_tail && last,
                        frame,
                    });
                }
                if !cutting.emitted && cutting.clear_tail {
                    cutting.emitted = true;
                    return Some(RowEntry {
                        row: cutting.row,
                        chunk: cutting.cut,
                        clear_tail: true,
                        frame: RowChunk {
                            text: "",
                            runs: &[],
                            cells: 0,
                            col: cutting.start.0,
                            byte: cutting.start.1,
                        },
                    });
                }
            }
            let update = self.rows.next()?;
            let chunks = update.frame.span(update.runs, self.budget);
            let start = chunks.start();
            // One comparison decides it for the whole span, so the flag is known as each chunk is
            // written rather than after the row has been walked twice.
            let cut = update.frame.span_len(update.runs) > self.budget;
            self.current = Some(Cutting {
                row: update.row,
                cut,
                clear_tail: update.clear_tail,
                start,
                emitted: false,
                chunks: chunks.peekable(),
            });
        }
    }
}

/// A piece's rows: the count, then each row's index, where its span lands and one chunk of it.
fn encode_part_rows<'a>(
    out: &mut Vec<u8>,
    count: usize,
    rows: impl Iterator<Item = RowEntry<'a>>,
) -> Result<(), EncodeError> {
    let count = u16::try_from(count).map_err(|_| EncodeError::Oversize)?;
    put_u16(out, count);
    for entry in rows {
        if entry.row & !ROW_INDEX_MASK != 0 {
            return Err(EncodeError::RowIndex(entry.row));
        }
        let mut named = entry.row;
        if entry.chunk {
            named |= ROW_CHUNK_FLAG;
        }
        if entry.clear_tail {
            named |= ROW_CLEAR_TAIL_FLAG;
        }
        put_u16(out, named);
        put_u16(out, entry.frame.col);
        put_u32(out, entry.frame.byte);
        encode_row_chunk(out, &entry.frame)?;
    }
    Ok(())
}

fn put_screen_part(out: &mut Vec<u8>, part: &ScreenPart) -> Result<(), EncodeError> {
    match part {
        ScreenPart::Head {
            header,
            base,
            scroll,
            pieces,
            rows,
        } => {
            out.push(0);
            encode_header(out, header)?;
            put_u64(out, base.map_or(0, ScreenVersion::get));
            encode_scroll(out, *scroll);
            put_u16(out, *pieces);
            encode_part_rows(out, rows.len(), rows.iter().map(RowSpan::borrow))
        }
        ScreenPart::Tail {
            generation,
            version,
            pieces,
            index,
            rows,
        } => {
            out.push(1);
            put_u64(out, generation.get());
            put_u64(out, version.get());
            put_u16(out, *pieces);
            put_u16(out, *index);
            encode_part_rows(out, rows.len(), rows.iter().map(RowSpan::borrow))
        }
    }
}

fn decode_screen_part(c: &mut Cursor<'_>) -> Result<ScreenPart, DecodeError> {
    match c.u8()? {
        0 => {
            let header = decode_header(c)?;
            let base = ScreenVersion::from_u64(c.u64()?);
            let scroll = decode_scroll(c, header.size.rows)?;
            let pieces = c.u16()?;
            // A client that applied a scroll and then lost a piece holds every row at an offset the
            // server cannot name.
            if pieces == 0 || (scroll.is_some() && pieces != 1) {
                return Err(DecodeError::InvalidField);
            }
            let rows = decode_part_rows(c, Some(header.size))?;
            Ok(ScreenPart::Head {
                header,
                base,
                scroll,
                pieces,
                rows,
            })
        }
        1 => {
            let generation = Generation::decode(c.u64()?)?;
            let version = ScreenVersion::decode(c.u64()?)?;
            let pieces = c.u16()?;
            let index = c.u16()?;
            if pieces < 2 || index == 0 || index >= pieces {
                return Err(DecodeError::InvalidField);
            }
            Ok(ScreenPart::Tail {
                generation,
                version,
                pieces,
                index,
                rows: decode_part_rows(c, None)?,
            })
        }
        _ => Err(DecodeError::InvalidField),
    }
}

/// A piece's rows, against the grid the piece names — or, for a `Tail`, which names none,
/// against the protocol's own limits. The column limit is not left to the reassembly site:
/// an unbounded one lets a row claim 65535 style runs and buy a two-megabyte reservation
/// with thirty bytes of wire. Row indices are re-checked against the real grid there.
fn decode_part_rows(
    c: &mut Cursor<'_>,
    grid: Option<GridSize>,
) -> Result<Vec<RowSpan>, DecodeError> {
    let count = usize::from(c.u16()?);
    if count > usize::from(grid.map_or(GridSize::MAX_ROWS, |grid| grid.rows)) {
        return Err(DecodeError::InvalidField);
    }
    let cols = grid.map_or(GridSize::MAX_COLS, |grid| grid.cols);
    // A span cannot cost less than its own header and an empty chunk.
    let mut rows = Vec::with_capacity(count.min(c.remaining() / (PART_ROW_HEAD + CHUNK_FIXED)));
    let mut previous: Option<(u16, u16)> = None;
    for _ in 0..count {
        let named = c.u16()?;
        let chunk = named & ROW_CHUNK_FLAG != 0;
        let clear_tail = named & ROW_CLEAR_TAIL_FLAG != 0;
        let row = named & ROW_INDEX_MASK;
        let col = c.u16()?;
        let byte = c.u32()?;
        if grid.is_some_and(|grid| row >= grid.rows) {
            return Err(DecodeError::InvalidField);
        }
        // Non-descending, so a piece cannot depend on the order its rows are applied in. Spans
        // of one row are ordered by the column they land at, so they commute too.
        if previous.is_some_and(|(last_row, last_col)| {
            row < last_row || (row == last_row && col <= last_col)
        }) {
            return Err(DecodeError::InvalidField);
        }
        previous = Some((row, col));
        let frame = decode_row_frame(c, cols)?;
        // A span has to land inside the row it names, in both extents.
        if usize::from(col) + usize::from(frame.cells) > usize::from(cols)
            || byte as usize + frame.text.len() > usize::from(cols) * MAX_CLUSTER_BYTES
        {
            return Err(DecodeError::InvalidField);
        }
        rows.push(RowSpan {
            row,
            chunk,
            col,
            byte,
            clear_tail,
            frame,
        });
    }
    Ok(rows)
}
impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    /// Bytes of the frame this cursor has not reached yet: every reservation driven by a
    /// wire-supplied count is held against this.
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::InvalidField)?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(value)
    }
    /// A fixed-size field; `take` has already proved the length.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DecodeError::InvalidField)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn str(&mut self, len: usize) -> Result<&'a str, DecodeError> {
        std::str::from_utf8(self.take(len)?).map_err(|_| DecodeError::BadUtf8)
    }
    /// Whether the body ends here: a field beginning past the end of the body was appended
    /// by a version this decoder does not have, and takes its documented default. A field
    /// that begins inside the body and runs off the end is a truncated frame and still fails.
    fn exhausted(&self) -> bool {
        self.pos >= self.bytes.len()
    }
}

/// Start a frame with room for the length its contents will need; the prefix is written
/// last, by [`finish`], so nothing copies the payload.
fn open_frame(capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity + LENGTH_PREFIX);
    out.extend_from_slice(&[0; LENGTH_PREFIX]);
    out
}

/// Write a frame's length over the prefix [`open_frame`] reserved.
///
/// Public because the datagram cut frames its own pieces: the length prefix
/// comes off the wire there and goes back on around the packed body, and a
/// daemon that wrote that prefix itself could disagree with this crate about
/// what a frame is.
pub fn seal_frame(frame: &mut [u8]) -> Result<(), EncodeError> {
    let length = u32::try_from(frame.len() - LENGTH_PREFIX).map_err(|_| EncodeError::Oversize)?;
    if length == 0 || length > MAX_FRAME {
        return Err(EncodeError::Oversize);
    }
    frame[..LENGTH_PREFIX].copy_from_slice(&length.to_be_bytes());
    Ok(())
}

fn finish(mut frame: Vec<u8>) -> Result<Vec<u8>, EncodeError> {
    seal_frame(&mut frame)?;
    Ok(frame)
}

/// A `TERM` reaches a child process's environment, so it is admitted as a terminfo name and nothing else.
fn valid_term(term: &str) -> bool {
    !term.is_empty()
        && term.len() <= MAX_TERM
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'+' | b'.' | b'_'))
}

/// Likewise a variable name: a shell that inherits `PATH=x; rm -rf` inherits it.
fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn encode_env(out: &mut Vec<u8>, env: &SessionEnv) -> Result<(), EncodeError> {
    if env.0.len() > MAX_ENV_VARS {
        return Err(EncodeError::BadEnv);
    }
    let total: usize = env
        .0
        .iter()
        .map(|(name, value)| name.len() + value.len() + 3)
        .sum();
    if total > MAX_ENV {
        return Err(EncodeError::BadEnv);
    }
    let count = u8::try_from(env.0.len()).map_err(|_| EncodeError::BadEnv)?;
    out.push(count);
    for (name, value) in &env.0 {
        if !valid_env_name(name) || value.chars().any(char::is_control) {
            return Err(EncodeError::BadEnv);
        }
        let name_len = u8::try_from(name.len()).map_err(|_| EncodeError::Oversize)?;
        out.push(name_len);
        out.extend_from_slice(name.as_bytes());
        let value_len = u16::try_from(value.len()).map_err(|_| EncodeError::Oversize)?;
        put_u16(out, value_len);
        out.extend_from_slice(value.as_bytes());
    }
    Ok(())
}

fn decode_env(c: &mut Cursor<'_>) -> Result<SessionEnv, DecodeError> {
    let count = usize::from(c.u8()?);
    if count > MAX_ENV_VARS {
        return Err(DecodeError::InvalidField);
    }
    // Bounded by the count *and* by what the rest of the payload could hold.
    let mut env = Vec::with_capacity(count.min(c.remaining() / 3));
    let mut total = 0_usize;
    for _ in 0..count {
        let name_len = usize::from(c.u8()?);
        let name = c.str(name_len)?.to_owned();
        let value_len = usize::from(c.u16()?);
        let value = c.str(value_len)?.to_owned();
        total += name_len + value_len + 3;
        if total > MAX_ENV || !valid_env_name(&name) {
            return Err(DecodeError::InvalidField);
        }
        reject_control(&value)?;
        env.push((name, value));
    }
    Ok(SessionEnv(env))
}

/// argv, not a string: the daemon executes it directly, so there is no shell to quote for
/// and nothing to re-parse on the far end.
fn encode_command(out: &mut Vec<u8>, command: &[String]) -> Result<(), EncodeError> {
    if command.len() > MAX_COMMAND_WORDS {
        return Err(EncodeError::BadCommand);
    }
    let total: usize = command.iter().map(|word| word.len() + 2).sum();
    if total > MAX_COMMAND {
        return Err(EncodeError::BadCommand);
    }
    if command.iter().any(String::is_empty) {
        return Err(EncodeError::BadCommand);
    }
    let count = u8::try_from(command.len()).map_err(|_| EncodeError::BadCommand)?;
    out.push(count);
    for word in command {
        let len = u16::try_from(word.len()).map_err(|_| EncodeError::BadCommand)?;
        put_u16(out, len);
        out.extend_from_slice(word.as_bytes());
    }
    Ok(())
}

fn decode_command(c: &mut Cursor<'_>) -> Result<Vec<String>, DecodeError> {
    let count = usize::from(c.u8()?);
    if count > MAX_COMMAND_WORDS {
        return Err(DecodeError::InvalidField);
    }
    let mut command = Vec::with_capacity(count.min(c.remaining() / 2));
    let mut total = 0_usize;
    for _ in 0..count {
        let len = usize::from(c.u16()?);
        let word = c.str(len)?;
        total += len + 2;
        if total > MAX_COMMAND || word.is_empty() {
            return Err(DecodeError::InvalidField);
        }
        command.push(word.to_owned());
    }
    Ok(command)
}

/// One field of one message: its wire form, its bounds, and the borrowed shape an encoder
/// takes it in. A codec per field rather than per Rust type, because `String` is a `TERM`,
/// a search pattern and a session command, each bounded differently.
trait Field {
    type Value;
    /// The borrowed shape the encoder takes: `&[u8]` where the value is a `Vec<u8>`.
    type Ref<'a>: Copy
    where
        Self: 'a;
    fn borrow(value: &Self::Value) -> Self::Ref<'_>;
    /// Bytes this value costs, so a frame is allocated exactly once.
    fn hint(value: Self::Ref<'_>) -> usize;
    fn put(out: &mut Vec<u8>, value: Self::Ref<'_>) -> Result<(), EncodeError>;
    fn get(c: &mut Cursor<'_>) -> Result<Self::Value, DecodeError>;
}

/// A field whose value is `Copy` and costs the same on every wire.
macro_rules! copy_field {
    (
        $(#[$meta:meta])*
        $codec:ident : $value:ty, size = $size:expr,
        put(|$o:ident, $v:ident| $put:expr),
        get(|$c:ident| $get:expr)
    ) => {
        $(#[$meta])*
        pub(crate) enum $codec {}
        impl Field for $codec {
            type Value = $value;
            type Ref<'a> = $value;
            fn borrow(value: &Self::Value) -> Self::Ref<'_> {
                *value
            }
            fn hint(_value: Self::Ref<'_>) -> usize {
                $size
            }
            fn put($o: &mut Vec<u8>, $v: Self::Ref<'_>) -> Result<(), EncodeError> {
                $put
            }
            fn get($c: &mut Cursor<'_>) -> Result<Self::Value, DecodeError> {
                $get
            }
        }
    };
}

copy_field! {
    U16: u16, size = 2,
    put(|out, value| { put_u16(out, value); Ok(()) }),
    get(|c| c.u16())
}

copy_field! {
    U32: u32, size = 4,
    put(|out, value| { put_u32(out, value); Ok(()) }),
    get(|c| c.u32())
}

copy_field! {
    U64: u64, size = 8,
    put(|out, value| { put_u64(out, value); Ok(()) }),
    get(|c| c.u64())
}

copy_field! {
    I32: i32, size = 4,
    put(|out, value| { out.extend_from_slice(&value.to_be_bytes()); Ok(()) }),
    get(|c| Ok(i32::from_be_bytes(c.array()?)))
}

copy_field! {
    Grid: GridSize, size = 4,
    put(|out, size| { put_u16(out, size.cols); put_u16(out, size.rows); Ok(()) }),
    get(|c| GridSize::new(c.u16()?, c.u16()?).ok_or(DecodeError::InvalidField))
}

copy_field! {
    Seq: CmdSeq, size = 8,
    put(|out, seq| { put_u64(out, seq.get()); Ok(()) }),
    get(|c| CmdSeq::decode(c.u64()?))
}

copy_field! {
    /// An acknowledgement position, or the absence of one: zero is parsed here into `None`
    /// and never travels past this line as a `CmdSeq` that happens to be zero.
    OptSeq: Option<CmdSeq>, size = 8,
    put(|out, seq| { put_u64(out, seq.map_or(0, CmdSeq::get)); Ok(()) }),
    get(|c| Ok(CmdSeq::from_u64(c.u64()?)))
}

copy_field! {
    Off: ByteOff, size = 8,
    put(|out, off| { put_u64(out, off.get()); Ok(()) }),
    get(|c| Ok(ByteOff(c.u64()?)))
}

copy_field! {
    Gen: Generation, size = 8,
    put(|out, generation| { put_u64(out, generation.get()); Ok(()) }),
    get(|c| Generation::decode(c.u64()?))
}

copy_field! {
    ScreenVer: ScreenVersion, size = 8,
    put(|out, version| { put_u64(out, version.get()); Ok(()) }),
    get(|c| ScreenVersion::decode(c.u64()?))
}

copy_field! {
    StreamNum: StreamId, size = 4,
    put(|out, stream| { put_u32(out, stream.get()); Ok(()) }),
    get(|c| StreamId::decode(c.u32()?))
}

copy_field! {
    Client: ClientId, size = 16,
    put(|out, client| { out.extend_from_slice(&client.as_bytes()); Ok(()) }),
    get(|c| Ok(ClientId(c.array()?)))
}

copy_field! {
    Session: SessionId, size = 16,
    put(|out, id| { out.extend_from_slice(&id.as_bytes()); Ok(()) }),
    get(|c| Ok(SessionId(c.array()?)))
}

copy_field! {
    Cap: Capability, size = CAPABILITY_BYTES,
    put(|out, capability| { out.extend_from_slice(capability.as_bytes()); Ok(()) }),
    get(|c| Ok(Capability(c.array()?)))
}

copy_field! {
    Offer: Option<DatagramOffer>, size = 1 + OFFER_BYTES,
    put(|out, offer| { encode_offer(out, offer); Ok(()) }),
    get(|c| decode_offer(c))
}

copy_field! {
    Cue: InputCue, size = 3,
    put(|out, cue| { encode_cue(out, cue); Ok(()) }),
    get(|c| decode_cue(c))
}

copy_field! {
    Detach: DetachReason, size = 1,
    put(|out, reason| { out.push(reason.to_wire()); Ok(()) }),
    get(|c| DetachReason::from_wire(c.u8()?).ok_or(DecodeError::InvalidField))
}

copy_field! {
    Reset: ForwardResetReason, size = 1,
    put(|out, reason| { out.push(reason.to_wire()); Ok(()) }),
    get(|c| ForwardResetReason::from_wire(c.u8()?).ok_or(DecodeError::InvalidField))
}

copy_field! {
    /// The one flag a forward payload carries; every other bit is reserved and refused.
    Fin: bool, size = 1,
    put(|out, fin| { out.push(if fin { FORWARD_FIN } else { 0 }); Ok(()) }),
    get(|c| {
        let flags = c.u8()?;
        if flags & !FORWARD_FIN != 0 {
            return Err(DecodeError::InvalidField);
        }
        Ok(flags & FORWARD_FIN != 0)
    })
}

copy_field! {
    Request: ResumeRequest, size = 80,
    put(|out, request| {
        out.extend_from_slice(&request.session_id.as_bytes());
        out.extend_from_slice(request.capability.as_bytes());
        put_u64(out, request.confirmed_output.generation.get());
        put_u64(out, request.confirmed_output.next_off.get());
        out.extend_from_slice(&request.client.as_bytes());
        Ok(())
    }),
    get(|c| {
        let session_id = SessionId(c.array()?);
        let capability = Capability(c.array()?);
        let confirmed_output = ConfirmedOutput {
            generation: Generation::decode(c.u64()?)?,
            next_off: ByteOff(c.u64()?),
        };
        Ok(ResumeRequest {
            session_id,
            capability,
            confirmed_output,
            client: ClientId(c.array()?),
        })
    })
}

copy_field! {
    Range: VersionRange, size = 4,
    put(|out, range| { put_u16(out, range.oldest()); put_u16(out, range.newest()); Ok(()) }),
    get(|c| VersionRange::new(c.u16()?, c.u16()?).ok_or(DecodeError::InvalidField))
}

copy_field! {
    /// The version the server picked, proved against what this build can read: a server
    /// answering outside the range the client stated has guessed, not negotiated.
    Ver: Version, size = 2,
    put(|out, version| { put_u16(out, version.get()); Ok(()) }),
    get(|c| {
        let stated = c.u16()?;
        if stated < VersionRange::LOCAL.oldest() || stated > VersionRange::LOCAL.newest() {
            return Err(DecodeError::Version(stated));
        }
        Ok(Version(stated))
    })
}

copy_field! {
    /// A refusal, and for a version mismatch both ends' ranges: a user cannot otherwise tell
    /// which side to upgrade.
    Refusal: RejectReason, size = 9,
    put(|out, reason| {
        out.push(reason.to_wire());
        if let RejectReason::Version { server, client } = reason {
            put_u16(out, server.oldest());
            put_u16(out, server.newest());
            put_u16(out, client.oldest());
            put_u16(out, client.newest());
        }
        Ok(())
    }),
    get(|c| Ok(match c.u8()? {
        0 => RejectReason::Version {
            server: VersionRange::new(c.u16()?, c.u16()?).ok_or(DecodeError::InvalidField)?,
            client: VersionRange::new(c.u16()?, c.u16()?).ok_or(DecodeError::InvalidField)?,
        },
        1 => RejectReason::UnknownSession,
        2 => RejectReason::SequenceGap,
        3 => RejectReason::InputBacklog,
        4 => RejectReason::Internal,
        5 => RejectReason::TooManySessions,
        6 => RejectReason::TooManyAttachments,
        _ => return Err(DecodeError::InvalidField),
    }))
}

/// A field the encoder borrows rather than copies, so `borrow` is the identity. The rest is
/// the shape [`copy_field`] generates, with a measured hint in place of a constant size.
macro_rules! ref_field {
    (
        $(#[$meta:meta])*
        $codec:ident $(<const $max:ident: usize>)? : $value:ty as $pointee:ty,
        hint(|$h:ident| $hint:expr),
        put(|$o:ident, $v:ident| $put:expr),
        get(|$c:ident| $get:expr)
    ) => {
        $(#[$meta])*
        pub(crate) enum $codec $(<const $max: usize>)? {}
        impl $(<const $max: usize>)? Field for $codec $(<$max>)? {
            type Value = $value;
            type Ref<'a> = &'a $pointee;
            fn borrow(value: &Self::Value) -> Self::Ref<'_> {
                value
            }
            fn hint($h: Self::Ref<'_>) -> usize {
                $hint
            }
            fn put($o: &mut Vec<u8>, $v: Self::Ref<'_>) -> Result<(), EncodeError> {
                $put
            }
            fn get($c: &mut Cursor<'_>) -> Result<Self::Value, DecodeError> {
                $get
            }
        }
    };
}

ref_field! {
    /// A length-prefixed run of bytes, bounded by the constant its message is bounded by.
    /// The bound is a const parameter rather than a call-site check: a client `Input` and a
    /// server `Output` are different limits that happen to hold the same number.
    Chunk<const MAX: usize>: Vec<u8> as [u8],
    hint(|value| 4 + value.len()),
    put(|out, value| {
        if value.len() > MAX {
            return Err(EncodeError::Oversize);
        }
        let len = u32::try_from(value.len()).map_err(|_| EncodeError::Oversize)?;
        put_u32(out, len);
        out.extend_from_slice(value);
        Ok(())
    }),
    get(|c| {
        let len = c.u32()?;
        let limit = u32::try_from(MAX).unwrap_or(u32::MAX);
        if len > limit {
            return Err(DecodeError::Oversize { actual: len, limit });
        }
        let len = usize::try_from(len).map_err(|_| DecodeError::InvalidField)?;
        Ok(c.take(len)?.to_vec())
    })
}

ref_field! {
    Term: String as str,
    hint(|value| 2 + value.len()),
    put(|out, value| {
        if !valid_term(value) {
            return Err(EncodeError::BadTerm);
        }
        let len = u16::try_from(value.len()).map_err(|_| EncodeError::BadTerm)?;
        put_u16(out, len);
        out.extend_from_slice(value.as_bytes());
        Ok(())
    }),
    get(|c| {
        let len = usize::from(c.u16()?);
        if len > MAX_TERM {
            return Err(DecodeError::InvalidField);
        }
        let term = c.str(len)?;
        if !valid_term(term) {
            return Err(DecodeError::InvalidField);
        }
        Ok(term.to_owned())
    })
}

ref_field! {
    /// A scrollback search pattern: matched against history and echoed back in the failure
    /// message, so it is control-checked like every other string this protocol carries.
    Pattern: String as str,
    hint(|value| 2 + value.len()),
    put(|out, value| {
        if value.is_empty() || value.len() > MAX_PATTERN || value.chars().any(char::is_control) {
            return Err(EncodeError::BadPattern);
        }
        let len = u16::try_from(value.len()).map_err(|_| EncodeError::BadPattern)?;
        put_u16(out, len);
        out.extend_from_slice(value.as_bytes());
        Ok(())
    }),
    get(|c| {
        let len = usize::from(c.u16()?);
        if len > MAX_PATTERN {
            return Err(DecodeError::InvalidField);
        }
        let pattern = c.str(len)?;
        reject_control(pattern)?;
        if pattern.is_empty() {
            return Err(DecodeError::InvalidField);
        }
        Ok(pattern.to_owned())
    })
}

ref_field! {
    Env: SessionEnv as SessionEnv,
    hint(|env| 1 + env.0.iter().map(|(name, value)| 3 + name.len() + value.len()).sum::<usize>()),
    put(|out, value| encode_env(out, value)),
    get(|c| decode_env(c))
}

ref_field! {
    Command: Vec<String> as [String],
    hint(|value| 1 + value.iter().map(|word| 2 + word.len()).sum::<usize>()),
    put(|out, value| encode_command(out, value)),
    get(|c| decode_command(c))
}

ref_field! {
    Target: ForwardTarget as ForwardTarget,
    hint(|value| 3 + value.host.len()),
    put(|out, value| encode_forward_target(out, value)),
    get(|c| decode_forward_target(c))
}

ref_field! {
    Sessions: Vec<SessionSummary> as [SessionSummary],
    hint(|value| 2 + value.iter().map(|session| 31 + session.command.len()).sum::<usize>()),
    put(|out, value| {
        if value.len() > MAX_SESSIONS {
            return Err(EncodeError::Oversize);
        }
        let count = u16::try_from(value.len()).map_err(|_| EncodeError::Oversize)?;
        put_u16(out, count);
        for session in value {
            let command = session.command.as_bytes();
            if command.len() > MAX_COMMAND || has_control(&session.command) {
                return Err(EncodeError::BadSessionName);
            }
            out.extend_from_slice(&session.session_id.as_bytes());
            put_u16(out, session.size.cols);
            put_u16(out, session.size.rows);
            put_u16(out, session.attachments);
            put_u64(out, session.active_unix);
            let len = u8::try_from(command.len()).map_err(|_| EncodeError::BadSessionName)?;
            out.push(len);
            out.extend_from_slice(command);
        }
        Ok(())
    }),
    get(|c| {
        let count = usize::from(c.u16()?);
        if count > MAX_SESSIONS {
            return Err(DecodeError::InvalidField);
        }
        let mut sessions = Vec::with_capacity(count.min(c.remaining() / 31));
        for _ in 0..count {
            let session_id = SessionId(c.array()?);
            let size = GridSize::new(c.u16()?, c.u16()?).ok_or(DecodeError::InvalidField)?;
            let attachments = c.u16()?;
            let active_unix = c.u64()?;
            let len = usize::from(c.u8()?);
            if len > MAX_COMMAND {
                return Err(DecodeError::InvalidField);
            }
            let command = c.str(len)?.to_owned();
            reject_control(&command)?;
            sessions.push(SessionSummary {
                session_id,
                size,
                attachments,
                active_unix,
                command,
            });
        }
        Ok(sessions)
    })
}

ref_field! {
    Matches: Vec<SearchMatch> as [SearchMatch],
    hint(|value| 2 + value.iter().map(|found| 24 + found.line.len()).sum::<usize>()),
    put(|out, value| {
        if value.len() > MAX_MATCHES {
            return Err(EncodeError::Oversize);
        }
        let count = u16::try_from(value.len()).map_err(|_| EncodeError::Oversize)?;
        put_u16(out, count);
        for found in value {
            let line = found.line.as_bytes();
            if line.len() > MAX_MATCH_LINE || has_control(&found.line) {
                return Err(EncodeError::BadMatch);
            }
            out.extend_from_slice(&found.session_id.as_bytes());
            put_u32(out, found.distance);
            let len = u16::try_from(line.len()).map_err(|_| EncodeError::BadMatch)?;
            put_u16(out, len);
            out.extend_from_slice(line);
        }
        Ok(())
    }),
    get(|c| {
        let count = usize::from(c.u16()?);
        if count > MAX_MATCHES {
            return Err(DecodeError::InvalidField);
        }
        let mut matches = Vec::with_capacity(count.min(c.remaining() / 22));
        for _ in 0..count {
            let session_id = SessionId(c.array()?);
            let distance = c.u32()?;
            let len = usize::from(c.u16()?);
            if len > MAX_MATCH_LINE {
                return Err(DecodeError::InvalidField);
            }
            // Printed straight to a terminal, like every other string here.
            let line = c.str(len)?.to_owned();
            reject_control(&line)?;
            matches.push(SearchMatch {
                session_id,
                distance,
                line,
            });
        }
        Ok(matches)
    })
}

ref_field! {
    /// One piece of a screen. [`encode_screen_parts`] writes this same layout while cutting a
    /// screen to a budget, because a fragmenter producing an owned [`ScreenPart`] per piece
    /// would copy every row it borrows.
    Piece: ScreenPart as ScreenPart,
    hint(|value| {
        let rows = match value {
            ScreenPart::Head { rows, .. } | ScreenPart::Tail { rows, .. } => rows,
        };
        let fixed = match value {
            ScreenPart::Head { header, .. } => screen_prefix(header) + PART_BASE + PART_SCROLL,
            ScreenPart::Tail { .. } => PART_GENERATION + PART_VERSION + PART_INDEX,
        };
        PART_KIND
            + fixed
            + PART_PIECES
            + PART_ROW_COUNT
            + rows.iter().map(RowSpan::encoded_len).sum::<usize>()
    }),
    put(|out, value| put_screen_part(out, value)),
    get(|c| decode_screen_part(c))
}

ref_field! {
    Sack: SackRuns as SackRuns,
    hint(|value| 1 + 8 * value.as_slice().len()),
    put(|out, value| {
        let runs = value.as_slice();
        let count = u8::try_from(runs.len()).map_err(|_| EncodeError::Oversize)?;
        if runs.len() > MAX_ACK_RUNS {
            return Err(EncodeError::Oversize);
        }
        out.push(count);
        for run in runs {
            put_u32(out, run.gap.get());
            put_u32(out, run.len.get());
        }
        Ok(())
    }),
    get(|c| {
        let count = usize::from(c.u8()?);
        if count > MAX_ACK_RUNS {
            return Err(DecodeError::InvalidField);
        }
        let mut runs = Vec::with_capacity(count);
        for _ in 0..count {
            // A zero gap puts a run against the cumulative offset — the receiver both has and has
            // not those bytes — and a zero length is a run that names nothing.
            let gap = NonZeroU32::new(c.u32()?).ok_or(DecodeError::InvalidField)?;
            let len = NonZeroU32::new(c.u32()?).ok_or(DecodeError::InvalidField)?;
            runs.push(SackRun { gap, len });
        }
        SackRuns::new(runs).ok_or(DecodeError::InvalidField)
    })
}

/// Encode one field, skipping one the negotiated version has not reached.
macro_rules! put_field {
    ($spoken:ident, $out:expr, $codec:ty, $value:expr) => {
        <$codec as Field>::put($out, $value)
    };
    ($spoken:ident, $out:expr, $codec:ty, $value:expr, since $since:literal, default $default:expr) => {
        if $spoken.get() >= $since {
            <$codec as Field>::put($out, $value)
        } else {
            Ok(())
        }
    };
}

/// Decode one field, or take its documented default when the body ended before it.
macro_rules! get_field {
    ($spoken:ident, $c:ident, $codec:ty) => {
        <$codec as Field>::get(&mut $c)?
    };
    ($spoken:ident, $c:ident, $codec:ty, since $since:literal, default $default:expr) => {
        // A body that ends exactly where an appended field would begin is an older peer's, not
        // a corrupt frame. One that ends *inside* a field still fails.
        if $spoken.get() < $since || $c.exhausted() {
            $default
        } else {
            <$codec as Field>::get(&mut $c)?
        }
    };
}

/// The borrowed encoder a hot shape names, when it names one. The rule takes plain fields
/// only: a version-gated field would need the negotiated version to decide what to write.
macro_rules! borrowed_encoder {
    (
        $tags:ident, $base:expr, $variant:ident,
        [ $( $field:ident : $codec:ty $( = since $since:literal, default $default:expr )? ),* ]
    ) => {};
    (
        $tags:ident, $base:expr, $variant:ident,
        [ $( $field:ident : $codec:ty ),* ], $name:ident
    ) => {
        /// Encode this message straight from borrowed data, into a caller-owned buffer.
        ///
        /// Taking the destination and the payload by reference keeps an allocation and a
        /// whole-payload copy off every frame. Generated from the same field list as the decoder.
        pub(crate) fn $name(
            out: &mut Vec<u8>,
            $( $field: <$codec as Field>::Ref<'_>, )*
        ) -> Result<(), EncodeError> {
            out.clear();
            out.reserve(LENGTH_PREFIX + 1 $( + <$codec as Field>::hint($field) )*);
            out.extend_from_slice(&[0; LENGTH_PREFIX]);
            out.push($tags::$variant as u8 + $base);
            $( <$codec as Field>::put(out, $field)?; )*
            seal_frame(out)
        }
    };
}

/// One declarative definition per message: wire order, tag, and the codec each field is
/// parsed under. The encoder, the decoder and the allocation hint are all generated from
/// this list, and tags come from an enum's own discriminants counted from `base`.
///
/// A trailing field written `= since N, default D` is one appended in version `N`: an
/// encoder below `N` omits it and a decoder that reaches the end of the body takes `D`.
/// Fields may be appended, never reordered or resized; bytes past the last field a decoder
/// knows are skipped, because they belong to a version it does not have.
macro_rules! messages {
    (
        $enum:ident, tags = $tags:ident, base = $base:expr;
        $(
            $variant:ident $( as $borrowed:ident )? {
                $( $field:ident : $codec:ty $( = since $since:literal, default $default:expr )? ),* $(,)?
            }
        )*
    ) => {
        #[repr(u8)]
        enum $tags {
            $( $variant, )*
        }

        $(
            borrowed_encoder!(
                $tags, $base, $variant,
                [ $( $field : $codec $( = since $since, default $default )? ),* ]
                $(, $borrowed)?
            );
        )*

        impl $enum {
            fn hint(&self) -> usize {
                match self {
                    $(
                        Self::$variant { $( $field, )* } =>
                            1 $( + <$codec as Field>::hint(<$codec as Field>::borrow($field)) )*,
                    )*
                }
            }

            pub fn encode(&self, spoken: Version) -> Result<Vec<u8>, EncodeError> {
                let mut out = open_frame(self.hint());
                match self {
                    $(
                        Self::$variant { $( $field, )* } => {
                            out.push($tags::$variant as u8 + $base);
                            $(
                                put_field!(
                                    spoken, &mut out, $codec,
                                    <$codec as Field>::borrow($field)
                                    $(, since $since, default $default)?
                                )?;
                            )*
                        }
                    )*
                }
                finish(out)
            }

            pub fn decode(payload: &[u8], spoken: Version) -> Result<Self, DecodeError> {
                let mut c = Cursor::new(payload);
                let tag = c.u8()?;
                $(
                    if tag == $tags::$variant as u8 + $base {
                        $(
                            let $field = get_field!(
                                spoken, c, $codec
                                $(, since $since, default $default)?
                            );
                        )*
                        return Ok(Self::$variant { $( $field, )* });
                    }
                )*
                Err(DecodeError::BadTag(tag))
            }
        }
    };
}

/// Encode one output chunk straight from the buffer that holds it, into a caller-owned
/// buffer. A named signature over the generated borrowed encoder, checked against it.
pub fn encode_output_into(
    out: &mut Vec<u8>,
    off: ByteOff,
    cue: InputCue,
    echo_ack: Option<CmdSeq>,
    bytes: &[u8],
) -> Result<(), EncodeError> {
    put_output(out, off, cue, echo_ack, bytes)
}

messages! {
    ClientMessage, tags = ClientTag, base = CLIENT_TAG_BASE;

    Hello {
        versions: Range,
        size: Grid,
        term: Term,
        env: Env,
        command: Command,
        client: Client,
    }
    HelloForward {
        versions: Range,
        client: Client,
    }
    Resume {
        versions: Range,
        seq: Seq,
        request: Request,
    }
    Input {
        seq: Seq,
        bytes: Chunk<MAX_INPUT_CHUNK>,
    }
    Resize {
        seq: Seq,
        size: Grid,
    }
    RequestRepaint {
        seq: Seq,
    }
    ScreenAck {
        generation: Gen,
        version: ScreenVer,
    }
    Close {
        seq: Seq,
    }
    Detach {
        seq: Seq,
    }
    Pong {
        token: U64,
        consumed: Off,
    }
    Consumed {
        off: Off,
    }
    ListSessions {}
    KillSession {
        session_id: Session,
    }
    Search {
        pattern: Pattern,
        limit: U16,
    }
    ForwardOpen {
        seq: Seq,
        stream: StreamNum,
        target: Target,
    }
    ForwardData {
        stream: StreamNum,
        off: Off,
        fin: Fin,
        bytes: Chunk<MAX_FORWARD_CHUNK>,
    }
    ForwardAck {
        stream: StreamNum,
        off: Off,
        window: U32,
        held: Sack = since 14, default SackRuns::EMPTY,
    }
    ForwardReset {
        stream: StreamNum,
        reason: Reset,
    }
}

messages! {
    ServerMessage, tags = ServerTag, base = SERVER_TAG_BASE;

    Hello {
        version: Ver,
        size: Grid,
        session_id: Session,
        capability: Cap,
        offer: Offer,
    }
    HelloForward {
        version: Ver,
        session_id: Session,
        capability: Cap,
        offer: Offer,
    }
    Output as put_output {
        off: Off,
        cue: Cue,
        echo_ack: OptSeq,
        bytes: Chunk<MAX_OUTPUT_CHUNK>,
    }
    Exit {
        code: I32,
    }
    Reject {
        reason: Refusal,
    }
    CommandAck {
        highest: OptSeq,
    }
    Detached {
        reason: Detach,
    }
    Ping {
        token: U64,
        echo_ack: OptSeq,
        interval_ms: U16,
    }
    SessionList {
        sessions: Sessions,
    }
    SearchResults {
        matches: Matches,
    }
    Screen {
        part: Piece,
    }
    ForwardData {
        stream: StreamNum,
        off: Off,
        fin: Fin,
        bytes: Chunk<MAX_FORWARD_CHUNK>,
    }
    ForwardAck {
        stream: StreamNum,
        off: Off,
        window: U32,
        held: Sack = since 14, default SackRuns::EMPTY,
    }
    ForwardReset {
        stream: StreamNum,
        reason: Reset,
    }
    // Appended last, so every tag before it keeps the number it had.
    OutputSkipped {
        bytes: U64,
    }
}

pub fn write_message<W: Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes)?;
    writer.flush()
}

/// Read one frame into a caller-owned buffer, refusing one larger than `limit`.
///
/// `limit` is the caller's, not the protocol's: only a server sends a screen, so a daemon
/// sizing this by [`MAX_FRAME`] lets four attacker-chosen bytes buy a megabyte of zeroing
/// once per keystroke. A daemon passes [`MAX_CLIENT_FRAME`], a client passes [`MAX_FRAME`].
pub fn read_frame_into<R: Read>(
    reader: &mut R,
    into: &mut Vec<u8>,
    limit: u32,
) -> Result<(), DecodeError> {
    let mut header = [0; 4];
    read_exact(reader, &mut header)?;
    let length = u32::from_be_bytes(header);
    if length == 0 || length > limit {
        return Err(DecodeError::Oversize {
            actual: length,
            limit,
        });
    }
    // Length is proved against the bound before a byte of it is committed.
    let length = usize::try_from(length).map_err(|_| DecodeError::InvalidField)?;
    // `resize` alone, with no `clear` before it: `clear` sets the length to zero, which makes
    // `resize` zero every byte `read_exact` is about to overwrite in full. At `MAX_FRAME` the
    // difference is a 1 MiB memset per screen.
    into.resize(length, 0);
    read_exact(reader, into)
}

pub fn read_frame<R: Read>(reader: &mut R, limit: u32) -> Result<Vec<u8>, DecodeError> {
    let mut payload = Vec::new();
    read_frame_into(reader, &mut payload, limit)?;
    Ok(payload)
}

fn read_exact<R: Read>(reader: &mut R, into: &mut [u8]) -> Result<(), DecodeError> {
    reader.read_exact(into).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            DecodeError::Truncated
        } else {
            DecodeError::Io(error)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the grid sits in an encoded screen piece: the length prefix, the tag, the piece
    /// kind and three 64-bit fields precede it.
    const GRID_AT: usize = LENGTH_PREFIX + 2 + 24;

    fn patch_u16(frame: &mut [u8], at: usize, value: u16) {
        frame[at..at + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn small_grid() -> GridSize {
        GridSize::new(80, 24).expect("a small grid")
    }

    fn client_id() -> ClientId {
        ClientId::from_bytes([
            0xa1, 0xb2, 0xc3, 0xd4, 0, 1, 2, 3, 0xff, 0xfe, 0xfd, 0xfc, 9, 8, 7, 6,
        ])
    }

    fn screen_header(size: GridSize, cursor: Option<(u16, u16)>) -> ScreenHeader {
        ScreenHeader {
            generation: Generation::initial(),
            version: ScreenVersion::initial(),
            next_off: ByteOff::zero(),
            size,
            cursor,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            cursor_blinking: false,
            modes: ModeSet::empty(),
            sticky: StickyState::default(),
        }
    }

    fn styled(text: &str, style: CellStyle, cells: u16) -> RowFrame {
        RowFrame {
            text: text.into(),
            runs: vec![StyleRun {
                cells,
                bytes: u32::try_from(text.len()).expect("a short row"),
                style,
            }],
            cells,
        }
    }

    fn plain(text: &str) -> RowFrame {
        RowFrame {
            text: text.into(),
            runs: Vec::new(),
            cells: u16::try_from(text.chars().count()).expect("a short row"),
        }
    }

    fn indexed(rows: &[RowFrame]) -> impl Iterator<Item = RowUpdate<'_>> + Clone + '_ {
        rows.iter()
            .enumerate()
            .map(|(row, frame)| RowUpdate::whole(u16::try_from(row).expect("a row index"), frame))
    }

    fn spans(rows: &[RowFrame]) -> Vec<RowSpan> {
        rows.iter()
            .enumerate()
            .map(|(row, frame)| RowSpan {
                row: u16::try_from(row).expect("a row index"),
                chunk: false,
                col: 0,
                byte: 0,
                clear_tail: false,
                frame: frame.clone(),
            })
            .collect()
    }

    fn frame_budget() -> usize {
        usize::try_from(MAX_FRAME).expect("a 32-bit limit fits a usize")
    }

    /// A `SessionList` payload built by hand, so commands the encoder refuses reach the decoder.
    fn session_list_payload(command: &[u8]) -> Vec<u8> {
        let mut out = vec![ServerTag::SessionList as u8 + SERVER_TAG_BASE];
        put_u16(&mut out, 1);
        out.extend_from_slice(&[7; 16]);
        put_u16(&mut out, 80);
        put_u16(&mut out, 24);
        put_u16(&mut out, 1);
        put_u64(&mut out, 1_700_000_000);
        out.push(u8::try_from(command.len()).expect("a command a u8 can measure"));
        out.extend_from_slice(command);
        out
    }

    /// A `SearchResults` payload built by hand, so lines the encoder refuses reach the decoder.
    fn search_results_payload(line: &[u8]) -> Vec<u8> {
        let mut out = vec![ServerTag::SearchResults as u8 + SERVER_TAG_BASE];
        put_u16(&mut out, 1);
        out.extend_from_slice(&[7; 16]);
        put_u32(&mut out, 3);
        put_u16(
            &mut out,
            u16::try_from(line.len()).expect("a line a u16 can measure"),
        );
        out.extend_from_slice(line);
        out
    }

    /// A `Hello` payload built by hand, so commands the encoder refuses reach the decoder.
    fn hello_payload(command: &[&str]) -> Vec<u8> {
        let mut out = vec![ClientTag::Hello as u8 + CLIENT_TAG_BASE];
        put_u16(&mut out, MIN_PROTOCOL_VERSION);
        put_u16(&mut out, PROTOCOL_VERSION);
        put_u16(&mut out, 80);
        put_u16(&mut out, 24);
        put_u16(&mut out, 5);
        out.extend_from_slice(b"xterm");
        out.push(0);
        out.push(u8::try_from(command.len()).expect("a word count a u8 can measure"));
        for word in command {
            put_u16(&mut out, u16::try_from(word.len()).expect("a short word"));
            out.extend_from_slice(word.as_bytes());
        }
        out.extend_from_slice(&client_id().as_bytes());
        out
    }

    fn range(oldest: u16, newest: u16) -> VersionRange {
        VersionRange::new(oldest, newest).expect("a range")
    }

    fn resume_request() -> ResumeRequest {
        ResumeRequest {
            session_id: SessionId::from_bytes([7; 16]),
            capability: Capability::from_bytes([1; CAPABILITY_BYTES]),
            confirmed_output: ConfirmedOutput {
                generation: Generation::initial(),
                next_off: ByteOff::from_u64(0xfeed_beef),
            },
            client: client_id(),
        }
    }

    /// The decoder does not trust the encoder to have checked: this is a shape a peer sends,
    /// not one this side can write. The encoder's own refusal is the property suite's.
    #[test]
    fn a_forwarded_variable_a_peer_states_is_refused() {
        let mut payload = vec![1_u8];
        put_u16(&mut payload, PROTOCOL_VERSION);
        put_u16(&mut payload, 80);
        put_u16(&mut payload, 24);
        put_u16(&mut payload, 5);
        payload.extend_from_slice(b"xterm");
        payload.push(1);
        payload.push(5);
        payload.extend_from_slice(b"1PATH");
        put_u16(&mut payload, 4);
        payload.extend_from_slice(b"/bin");
        payload.push(0);
        assert!(matches!(
            ClientMessage::decode(&payload, Version::LOCAL),
            Err(DecodeError::InvalidField)
        ));
    }

    /// argv this side cannot write a peer can still state: an empty word names no program,
    /// and the word count is the decoder's own bound. The encoder's refusals are the
    /// property suite's.
    #[test]
    fn an_explicit_command_a_peer_states_is_bounded_and_never_empty() {
        assert!(matches!(
            ClientMessage::decode(&hello_payload(&[""]), Version::LOCAL),
            Err(DecodeError::InvalidField)
        ));
        assert!(matches!(
            ClientMessage::decode(
                &hello_payload(&["x"; MAX_COMMAND_WORDS + 1]),
                Version::LOCAL
            ),
            Err(DecodeError::InvalidField)
        ));
        assert!(ClientMessage::decode(&hello_payload(&["tmux", "attach"]), Version::LOCAL).is_ok());
    }

    /// The management encoding in bytes. A round trip cannot catch a wire change, since
    /// both halves move together; these literals are pinned to [`MANAGEMENT_VERSION`],
    /// which never moves, so they never move either. They used to be pinned to the
    /// compatibility floor, which does.
    #[test]
    fn the_management_encoding_is_frozen() {
        for (message, frozen) in [
            (ClientMessage::ListSessions, &[0, 0, 0, 1, 12][..]),
            (
                ClientMessage::KillSession {
                    session_id: SessionId::from_bytes([3; 16]),
                },
                &[
                    0, 0, 0, 17, 13, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                ][..],
            ),
        ] {
            assert_eq!(
                message
                    .encode(Version::MANAGEMENT)
                    .expect("a frozen message"),
                frozen
            );
            assert_eq!(
                ClientMessage::decode(&frozen[LENGTH_PREFIX..], Version::MANAGEMENT)
                    .expect("a frozen message"),
                message
            );
        }

        for (message, frozen) in [
            (
                ServerMessage::SessionList {
                    sessions: vec![SessionSummary {
                        session_id: SessionId::from_bytes([7; 16]),
                        size: small_grid(),
                        attachments: 2,
                        active_unix: 1_700_000_000,
                        command: "zsh".to_owned(),
                    }],
                },
                &[
                    0, 0, 0, 37, 0x89, 0, 1, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 80,
                    0, 24, 0, 2, 0, 0, 0, 0, 0x65, 0x53, 0xF1, 0x00, 3, b'z', b's', b'h',
                ][..],
            ),
            (
                ServerMessage::SessionList {
                    sessions: Vec::new(),
                },
                &[0, 0, 0, 3, 0x89, 0, 0][..],
            ),
        ] {
            assert_eq!(
                message
                    .encode(Version::MANAGEMENT)
                    .expect("a frozen message"),
                frozen
            );
            assert_eq!(
                ServerMessage::decode(&frozen[LENGTH_PREFIX..], Version::MANAGEMENT)
                    .expect("a frozen message"),
                message
            );
        }
    }

    #[test]
    fn a_session_command_is_bounded_and_control_checked() {
        for command in [
            "x".repeat(MAX_COMMAND + 1),
            "vim\u{1b}]0;pwned\u{7}".to_owned(),
        ] {
            let message = ServerMessage::SessionList {
                sessions: vec![SessionSummary {
                    session_id: SessionId::from_bytes([1; 16]),
                    size: small_grid(),
                    attachments: 0,
                    active_unix: 0,
                    command: command.clone(),
                }],
            };
            assert_eq!(
                message.encode(Version::LOCAL),
                Err(EncodeError::BadSessionName)
            );
            assert!(matches!(
                ServerMessage::decode(&session_list_payload(command.as_bytes()), Version::LOCAL),
                Err(DecodeError::InvalidField)
            ));
        }
        assert!(
            ServerMessage::decode(&session_list_payload(b"vim -O a b"), Version::LOCAL).is_ok()
        );
    }

    /// `Output` is the shape the PTY's bytes travel on and `Input` a keystroke's; both are
    /// generated from the message table, so this is what says the table costs no extra copy.
    #[test]
    fn the_hot_shapes_allocate_once_and_copy_once() {
        let bytes = vec![b'x'; 4096];
        let mut out = Vec::new();
        encode_output_into(
            &mut out,
            ByteOff::from_u64(9),
            InputCue::Opaque,
            Some(CmdSeq::first()),
            &bytes,
        )
        .expect("an output encodes");
        let first = out.capacity();
        assert_eq!(out.len(), LENGTH_PREFIX + 1 + 8 + 1 + 8 + 4 + bytes.len());
        // The second frame reuses the buffer the first one sized.
        encode_output_into(
            &mut out,
            ByteOff::from_u64(9 + 4096),
            InputCue::Echoing { room: 3 },
            None,
            &bytes,
        )
        .expect("an output encodes");
        assert_eq!(out.capacity(), first, "the hot output path reallocated");

        let input = ClientMessage::Input {
            seq: CmdSeq::first(),
            bytes,
        };
        let frame = input.encode(Version::LOCAL).expect("an input encodes");
        assert_eq!(
            frame.len(),
            frame.capacity(),
            "an input frame was allocated larger than it needed, so the hint is wrong"
        );

        // The third shape is the screen: each piece is written into a buffer the cut sized.
        let header = screen_header(small_grid(), None);
        let rows = [plain("hello")];
        let pieces = encode_screen_parts(&header, None, None, indexed(&rows), frame_budget())
            .expect("a screen cuts");
        assert_eq!(pieces.len(), 1);
        assert!(
            pieces[0].capacity() >= pieces[0].len(),
            "a screen piece outgrew the buffer its cut reserved"
        );
    }

    #[test]
    fn overlapping_ranges_negotiate_and_communicate() {
        let server = range(12, 16);
        let client = range(14, 15);
        let spoken = server.negotiate(client).expect("the ranges overlap");
        assert_eq!(spoken.get(), 15, "the newest both ends speak");

        let message = ClientMessage::Input {
            seq: CmdSeq::first(),
            bytes: b"ls\r".to_vec(),
        };
        let frame = message.encode(spoken).expect("an input encodes");
        assert_eq!(
            ClientMessage::decode(&frame[LENGTH_PREFIX..], spoken).expect("an input"),
            message
        );
    }

    #[test]
    fn ranges_that_do_not_meet_are_refused_by_naming_both() {
        let server = range(20, 24);
        let client = range(14, 16);
        let reason = server.negotiate(client).expect_err("nothing in common");
        assert_eq!(reason, RejectReason::Version { server, client });
        assert_eq!(
            reason.to_string(),
            "this server speaks protocol 20-24, this client speaks 14-16"
        );
        assert!(reason.is_terminal(), "no retry finds a common version");
        // And it survives the wire, because the client is the end that has to print it.
        let frame = ServerMessage::Reject { reason }
            .encode(Version::LOCAL)
            .expect("a refusal encodes");
        assert_eq!(
            ServerMessage::decode(&frame[LENGTH_PREFIX..], Version::LOCAL).expect("a refusal"),
            ServerMessage::Reject { reason }
        );
        // A single number reads as itself; only a real range reads as one.
        assert_eq!(
            VersionRange::new(14, 14).expect("a point").to_string(),
            "14"
        );
        assert_eq!(VersionRange::new(15, 14), None);
    }

    /// `brd ls` against a daemon whose protocol this build cannot agree on is the whole
    /// reason management skips the handshake, and that promise is about a *fixed* layout.
    /// The literal is the test: [`MANAGEMENT_VERSION`] silently tracking the floor —
    /// which is what it did when the two were one constant — is the regression.
    #[test]
    fn management_is_spoken_at_a_frozen_version_the_floor_cannot_drag() {
        assert_eq!(MANAGEMENT_VERSION, 14, "the management dialect moved");
        assert_eq!(Version::MANAGEMENT.get(), MANAGEMENT_VERSION);

        let asked = [
            ClientMessage::ListSessions,
            ClientMessage::KillSession {
                session_id: SessionId::from_bytes([7; 16]),
            },
            ClientMessage::Search {
                pattern: "needle".to_owned(),
                limit: 8,
            },
        ];
        for message in asked {
            let frame = message
                .encode(Version::MANAGEMENT)
                .expect("management encodes");
            assert_eq!(
                ClientMessage::decode(&frame[LENGTH_PREFIX..], Version::MANAGEMENT)
                    .expect("management decodes"),
                message
            );
            // The daemon reads the *first* frame at its own newest, before it knows the
            // connection is management at all: a management message that only decodes at
            // its own version would never be recognised as one.
            assert_eq!(
                ClientMessage::decode(&frame[LENGTH_PREFIX..], Version::LOCAL)
                    .expect("the first frame is read at this build's newest"),
                message
            );
        }

        let answered = ServerMessage::SessionList {
            sessions: Vec::new(),
        };
        let frame = answered
            .encode(Version::MANAGEMENT)
            .expect("a list encodes");
        assert_eq!(
            ServerMessage::decode(&frame[LENGTH_PREFIX..], Version::MANAGEMENT).expect("a list"),
            answered
        );
    }

    /// A message, unlike a field, has no gate in the codec: an unknown tag is a hard
    /// error, so a peer that predates one must never be sent it. The gate is the sender's.
    #[test]
    fn skipped_output_is_refused_to_a_peer_that_predates_it() {
        assert!(Version::LOCAL.carries_output_skipped());
        assert!(
            !Version::MANAGEMENT.carries_output_skipped(),
            "management is frozen below this message and must never be sent one"
        );
        assert!(
            !Version::FLOOR.carries_output_skipped(),
            "the oldest peer this build still speaks to cannot decode this tag"
        );

        let message = ServerMessage::OutputSkipped { bytes: 1 << 20 };
        let frame = message.encode(Version::LOCAL).expect("a notice encodes");
        assert_eq!(
            ServerMessage::decode(&frame[LENGTH_PREFIX..], Version::LOCAL).expect("a notice"),
            message
        );
    }

    /// A body that ends where an appended field would begin is an older encoder's, and the
    /// field takes its documented default; a strict end-of-body check cannot tell the two apart.
    #[test]
    fn a_decoder_takes_the_default_for_a_field_the_body_never_reached() {
        let held = SackRuns::new(vec![SackRun {
            gap: NonZeroU32::new(9).expect("a gap"),
            len: NonZeroU32::new(40).expect("a length"),
        }])
        .expect("one run");
        let message = ClientMessage::ForwardAck {
            stream: StreamId::first(),
            off: ByteOff::from_u64(4096),
            window: 65536,
            held: held.clone(),
        };
        let frame = message.encode(Version::LOCAL).expect("an ack encodes");
        assert_eq!(
            ClientMessage::decode(&frame[LENGTH_PREFIX..], Version::LOCAL).expect("an ack"),
            message
        );

        // What an encoder that predates the appended field writes.
        let older = &frame[LENGTH_PREFIX..LENGTH_PREFIX + 1 + 4 + 8 + 4];
        assert_eq!(
            ClientMessage::decode(older, Version::LOCAL).expect("an older peer's ack"),
            ClientMessage::ForwardAck {
                stream: StreamId::first(),
                off: ByteOff::from_u64(4096),
                window: 65536,
                held: SackRuns::EMPTY,
            }
        );

        // A newer encoder's appended bytes are skipped rather than refused.
        let mut newer = frame[LENGTH_PREFIX..].to_vec();
        newer.extend_from_slice(&[0x5A; 6]);
        assert_eq!(
            ClientMessage::decode(&newer, Version::LOCAL).expect("a newer peer's ack"),
            message
        );

        // A body cut in the middle of the appended field is a corrupt frame, not an old peer.
        let torn = &frame[LENGTH_PREFIX..frame.len() - 3];
        assert!(matches!(
            ClientMessage::decode(torn, Version::LOCAL),
            Err(DecodeError::Truncated)
        ));
    }

    #[test]
    fn a_search_is_readable_at_the_compatibility_floor() {
        let message = ClientMessage::Search {
            pattern: "error".into(),
            limit: 32,
        };
        let frame = message.encode(Version::FLOOR).expect("a search encodes");
        assert_eq!(
            ClientMessage::decode(&frame[LENGTH_PREFIX..], Version::FLOOR).expect("a search"),
            message
        );
    }

    #[test]
    fn an_empty_search_pattern_is_refused_at_both_ends() {
        assert_eq!(
            ClientMessage::Search {
                pattern: String::new(),
                limit: 8,
            }
            .encode(Version::LOCAL),
            Err(EncodeError::BadPattern)
        );
        let mut payload = vec![ClientTag::Search as u8 + CLIENT_TAG_BASE];
        put_u16(&mut payload, 0);
        put_u16(&mut payload, 8);
        assert!(matches!(
            ClientMessage::decode(&payload, Version::LOCAL),
            Err(DecodeError::InvalidField)
        ));
    }

    #[test]
    fn a_search_result_line_is_control_checked_before_it_can_reach_a_terminal() {
        let message = ServerMessage::SearchResults {
            matches: vec![SearchMatch {
                session_id: SessionId::from_bytes([7; 16]),
                distance: 3,
                line: "make\u{1b}]0;pwned\u{7}".into(),
            }],
        };
        assert_eq!(message.encode(Version::LOCAL), Err(EncodeError::BadMatch));
        assert!(matches!(
            ServerMessage::decode(
                &search_results_payload(b"make\x1b]0;pwned\x07"),
                Version::LOCAL
            ),
            Err(DecodeError::InvalidField)
        ));
        assert!(
            ServerMessage::decode(
                &search_results_payload("make -j漢".as_bytes()),
                Version::LOCAL
            )
            .is_ok()
        );
    }

    #[test]
    fn only_a_reject_the_session_cannot_outlive_is_terminal() {
        for reason in [
            RejectReason::Version {
                server: VersionRange::LOCAL,
                client: range(7, 7),
            },
            RejectReason::UnknownSession,
            RejectReason::TooManySessions,
            RejectReason::TooManyAttachments,
        ] {
            assert!(reason.is_terminal(), "{reason} is worth a resume");
        }
        for reason in [
            RejectReason::SequenceGap,
            RejectReason::InputBacklog,
            RejectReason::Internal,
        ] {
            assert!(!reason.is_terminal(), "{reason} ended a live session");
        }
    }

    #[test]
    fn a_capability_is_exactly_capability_bytes() {
        let hello = ServerMessage::Hello {
            version: Version::LOCAL,
            size: small_grid(),
            session_id: SessionId::from_bytes([2; 16]),
            capability: Capability::from_bytes([9; CAPABILITY_BYTES]),
            offer: None,
        };
        let bytes = hello.encode(Version::LOCAL).unwrap();
        assert_eq!(
            ServerMessage::decode(&bytes[4..], Version::LOCAL).unwrap(),
            hello
        );
        // The field is exactly as long as the only value it may hold, so a longer frame is a
        // peer with an appended field this build does not know rather than a longer capability.
        let mut long = bytes.clone();
        long.extend_from_slice(&[9; CAPABILITY_BYTES]);
        assert_eq!(
            ServerMessage::decode(&long[4..], Version::LOCAL).expect("a hello"),
            hello
        );
        assert!(matches!(
            ServerMessage::decode(&bytes[4..bytes.len() - 1], Version::LOCAL),
            Err(DecodeError::Truncated)
        ));
        // A bearer credential must not reach a log line through `Debug`.
        assert_eq!(format!("{hello:?}").matches('9').count(), 0);
    }

    /// The bound is the reader's, not the protocol's: only a server sends a screen, so a
    /// daemon sizing this by `MAX_FRAME` lets four attacker-chosen bytes buy a megabyte of
    /// zeroing in the loop that runs once per keystroke.
    #[test]
    fn a_frame_past_its_reader_s_bound_is_refused_before_allocating() {
        let mut header = &((MAX_FRAME + 1).to_be_bytes())[..];
        assert!(matches!(
            read_frame(&mut header, MAX_FRAME),
            Err(DecodeError::Oversize { .. })
        ));

        let length = MAX_CLIENT_FRAME + 1;
        let mut frame = Vec::from(length.to_be_bytes());
        frame.resize(
            frame.len() + usize::try_from(length).expect("a 32-bit length"),
            0x41,
        );
        assert!(matches!(
            read_frame(&mut &frame[..], MAX_CLIENT_FRAME),
            Err(DecodeError::Oversize { actual, limit })
                if actual == length && limit == MAX_CLIENT_FRAME
        ));
        assert_eq!(
            read_frame(&mut &frame[..], MAX_FRAME).unwrap().len(),
            usize::try_from(length).expect("a 32-bit length")
        );
    }

    #[test]
    fn a_closed_stream_is_transport_loss_but_a_bad_frame_is_not() {
        // A dead transport must be recoverable: a protocol error ends a session the remote
        // daemon is still holding open.
        let mut empty: &[u8] = &[];
        assert!(
            read_frame(&mut empty, MAX_FRAME)
                .unwrap_err()
                .is_transport_loss()
        );
        let mut partial: &[u8] = &[0, 0, 0, 8, 1, 2];
        assert!(
            read_frame(&mut partial, MAX_FRAME)
                .unwrap_err()
                .is_transport_loss()
        );
        assert!(!DecodeError::BadTag(0x99).is_transport_loss());
        assert!(!DecodeError::InvalidField.is_transport_loss());
    }

    #[test]
    fn a_reused_buffer_holds_exactly_the_frame_it_last_read() {
        let mut stream = Vec::new();
        for payload in [&b"a-long-payload"[..], &b"hi"[..]] {
            stream.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
            stream.extend_from_slice(payload);
        }
        let mut reader = &stream[..];
        let mut buffer = Vec::new();
        read_frame_into(&mut reader, &mut buffer, MAX_FRAME).unwrap();
        assert_eq!(buffer, b"a-long-payload");
        read_frame_into(&mut reader, &mut buffer, MAX_FRAME).unwrap();
        assert_eq!(buffer, b"hi");
    }

    #[test]
    fn rejects_an_unknown_cue() {
        let mut bytes = ServerMessage::Output {
            off: ByteOff::from_u64(0),
            bytes: Vec::new(),
            cue: InputCue::Opaque,
            echo_ack: None,
        }
        .encode(Version::LOCAL)
        .unwrap();
        // Past the frame length and the tag and offset: the cue's own tag.
        bytes[4 + 1 + 8] = 9;
        assert!(matches!(
            ServerMessage::decode(&bytes[4..], Version::LOCAL),
            Err(DecodeError::InvalidField)
        ));
    }

    #[test]
    fn a_whole_screen_round_trips_its_resume_offset_and_styling() {
        let mut modes = ModeSet::empty();
        modes.set(13, true);
        modes.set(14, true);
        let style = CellStyle {
            fg: StyleColor::Palette(1),
            bg: StyleColor::Rgb(10, 20, 30),
            underline_color: StyleColor::Default,
            attrs: StyleAttrs::BOLD.with(StyleAttrs::ITALIC, true),
            underline: UnderlineStyle::Curly,
        };
        let header = ScreenHeader {
            next_off: ByteOff::from_u64(9_876_543_210),
            cursor_shape: CursorShape::Bar,
            cursor_blinking: true,
            modes,
            ..screen_header(GridSize { cols: 8, rows: 2 }, Some((1, 1)))
        };
        let rows = [styled("hello", style, 5), plain("world")];
        let encoded = encode_screen_parts(&header, None, None, indexed(&rows), frame_budget())
            .expect("a two-row screen")
            .remove(0);
        assert_eq!(
            ServerMessage::decode(&encoded[4..], Version::LOCAL).unwrap(),
            ServerMessage::Screen {
                part: ScreenPart::Head {
                    header,
                    base: None,
                    scroll: None,
                    pieces: 1,
                    rows: spans(&rows),
                }
            }
        );
    }

    /// The palette index must survive as an index. Resolving it server-side
    /// would repaint the user's terminal in the server's theme on reconnect.
    #[test]
    fn palette_colours_stay_unresolved() {
        let mut out = Vec::new();
        screen::encode_style_color(&mut out, StyleColor::Palette(1));
        assert_eq!(out, vec![1, 1]);
    }

    #[test]
    fn an_unstyled_row_carries_no_runs() {
        let header = screen_header(GridSize { cols: 4, rows: 1 }, None);
        let one = |rows: &[RowFrame]| {
            encode_screen_parts(&header, None, None, indexed(rows), frame_budget())
                .expect("a one-row screen")[0]
                .len()
        };
        let mut rows = [plain("abcd")];
        let bare = one(&rows);
        rows[0].runs.push(StyleRun {
            cells: 4,
            bytes: 4,
            style: CellStyle::default(),
        });
        assert_eq!(one(&rows) - bare, 11);
    }

    /// A row is painted over an erased line, so trailing blanks carrying no style are already
    /// correct on screen; dropping them at encode took a blank screen from half a megabyte to
    /// five kilobytes. A decoded row therefore legitimately has `text.len() < cells`.
    #[test]
    fn a_blank_screen_costs_its_rows_rather_than_its_cells() {
        let size = GridSize::new(GridSize::MAX_COLS, GridSize::MAX_ROWS).expect("the largest grid");
        let header = screen_header(size, Some((0, 0)));
        let blank = RowFrame {
            text: " ".repeat(usize::from(size.cols)),
            runs: Vec::new(),
            cells: size.cols,
        };
        assert_eq!(blank.painted_bytes(), 0);
        let rows = vec![blank.clone(); usize::from(size.rows)];
        let encoded = encode_screen_parts(&header, None, None, indexed(&rows), frame_budget())
            .expect("a blank screen")
            .remove(0);

        // A row costs its named index, the column and byte its span starts at, a length, its
        // painted text, a cell count and a run count; spelled out it carries its 1024 spaces too.
        let row_cost = |text: usize| 2 + 2 + 4 + 4 + text + 2 + 2;
        let elided = row_cost(blank.painted_bytes());
        let spelled_out = row_cost(blank.text.len());
        assert_eq!(elided, 16);
        assert_eq!(spelled_out, 1_040);
        assert_eq!(encoded.len(), 8_257);
        assert_eq!(
            encoded.len() + (spelled_out - elided) * usize::from(size.rows),
            532_545
        );

        let ServerMessage::Screen {
            part: ScreenPart::Head { rows: named, .. },
        } = ServerMessage::decode(&encoded[4..], Version::LOCAL).unwrap()
        else {
            panic!("expected a whole screen");
        };
        assert!(named.iter().all(|span| span.frame.text.is_empty()));
        assert!(named.iter().all(|span| span.frame.cells == size.cols));

        // A styled trailing run paints, so `styled_bytes` keeps it and the text travels whole.
        let mut painted = rows;
        painted[0].runs.push(StyleRun {
            cells: size.cols,
            bytes: u32::from(size.cols),
            style: CellStyle {
                bg: StyleColor::Palette(4),
                ..CellStyle::default()
            },
        });
        assert_eq!(painted[0].painted_bytes(), usize::from(size.cols));
        // The row's text, plus a run whose palette colour costs a byte more than three defaults.
        let with_tail = encode_screen_parts(&header, None, None, indexed(&painted), frame_budget())
            .expect("a screen carrying a painted row")
            .remove(0);
        assert_eq!(with_tail.len(), encoded.len() + usize::from(size.cols) + 12);
        let ServerMessage::Screen {
            part: ScreenPart::Head { rows: named, .. },
        } = ServerMessage::decode(&with_tail[4..], Version::LOCAL).unwrap()
        else {
            panic!("expected a whole screen");
        };
        assert_eq!(named[0].frame, painted[0]);
    }

    /// A piece cannot name more rows than the grid it arrives with holds: a partial screen
    /// decoded as complete leaves the server clearing damage for rows nothing ever painted.
    #[test]
    fn a_piece_may_not_name_more_rows_than_its_grid_holds() {
        let size = GridSize::new(8, 2).expect("a small grid");
        let header = screen_header(size, None);
        let row = plain("ok");
        let rows = [row.clone(), row];
        let mut parts = encode_screen_parts(&header, None, None, indexed(&rows), frame_budget())
            .expect("a two-row screen");
        let encoded = &mut parts[0];
        assert!(ServerMessage::decode(&encoded[4..], Version::LOCAL).is_ok());
        // The grid shrinks under the rows the piece has already named.
        patch_u16(encoded, GRID_AT + 2, 1);
        assert!(matches!(
            ServerMessage::decode(&encoded[4..], Version::LOCAL),
            Err(DecodeError::InvalidField)
        ));
    }

    /// Without the range in the resume itself, a stale binary's resume evicts the healthy
    /// client before failing on version, leaving neither end attached.
    #[test]
    fn a_resume_states_the_range_the_session_is_refused_against() {
        for stated in [
            range(1, 3),
            range(PROTOCOL_VERSION + 1, PROTOCOL_VERSION + 4),
        ] {
            let frame = ClientMessage::Resume {
                versions: stated,
                seq: CmdSeq::first(),
                request: resume_request(),
            }
            .encode(Version::LOCAL)
            .expect("a resume encodes");
            let ClientMessage::Resume { versions, .. } =
                ClientMessage::decode(&frame[LENGTH_PREFIX..], Version::LOCAL).expect("a resume")
            else {
                panic!("a resume");
            };
            assert_eq!(versions, stated, "the range survives the wire");
            assert_eq!(
                VersionRange::LOCAL.negotiate(versions),
                Err(RejectReason::Version {
                    server: VersionRange::LOCAL,
                    client: stated,
                }),
                "a resume this daemon cannot speak to must be refused, not applied"
            );
        }
    }

    #[test]
    fn a_zero_sequence_number_is_refused_rather_than_silently_accepted() {
        for message in [
            ClientMessage::Input {
                seq: CmdSeq::first(),
                bytes: b"ls\r".to_vec(),
            },
            ClientMessage::Resize {
                seq: CmdSeq::first(),
                size: small_grid(),
            },
            ClientMessage::RequestRepaint {
                seq: CmdSeq::first(),
            },
            ClientMessage::Close {
                seq: CmdSeq::first(),
            },
            ClientMessage::Detach {
                seq: CmdSeq::first(),
            },
            ClientMessage::Resume {
                versions: VersionRange::LOCAL,
                seq: CmdSeq::first(),
                request: resume_request(),
            },
        ] {
            let mut frame = message.encode(Version::LOCAL).unwrap();
            // The sequence follows the tag, with `Resume` stating its version in between.
            let at = LENGTH_PREFIX
                + 1
                + 2 * usize::from(matches!(message, ClientMessage::Resume { .. }));
            frame[at..at + 8].fill(0);
            assert!(
                matches!(
                    ClientMessage::decode(&frame[4..], Version::LOCAL),
                    Err(DecodeError::InvalidField)
                ),
                "the decoder placed a zero sequence: {message:?}"
            );
        }

        // The same eight zero bytes where absence is what they mean.
        let absent = ServerMessage::CommandAck { highest: None };
        let frame = absent.encode(Version::LOCAL).unwrap();
        assert_eq!(&frame[LENGTH_PREFIX + 1..], &[0; 8]);
        assert_eq!(
            ServerMessage::decode(&frame[4..], Version::LOCAL).unwrap(),
            absent
        );
    }

    #[test]
    fn rejects_unknown_detach_reason() {
        assert!(matches!(
            ServerMessage::decode(
                &[ServerTag::Detached as u8 + SERVER_TAG_BASE, 9],
                Version::LOCAL
            ),
            Err(DecodeError::InvalidField)
        ));
    }

    /// A screen naming the handful of rows that changed, on top of the version it applies to.
    fn small_delta(scroll: Option<ScrollBand>, rows: Vec<u16>) -> ScreenPart {
        ScreenPart::Head {
            header: screen_header(GridSize { cols: 16, rows: 4 }, Some((3, 2))),
            base: Some(ScreenVersion::initial()),
            scroll,
            pieces: 1,
            rows: rows
                .into_iter()
                .map(|row| RowSpan {
                    row,
                    chunk: false,
                    col: 0,
                    byte: 0,
                    clear_tail: false,
                    frame: plain("shell $"),
                })
                .collect(),
        }
    }

    /// The whole viewport, moved by `lines`.
    fn viewport(rows: u16, lines: u16) -> ScrollBand {
        ScrollBand {
            top: 0,
            bottom: rows,
            lines,
        }
    }

    #[test]
    fn a_scroll_band_that_names_no_movement_is_refused() {
        let bands = [
            viewport(4, 0),
            viewport(4, 5),
            viewport(4, 6),
            viewport(4, u16::MAX),
            // Past the bottom of the grid.
            ScrollBand {
                top: 0,
                bottom: 5,
                lines: 1,
            },
            // Empty, and inverted.
            ScrollBand {
                top: 2,
                bottom: 2,
                lines: 1,
            },
            ScrollBand {
                top: 3,
                bottom: 1,
                lines: 1,
            },
            // A movement larger than the band itself.
            ScrollBand {
                top: 1,
                bottom: 3,
                lines: 3,
            },
        ];
        for scroll in bands {
            let encoded = ServerMessage::Screen {
                part: small_delta(Some(scroll), vec![1]),
            }
            .encode(Version::LOCAL)
            .unwrap();
            assert!(
                matches!(
                    ServerMessage::decode(&encoded[4..], Version::LOCAL),
                    Err(DecodeError::InvalidField)
                ),
                "the decoder admitted {scroll:?} over four rows"
            );
        }
    }

    #[test]
    fn the_cut_refuses_a_band_outside_its_own_grid() {
        let header = screen_header(GridSize { cols: 16, rows: 4 }, None);
        let rows = [plain("one"), plain("two")];
        let band = ScrollBand {
            top: 0,
            bottom: 9,
            lines: 1,
        };
        assert_eq!(
            encode_screen_parts(&header, None, Some(band), indexed(&rows), frame_budget()),
            Err(EncodeError::BadScroll(band))
        );
    }

    /// The refusal that matters is the decoder's: a piece names the rows its caller chose and
    /// the encoder measures them against no grid. The one index the encoder still refuses is
    /// the one it cannot restate — an index carrying the bit that marks a chunk.
    #[test]
    fn a_delta_row_outside_the_screen_is_rejected() {
        let mut delta = small_delta(None, vec![9]);
        let encoded = ServerMessage::Screen {
            part: delta.clone(),
        }
        .encode(Version::LOCAL)
        .unwrap();
        assert!(matches!(
            ServerMessage::decode(&encoded[4..], Version::LOCAL),
            Err(DecodeError::InvalidField)
        ));

        let ScreenPart::Head { rows, .. } = &mut delta else {
            panic!("a head");
        };
        rows[0].row = 1 | ROW_CHUNK_FLAG;
        assert_eq!(
            ServerMessage::Screen { part: delta }.encode(Version::LOCAL),
            Err(EncodeError::RowIndex(1 | ROW_CHUNK_FLAG))
        );
    }
}
