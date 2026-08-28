#![forbid(unsafe_code)]

//! Commands held for replay onto a replacement transport.

use braid_proto::{ClientMessage, CmdSeq, GridSize};
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum JournalError {
    #[error("command journal is full")]
    Full,
}

pub(crate) struct CommandJournal {
    capacity: usize,
    entries: VecDeque<(CmdSeq, ClientMessage)>,
}

impl CommandJournal {
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity: capacity.get(),
            entries: VecDeque::new(),
        }
    }

    pub(crate) fn push(
        &mut self,
        sequence: CmdSeq,
        message: ClientMessage,
    ) -> Result<(), JournalError> {
        if self.entries.len() == self.capacity {
            return Err(JournalError::Full);
        }
        self.entries.push_back((sequence, message));
        Ok(())
    }

    /// Retire everything up to `highest`, handing back the buffer the last
    /// `Input` it dropped was carrying, so typing reuses one allocation.
    pub(crate) fn acknowledge(&mut self, highest: CmdSeq) -> Option<Vec<u8>> {
        let mut spare = None;
        while self
            .entries
            .front()
            .is_some_and(|(sequence, _)| sequence.get() <= highest.get())
        {
            if let Some((_, ClientMessage::Input { bytes, .. })) = self.entries.pop_front() {
                spare = Some(bytes);
            }
        }
        spare
    }

    /// Every retained command, oldest first.
    pub(crate) fn all(&self) -> Vec<ClientMessage> {
        self.entries
            .iter()
            .map(|(_, message)| message.clone())
            .collect()
    }

    /// The oldest retained commands, up to `most`: a cumulative acknowledgement
    /// cannot advance past the oldest thing the server is missing.
    pub(crate) fn oldest(&self, most: usize) -> Vec<(CmdSeq, ClientMessage)> {
        self.entries.iter().take(most).cloned().collect()
    }

    pub(crate) fn displace_oldest(&mut self) {
        self.entries.pop_front();
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    #[must_use]
    pub(crate) fn is_full(&self) -> bool {
        self.entries.len() == self.capacity
    }
}

/// Control messages a full journal could not number yet. Each is idempotent
/// and superseded by its own successor, so the latest is held rather than
/// dropped.
#[derive(Default)]
pub(crate) struct Deferred {
    pub(crate) resize: Option<GridSize>,
    pub(crate) repaint: bool,
}
