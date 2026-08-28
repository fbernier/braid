#![forbid(unsafe_code)]

use braid_proto::{CAPABILITY_BYTES, SessionId};

/// The unforgeable name of one live session. The identifier is public — it
/// appears in the runtime directory — so resume is authenticated by the
/// capability, of which only a hash is ever persisted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionTicket {
    pub session_id: SessionId,
    pub capability: [u8; CAPABILITY_BYTES],
}

impl SessionTicket {
    pub fn issue() -> Result<Self, getrandom::Error> {
        let mut id = [0_u8; 16];
        let mut capability = [0_u8; CAPABILITY_BYTES];
        getrandom::fill(&mut id)?;
        getrandom::fill(&mut capability)?;
        Ok(Self {
            session_id: SessionId::from_bytes(id),
            capability,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_ticket_names_a_distinct_session() {
        let first = SessionTicket::issue().expect("entropy should be available");
        let second = SessionTicket::issue().expect("entropy should be available");
        assert_ne!(first.session_id, second.session_id);
        assert_ne!(first.capability, second.capability);
        assert_ne!(first.capability, [0; CAPABILITY_BYTES]);
    }
}
