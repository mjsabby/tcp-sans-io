//! TCP state machine, per RFC 793 §3.2 / RFC 9293.
//!
//! Both active opens (`SynSent`) and passive opens (`Listen` / `SynRcvd`)
//! are supported. A single TCB can serve at most one connection at a time;
//! a `Listen` TCB transitions to `SynRcvd` on a valid inbound SYN, then to
//! `Established` on the matching ACK. SYN cookies (RFC 4987) are
//! optionally available for stateless half-open handling under flood
//! conditions — see `Tcb::set_cookie_secret`.

/// One-byte representation crossing the FFI boundary.
///
/// New variants must only be appended (existing discriminants are part of
/// the FFI contract). Bump `tcp_abi_version` if you ever renumber.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// No connection. Initial state and terminal state after a clean teardown.
    Closed = 0,
    /// Active open: SYN sent, awaiting SYN-ACK.
    SynSent = 1,
    /// Three-way handshake complete; bidirectional data flow allowed.
    Established = 2,
    /// Local app called `close`: FIN sent, awaiting ACK and possibly remote FIN.
    FinWait1 = 3,
    /// Our FIN was ACKed; awaiting remote FIN.
    FinWait2 = 4,
    /// Simultaneous close: peer sent FIN while we were in `FinWait1`.
    Closing = 5,
    /// Both sides have FINned and ACKed; waiting out `2*MSL` to absorb stragglers.
    TimeWait = 6,
    /// Peer sent FIN first; awaiting local app to call `close`.
    CloseWait = 7,
    /// We FINned from `CloseWait`; awaiting final ACK from peer.
    LastAck = 8,
    /// Passive open: bound to a local endpoint, awaiting an inbound SYN.
    /// The remote endpoint is unpinned until a SYN arrives.
    Listen = 9,
    /// Passive open mid-handshake: a valid SYN was accepted, our SYN-ACK
    /// has been emitted, and we are awaiting the third ACK. Time-bounded
    /// by an RTO retransmit budget — see [`crate::tcb`].
    SynRcvd = 10,
}

impl State {
    /// Whether application data may be *sent* in this state.
    #[inline]
    pub const fn can_send(self) -> bool {
        matches!(self, State::Established | State::CloseWait)
    }

    /// Whether application data may be *received* in this state.
    #[inline]
    pub const fn can_recv(self) -> bool {
        matches!(self, State::Established | State::FinWait1 | State::FinWait2)
    }

    /// Whether the connection is fully torn down.
    #[inline]
    pub const fn is_closed(self) -> bool {
        matches!(self, State::Closed)
    }

    /// Whether the TCB is acting as a passive listener (LISTEN or has
    /// half-completed a passive open and is in SYN_RCVD).
    #[inline]
    pub const fn is_listening(self) -> bool {
        matches!(self, State::Listen | State::SynRcvd)
    }

    /// Whether the connection is past the synchronisation point (i.e. all
    /// sequence-number variables on both sides are agreed).
    #[inline]
    pub const fn is_synchronized(self) -> bool {
        matches!(
            self,
            State::Established
                | State::FinWait1
                | State::FinWait2
                | State::Closing
                | State::CloseWait
                | State::LastAck
                | State::TimeWait
        )
    }
}
