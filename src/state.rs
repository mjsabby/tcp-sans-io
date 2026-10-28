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

#[cfg(any(test, feature = "std"))]
impl State {
    /// Every state change one API call (`inject_packet`, `tick`, `connect`,
    /// `listen`, `close`, `abort`, …) can make. The fuzz targets panic on any
    /// other move, and `docs/state-machine.dot` must draw exactly these edges
    /// (checked by a unit test), so the diagram cannot drift from the code.
    pub fn debug_transition_allowed(self, next: State) -> bool {
        use State::*;
        self == next
            || matches!(
                (self, next),
                (Closed, SynSent | Listen)
                    // SYN; a valid cookie ACK (possibly carrying a FIN);
                    // close() / abort().
                    | (Listen, SynRcvd | Established | CloseWait | Closed)
                    // SYN-ACK; simultaneous open; RST / timeout / abort().
                    | (SynSent, Established | SynRcvd | Closed)
                    // Third ACK (or a cookie ACK taking over the slot),
                    // possibly with a FIN; close(); recycle; abort.
                    | (SynRcvd, Established | CloseWait | FinWait1 | Listen | Closed)
                    | (Established, FinWait1 | CloseWait | Closed)
                    | (FinWait1, FinWait2 | Closing | TimeWait | Closed)
                    | (FinWait2, TimeWait | Closed)
                    | (Closing, TimeWait | Closed)
                    | (TimeWait, Closed | Listen)
                    | (CloseWait, LastAck | Closed)
                    | (LastAck, Closed)
            )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    extern crate std;
    use super::State;
    use std::collections::BTreeSet;

    const ALL: [State; 11] = [
        State::Closed,
        State::SynSent,
        State::Established,
        State::FinWait1,
        State::FinWait2,
        State::Closing,
        State::TimeWait,
        State::CloseWait,
        State::LastAck,
        State::Listen,
        State::SynRcvd,
    ];

    fn by_name(name: &str) -> State {
        *ALL.iter()
            .find(|s| std::format!("{s:?}") == name)
            .unwrap_or_else(|| panic!("unknown state {name} in state-machine.dot"))
    }

    /// The committed diagram draws exactly the transitions the code allows.
    #[test]
    fn state_machine_diagram_matches_the_transition_relation() {
        let dot = include_str!("../docs/state-machine.dot");
        let mut drawn = BTreeSet::new();
        for line in dot.lines() {
            let line = line.trim();
            if line.starts_with("//") {
                continue;
            }
            let Some((from, rest)) = line.split_once("->") else {
                continue;
            };
            let to: std::string::String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            drawn.insert((by_name(from.trim()) as u8, by_name(&to) as u8));
        }
        let mut allowed = BTreeSet::new();
        for a in ALL {
            for b in ALL {
                if a != b && a.debug_transition_allowed(b) {
                    allowed.insert((a as u8, b as u8));
                }
            }
        }
        let missing: std::vec::Vec<_> = allowed.difference(&drawn).collect();
        let extra: std::vec::Vec<_> = drawn.difference(&allowed).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "diagram drift: not drawn {missing:?}, drawn but not allowed {extra:?}"
        );
    }
}
