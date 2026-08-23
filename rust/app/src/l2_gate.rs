//! Pure readiness gate for the first Zephyr L2 proof.
//!
//! This module intentionally contains no Zephyr types and no socket or packet
//! ownership.  It is the small policy boundary used by the Embassy task:
//! credentials and an authorized link must both be present before the
//! platform L2 endpoint may be opened.  Rust IP initialization is not part of
//! this stage.

/// Snapshot reported by the package-private embassy-zephyr-nrf7002 bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct L2Status {
    /// The Zephyr Wi-Fi/Ethernet interface has been created and is usable.
    pub interface_ready: bool,
    /// The WPA controlled port is authorized and the link can carry data.
    pub link_authorized: bool,
    /// Credentials/configuration needed by the supplicant are available.
    pub credentials_ready: bool,
}

impl L2Status {
    /// A raw L2 endpoint may only be opened after all three gates pass.
    pub const fn can_open(self) -> bool {
        self.interface_ready && self.link_authorized && self.credentials_ready
    }
}

/// Stable error class for the L2 proof boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L2Error {
    /// The interface is not ready or the link/credential gate is closed.
    NotReady,
    /// The bridge is not linked into this image yet.
    Unavailable,
    /// The platform rejected the open request.  The value is an opaque,
    /// stable-negative platform code and is never interpreted here.
    Platform(i32),
}

/// State kept by the proof task after an endpoint has been opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L2Phase {
    Waiting,
    Open,
}

impl L2Phase {
    /// Apply a fresh status snapshot to the proof state.
    pub const fn observe(self, status: L2Status) -> Self {
        match (self, status.can_open()) {
            (Self::Open, true) => Self::Open,
            (Self::Open, false) => Self::Waiting,
            (Self::Waiting, _) => Self::Waiting,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{L2Phase, L2Status};

    #[test]
    fn all_readiness_gates_are_required() {
        let complete = L2Status {
            interface_ready: true,
            link_authorized: true,
            credentials_ready: true,
        };
        assert!(complete.can_open());

        for status in [
            L2Status {
                interface_ready: false,
                ..complete
            },
            L2Status {
                link_authorized: false,
                ..complete
            },
            L2Status {
                credentials_ready: false,
                ..complete
            },
        ] {
            assert!(!status.can_open());
        }
    }

    #[test]
    fn link_loss_returns_open_phase_to_waiting() {
        let complete = L2Status {
            interface_ready: true,
            link_authorized: true,
            credentials_ready: true,
        };
        let down = L2Status {
            link_authorized: false,
            ..complete
        };

        assert_eq!(L2Phase::Waiting.observe(complete), L2Phase::Waiting);
        assert_eq!(L2Phase::Open.observe(complete), L2Phase::Open);
        assert_eq!(L2Phase::Open.observe(down), L2Phase::Waiting);
    }
}
