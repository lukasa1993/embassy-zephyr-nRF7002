/// Decoded nRF7002 RPU status byte.
///
/// The bit definitions match Nordic's `qspi_if.h` interface:
/// bit 1 is RPU awake and bit 2 is RPU ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct RpuStatus(u8);

impl RpuStatus {
    /// RPU awake indication.
    pub const AWAKE_BIT: u8 = 1 << 1;
    /// RPU ready indication.
    pub const READY_BIT: u8 = 1 << 2;

    /// Decode a raw status byte.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// Return the original status byte.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Test whether the RPU reports an awake state.
    #[must_use]
    pub const fn is_awake(self) -> bool {
        self.0 & Self::AWAKE_BIT != 0
    }

    /// Test whether the RPU reports a ready state.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.0 & Self::READY_BIT != 0
    }
}

/// Value written to the wake-control status register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct WakeControl(u8);

impl WakeControl {
    /// Request immediate RPU wake-up.
    pub const WAKE_NOW_BIT: u8 = 1;

    /// Keep unrelated register bits and set the wake request.
    #[must_use]
    pub const fn request_wake(current: u8) -> Self {
        Self(current | Self::WAKE_NOW_BIT)
    }

    /// Return the byte for the status-register write.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{RpuStatus, WakeControl};

    #[test]
    fn status_bits_are_decoded_independently() {
        let status = RpuStatus::from_raw(RpuStatus::AWAKE_BIT | RpuStatus::READY_BIT);
        assert!(status.is_awake());
        assert!(status.is_ready());
        assert_eq!(status.raw(), 0b0000_0110);
    }

    #[test]
    fn wake_request_preserves_other_bits() {
        assert_eq!(WakeControl::request_wake(0b1010_0000).raw(), 0b1010_0001);
    }
}
