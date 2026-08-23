/// IEEE 802.11 service-set identifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ssid {
    bytes: [u8; Self::MAX_LEN],
    len: u8,
}

impl Ssid {
    /// Maximum SSID length defined by IEEE 802.11.
    pub const MAX_LEN: usize = 32;

    /// Copy an SSID into fixed storage.
    ///
    /// Returns `None` for an empty value or a value longer than 32 bytes.
    #[must_use]
    pub fn new(value: &[u8]) -> Option<Self> {
        if value.is_empty() || value.len() > Self::MAX_LEN {
            return None;
        }
        let mut bytes = [0; Self::MAX_LEN];
        bytes[..value.len()].copy_from_slice(value);
        let len = u8::try_from(value.len()).ok()?;
        Some(Self { bytes, len })
    }

    /// Return the SSID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Return the SSID length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Test whether the SSID is empty.
    ///
    /// Values created through [`Ssid::new`] are never empty. This method is
    /// useful when an SSID was decoded from firmware data.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for Ssid {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Ssid")
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

/// Security mode requested for a station connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// No link-layer encryption.
    Open,
    /// WPA2 personal.
    Wpa2Personal,
    /// WPA3 SAE personal.
    Wpa3Personal,
    /// WPA2/WPA3 transition mode.
    Wpa2Wpa3Personal,
}

/// Authentication material supplied to the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credentials<'a> {
    /// Open network.
    None,
    /// Eight to 63 passphrase bytes.
    Passphrase(&'a [u8]),
    /// A pre-derived 256-bit WPA2 PSK.
    Psk(&'a [u8; 32]),
}

/// Validated connection parameters passed to an RPU control implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectRequest<'a> {
    /// Target network name.
    pub ssid: Ssid,
    /// Requested security mode.
    pub security: Security,
    /// Authentication material.
    pub credentials: Credentials<'a>,
    /// Optional channel hint in the range 1 through 233.
    pub channel_hint: Option<u8>,
}

impl ConnectRequest<'_> {
    /// Check credential and channel constraints before an RPU command is sent.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if matches!(self.channel_hint, Some(0)) {
            return false;
        }

        match (self.security, self.credentials) {
            (Security::Open, Credentials::None) => true,
            (Security::Open, _) | (_, Credentials::None) => false,
            (Security::Wpa3Personal, Credentials::Psk(_)) => false,
            (_, Credentials::Passphrase(passphrase)) => {
                (8..=63).contains(&passphrase.len())
            }
            (_, Credentials::Psk(_)) => true,
        }
    }
}

/// High-level station state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiState {
    /// RPU control interface is not initialized.
    Down,
    /// Interface is ready and not connected.
    Idle,
    /// Scan is in progress.
    Scanning,
    /// Firmware is associating with an access point.
    Associating,
    /// Link authentication is in progress.
    Authenticating,
    /// Ethernet data can flow.
    Connected {
        /// Access-point address.
        bssid: [u8; 6],
        /// Active channel.
        channel: u8,
    },
    /// A disconnect request is in progress.
    Disconnecting,
    /// Firmware reported a non-recoverable error.
    Fault,
}

/// Event emitted by an nRF7002 RPU implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiEvent {
    /// Control and data queues are ready.
    Ready,
    /// A scan has started.
    ScanStarted,
    /// One access point was found.
    ScanResult {
        /// Network name.
        ssid: Ssid,
        /// Access-point address.
        bssid: [u8; 6],
        /// Wi-Fi channel.
        channel: u8,
        /// Received signal level in dBm.
        rssi_dbm: i8,
        /// Advertised security mode.
        security: Security,
    },
    /// The scan result stream is complete.
    ScanComplete,
    /// Association and authentication completed.
    Connected {
        /// Access-point address.
        bssid: [u8; 6],
        /// Active channel.
        channel: u8,
    },
    /// The station left the network.
    Disconnected {
        /// IEEE 802.11 reason code.
        reason: u16,
    },
    /// At least one Ethernet receive descriptor is ready.
    ReceiveReady,
    /// Firmware completed an Ethernet transmit descriptor.
    TransmitComplete {
        /// Host token from the submitted descriptor.
        token: u32,
    },
    /// Firmware reported a fatal condition.
    FirmwareFault {
        /// Firmware-defined fault code.
        code: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::{ConnectRequest, Credentials, Security, Ssid};

    #[test]
    fn ssid_length_is_checked() {
        assert!(Ssid::new(b"network").is_some());
        assert!(Ssid::new(b"").is_none());
        assert!(Ssid::new(&[0; 33]).is_none());
    }

    #[test]
    fn open_network_rejects_credentials() {
        let request = ConnectRequest {
            ssid: Ssid::new(b"network").expect("valid SSID"),
            security: Security::Open,
            credentials: Credentials::Passphrase(b"not-needed"),
            channel_hint: None,
        };
        assert!(!request.is_valid());
    }

    #[test]
    fn personal_passphrase_length_is_checked() {
        let ssid = Ssid::new(b"network").expect("valid SSID");
        let short = ConnectRequest {
            ssid,
            security: Security::Wpa2Personal,
            credentials: Credentials::Passphrase(b"short"),
            channel_hint: None,
        };
        let valid = ConnectRequest {
            ssid,
            security: Security::Wpa2Personal,
            credentials: Credentials::Passphrase(b"12345678"),
            channel_hint: Some(6),
        };
        assert!(!short.is_valid());
        assert!(valid.is_valid());
    }
}
