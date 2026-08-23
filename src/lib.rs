//! Safe, bounded Rust access to the Zephyr Wi-Fi/L2 foundation.
//!
//! The crate is intentionally a small synchronous boundary.  Zephyr owns the
//! Wi-Fi device, supplicant, controlled port, and role-addressable raw L2
//! sockets. Rust owns Wi-Fi policy through [`WifiController`] and owns the
//! buffers passed to [`Platform::recv`] and [`Platform::send`], but
//! never receives a Zephyr packet object or descriptor.  No allocator,
//! executor, task, or hidden queue is used here.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

mod abi;
mod wifi;

pub use wifi::*;

#[cfg(feature = "embassy-net")]
mod driver;

#[cfg(feature = "embassy-net")]
pub use driver::{
    DEFAULT_PACKET_BUFFER_SIZE as DEFAULT_NETWORK_BUFFER_SIZE,
    DEFAULT_RX_SLOTS as DEFAULT_NETWORK_RX_SLOTS, DEFAULT_TX_SLOTS as DEFAULT_NETWORK_TX_SLOTS,
    DefaultSharedDevice, DriverError as NetworkDriverError, L2Endpoint as NetworkEndpoint,
    NetworkDriver, Reactor as NetworkReactor, RxToken as NetworkRxToken,
    ServiceReport as NetworkServiceReport, SharedDevice, Split as NetworkSplit,
    TxProgress as NetworkTxProgress, TxToken as NetworkTxToken, initialize as initialize_network,
    split as split_network,
};

use core::ffi::c_void;
use core::fmt;
use core::mem::size_of;
use core::ptr::null_mut;

/// ABI version expected from the frozen Zephyr foundation package.
pub const ABI_VERSION: u32 = abi::ABI_VERSION;
/// Maximum SSID length accepted by the bridge.
pub const MAX_SSID_LEN: usize = abi::MAX_SSID_LEN;
/// Maximum WPA2/WPA3 passphrase length accepted by the bridge.
pub const MAX_PASSPHRASE_LEN: usize = abi::MAX_PASSPHRASE_LEN;
/// Ethernet header length in bytes.
pub const ETHERNET_HEADER_LEN: usize = abi::ETH_HEADER_LEN;
/// Maximum complete Ethernet frame accepted by this adapter.
pub const MAX_FRAME_LEN: usize = abi::MAX_FRAME_LEN;
/// Smallest supported Ethernet MTU.
pub const MIN_MTU: u16 = 576;
/// Largest supported MTU.  This leaves room for an Ethernet header in
/// [`MAX_FRAME_LEN`].
pub const MAX_MTU: u16 = (MAX_FRAME_LEN - ETHERNET_HEADER_LEN) as u16;
/// EAPOL EtherType, owned by Zephyr and its supplicant.
pub const EAPOL_ETHERTYPE: u16 = 0x888e;

/// Errors exposed by the safe adapter.
///
/// These are owned Rust meanings, not Zephyr errno values.  The C side may
/// use different native errors; the private ABI layer maps them into this
/// closed set before returning to a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The foundation reports a different ABI version or structure layout.
    AbiMismatch,
    /// An operation was given an invalid argument.
    InvalidArgument,
    /// A station/interface MAC address is not a usable unicast address.
    InvalidMac,
    /// The configured MTU is outside the bounded adapter range.
    InvalidMtu,
    /// A caller-owned buffer is too small for the requested operation.
    BufferTooSmall,
    /// The received or transmitted data is shorter than an Ethernet header.
    FrameTooShort,
    /// A frame exceeds the configured MTU or adapter limit.
    FrameTooLarge,
    /// A frame contains EAPOL/control traffic owned by Zephyr.
    EapolFrame,
    /// The endpoint has not been opened.
    NotOpen,
    /// The interface or supplicant has not finished becoming ready.
    NotReady,
    /// The endpoint is already open or an operation is in progress.
    Busy,
    /// The controlled port is not authorized/connected for transmission.
    NotConnected,
    /// The operation exceeded its supplied timeout.
    TimedOut,
    /// A nonblocking operation has no data yet.
    WouldBlock,
    /// The foundation does not provide the requested operation.
    Unsupported,
    /// A foundation I/O operation failed.
    Io,
    /// The foundation returned a malformed value or event.
    Protocol,
    /// The foundation entered a terminal fault state.
    Fault,
}

impl Error {
    /// Returns a stable human-readable description without allocating.
    pub const fn description(self) -> &'static str {
        match self {
            Self::AbiMismatch => "Zephyr L2 ABI mismatch",
            Self::InvalidArgument => "invalid argument",
            Self::InvalidMac => "invalid MAC address",
            Self::InvalidMtu => "invalid MTU",
            Self::BufferTooSmall => "buffer too small",
            Self::FrameTooShort => "Ethernet frame is too short",
            Self::FrameTooLarge => "Ethernet frame is too large",
            Self::EapolFrame => "EAPOL frame belongs to Zephyr",
            Self::NotOpen => "Zephyr L2 endpoint is not open",
            Self::NotReady => "Zephyr Wi-Fi interface is not ready",
            Self::Busy => "Zephyr L2 endpoint is busy",
            Self::NotConnected => "Wi-Fi controlled port is not connected",
            Self::TimedOut => "operation timed out",
            Self::WouldBlock => "operation would block",
            Self::Unsupported => "operation is unsupported",
            Self::Io => "Zephyr L2 I/O failure",
            Self::Protocol => "malformed Zephyr L2 response",
            Self::Fault => "Zephyr L2 foundation fault",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

/// A validated station/interface MAC address.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MacAddress([u8; abi::MAC_LEN]);

impl MacAddress {
    /// Validates and constructs a station MAC address.
    ///
    /// Interface addresses must be unicast, non-zero, and different from the
    /// all-ones broadcast address.  Ethernet destination addresses are
    /// validated separately because multicast/broadcast destinations are
    /// valid for frames.
    pub const fn new(bytes: [u8; abi::MAC_LEN]) -> Result<Self, Error> {
        if !is_valid_unicast_mac(&bytes) {
            return Err(Error::InvalidMac);
        }
        Ok(Self(bytes))
    }

    /// Returns the six address octets.
    pub const fn as_bytes(&self) -> &[u8; abi::MAC_LEN] {
        &self.0
    }

    /// Returns whether this is a unicast, non-zero interface address.
    pub const fn is_unicast(self) -> bool {
        is_valid_unicast_mac(&self.0)
    }
}

/// A validated Ethernet MTU.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Mtu(u16);

impl Mtu {
    /// Validates and constructs an MTU.
    pub const fn new(value: u16) -> Result<Self, Error> {
        if value < MIN_MTU || value > MAX_MTU {
            return Err(Error::InvalidMtu);
        }
        Ok(Self(value))
    }

    /// Returns the MTU in bytes, excluding the Ethernet header.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Returns the largest complete frame accepted at this MTU.
    pub const fn frame_len(self) -> usize {
        ETHERNET_HEADER_LEN + self.0 as usize
    }
}

/// Wi-Fi security selected by the Zephyr supplicant for a connect request.
///
/// The enum is intentionally owned and closed: arbitrary Zephyr security
/// codes cannot cross into the Rust API.  The passphrase remains borrowed for
/// the duration of [`Platform::connect`] and is never retained by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Security {
    /// No passphrase; the network is open.
    Open,
    /// WPA-Personal compatibility mode.
    WpaPsk,
    /// WPA2-Personal with an 8--63 byte passphrase.
    Wpa2Psk,
    /// WPA2-Personal using the SHA-256 AKM.
    Wpa2PskSha256,
    /// WPA3-SAE with an 8--63 byte passphrase.
    Wpa3Sae,
    /// WPA3-SAE Hash-to-Element only.
    Wpa3SaeH2e,
    /// WPA3-SAE with automatic H2E compatibility.
    Wpa3SaeAutomatic,
    /// WPA/WPA2/WPA3 personal mode selected explicitly by Rust.
    WpaAutomaticPersonal,
}

impl Security {
    pub(crate) const fn to_wire(self) -> u8 {
        match self {
            Self::Open => abi::SECURITY_OPEN as u8,
            Self::WpaPsk => abi::SECURITY_WPA_PSK as u8,
            Self::Wpa2Psk => abi::SECURITY_WPA2_PSK as u8,
            Self::Wpa2PskSha256 => abi::SECURITY_WPA2_PSK_SHA256 as u8,
            Self::Wpa3Sae => abi::SECURITY_WPA3_SAE as u8,
            Self::Wpa3SaeH2e => abi::SECURITY_WPA3_SAE_H2E as u8,
            Self::Wpa3SaeAutomatic => abi::SECURITY_WPA3_SAE_AUTO as u8,
            Self::WpaAutomaticPersonal => abi::SECURITY_WPA_AUTO_PERSONAL as u8,
        }
    }

    const fn validate_passphrase(self, passphrase: &[u8]) -> Result<(), Error> {
        match self {
            Self::Open if passphrase.is_empty() => Ok(()),
            Self::Open => Err(Error::InvalidArgument),
            _ if passphrase.len() >= 8 && passphrase.len() <= MAX_PASSPHRASE_LEN => Ok(()),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Borrowed, bounded Wi-Fi connection parameters.
///
/// The adapter does not copy or retain any field.  The caller must keep the
/// slices valid only until [`Platform::connect`] returns; the Zephyr bridge
/// copies them into bounded call-local scratch storage and the underlying
/// supplicant consumes that request synchronously.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ConnectRequest<'a> {
    ssid: &'a [u8],
    security: Security,
    passphrase: &'a [u8],
    mfp: ManagementFrameProtection,
    band: Option<Band>,
    channel: Option<u8>,
    channel_width: ChannelWidth,
    hidden_ssid: HiddenSsid,
    bssid: Option<MacAddress>,
    timeout_ms: u32,
}

impl fmt::Debug for ConnectRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectRequest")
            .field("ssid_len", &self.ssid.len())
            .field("security", &self.security)
            .field("passphrase_len", &self.passphrase.len())
            .field("mfp", &self.mfp)
            .field("band", &self.band)
            .field("channel", &self.channel)
            .field("channel_width", &self.channel_width)
            .field("hidden_ssid", &self.hidden_ssid)
            .field("bssid_set", &self.bssid.is_some())
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl<'a> ConnectRequest<'a> {
    /// Creates a request with explicit security and borrowed credentials.
    pub const fn new(ssid: &'a [u8], security: Security, passphrase: &'a [u8]) -> Self {
        Self {
            ssid,
            security,
            passphrase,
            mfp: ManagementFrameProtection::Disabled,
            band: None,
            channel: None,
            channel_width: ChannelWidth::Automatic,
            hidden_ssid: HiddenSsid::Visible,
            bssid: None,
            timeout_ms: 0,
        }
    }

    /// Creates an open-network request with no credential bytes.
    pub const fn open(ssid: &'a [u8]) -> Self {
        Self::new(ssid, Security::Open, &[])
    }

    /// Selects management-frame protection policy.
    pub const fn with_mfp(mut self, mfp: ManagementFrameProtection) -> Self {
        self.mfp = mfp;
        self
    }

    /// Restricts association to one radio band.
    pub const fn with_band(mut self, band: Band) -> Self {
        self.band = Some(band);
        self
    }

    /// Restricts association to one band and channel.
    pub const fn with_channel(mut self, band: Band, channel: u8) -> Self {
        self.band = Some(band);
        self.channel = Some(channel);
        self
    }

    /// Selects the requested channel width.
    pub const fn with_channel_width(mut self, width: ChannelWidth) -> Self {
        self.channel_width = width;
        self
    }

    /// Selects hidden-SSID behavior.
    pub const fn with_hidden_ssid(mut self, hidden: HiddenSsid) -> Self {
        self.hidden_ssid = hidden;
        self
    }

    /// Restricts association to one BSSID.
    pub const fn with_bssid(mut self, bssid: MacAddress) -> Self {
        self.bssid = Some(bssid);
        self
    }

    /// Sets the supplicant timeout; zero explicitly authorizes no deadline.
    pub const fn with_timeout_ms(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Returns the borrowed SSID.
    pub const fn ssid(self) -> &'a [u8] {
        self.ssid
    }

    /// Returns the selected security mode.
    pub const fn security(self) -> Security {
        self.security
    }

    /// Returns the borrowed passphrase.
    pub const fn passphrase(self) -> &'a [u8] {
        self.passphrase
    }

    /// Returns the management-frame protection policy.
    pub const fn mfp(self) -> ManagementFrameProtection {
        self.mfp
    }

    /// Returns the selected band, or `None` when Rust authorized automatic selection.
    pub const fn band(self) -> Option<Band> {
        self.band
    }

    /// Returns the selected channel, or `None` when Rust authorized automatic selection.
    pub const fn channel(self) -> Option<u8> {
        self.channel
    }

    /// Returns the selected channel width.
    pub const fn channel_width(self) -> ChannelWidth {
        self.channel_width
    }

    /// Returns the hidden-SSID behavior.
    pub const fn hidden_ssid(self) -> HiddenSsid {
        self.hidden_ssid
    }

    /// Returns the selected BSSID, if any.
    pub const fn bssid(self) -> Option<MacAddress> {
        self.bssid
    }

    /// Returns the requested timeout in milliseconds.
    pub const fn timeout_ms(self) -> u32 {
        self.timeout_ms
    }

    pub(crate) fn validate(self) -> Result<(), Error> {
        if self.ssid.is_empty() || self.ssid.len() > MAX_SSID_LEN {
            return Err(Error::InvalidArgument);
        }
        self.security.validate_passphrase(self.passphrase)?;
        if (self.channel.is_some() && self.band.is_none())
            || self
                .channel
                .is_some_and(|channel| channel == 0 || channel >= abi::CHANNEL_ANY)
        {
            return Err(Error::InvalidArgument);
        }
        // The pinned NCS hostap adapter renders these into quoted control
        // commands but does not escape quote or backslash bytes.
        if self
            .ssid
            .iter()
            .chain(self.passphrase.iter())
            .any(|byte| matches!(*byte, b'"' | b'\\'))
        {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// Link status owned by the Rust boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// The endpoint is down or has not completed initialization.
    Down,
    /// The endpoint is initialized and not currently associating.
    Ready,
    /// Zephyr/the supplicant is associating.
    Connecting,
    /// The controlled port is authorized and data frames may be sent.
    Connected,
    /// The station is initialized but currently disconnected.
    Disconnected,
    /// The foundation reports a terminal fault.
    Faulted,
}

impl Status {
    /// Returns whether the controlled port is authorized for data TX.
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Connected)
    }

    fn from_wire(value: u32) -> Result<Self, Error> {
        match value {
            abi::STATUS_DOWN => Ok(Self::Down),
            abi::STATUS_READY => Ok(Self::Ready),
            abi::STATUS_CONNECTING => Ok(Self::Connecting),
            abi::STATUS_CONNECTED => Ok(Self::Connected),
            abi::STATUS_DISCONNECTED => Ok(Self::Disconnected),
            abi::STATUS_FAULTED => Ok(Self::Faulted),
            _ => Err(Error::Protocol),
        }
    }
}

/// Link events generated by Zephyr's Wi-Fi/supplicant state machine.
///
/// Rust can select a BSSID for the initial request. Automatic reconnect and
/// roaming remain enabled as explicit product exceptions, and their outcomes
/// are observable here. The final variant is reserved for the Rust DHCP/IP
/// layer; it is never produced by the Zephyr foundation poll ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiEvent {
    /// The station became connected and its controlled port is authorized.
    Connected,
    /// Zephyr changed BSSID while retaining a connected station.
    Roamed,
    /// The station lost its connection or controlled-port authorization.
    Disconnected,
    /// The interface address/state changed.
    AddressChanged,
}

impl WifiEvent {
    fn from_wire(value: u32) -> Result<Option<Self>, Error> {
        match value {
            abi::EVENT_NONE => Ok(None),
            abi::EVENT_CONNECTED => Ok(Some(Self::Connected)),
            abi::EVENT_ROAMED => Ok(Some(Self::Roamed)),
            abi::EVENT_DISCONNECTED => Ok(Some(Self::Disconnected)),
            // AddressChanged is generated by Rust DHCP/IP state and must not
            // be accepted as a Zephyr-originated event.
            abi::EVENT_ADDRESS_CHANGED => Err(Error::Protocol),
            // Control-plane EAPOL notifications never cross the safe
            // physical-IP boundary.  The frame path applies the same rule.
            abi::EVENT_EAPOL => Ok(None),
            _ => Err(Error::Protocol),
        }
    }
}

/// Immutable interface metadata returned after opening the endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceInfo {
    mac: MacAddress,
    mtu: Mtu,
    status: Status,
}

impl InterfaceInfo {
    /// Returns the station MAC address.
    pub const fn mac(self) -> MacAddress {
        self.mac
    }

    /// Returns the configured Ethernet MTU.
    pub const fn mtu(self) -> Mtu {
        self.mtu
    }

    /// Returns the most recently observed link status.
    pub const fn status(self) -> Status {
        self.status
    }
}

/// Result of one bounded poll operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollResult {
    event: Option<WifiEvent>,
    status: Status,
}

impl PollResult {
    /// Returns the translated event, if one was pending.
    pub const fn event(self) -> Option<WifiEvent> {
        self.event
    }

    /// Returns the current link status.
    pub const fn status(self) -> Status {
        self.status
    }
}

/// Result of one receive attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveResult {
    /// No frame was available before the backend's bounded wait expired.
    Empty,
    /// A data frame was written to the caller's buffer.
    Frame(usize),
    /// A control/EAPOL frame was consumed and intentionally not exposed.
    Filtered,
}

/// Bounded nonblocking access to the board's provisioning console.
///
/// Rust owns all parsing and credential policy. Zephyr contributes only the
/// UART byte transport, so credentials never live in Kconfig or a C command
/// handler. Exactly one console reader may be opened for the image lifetime.
pub struct ProvisioningConsole {
    opened: bool,
}

impl ProvisioningConsole {
    /// Opens the console byte transport.
    pub fn open() -> Result<Self, Error> {
        #[cfg(feature = "zephyr")]
        {
            // SAFETY: this function takes no pointer and initializes one
            // process-global Zephyr console transport.
            map_result(unsafe { abi::embassy_zephyr_nrf7002_console_open() })?;
            return Ok(Self { opened: true });
        }
        #[cfg(not(feature = "zephyr"))]
        {
            Err(Error::Unsupported)
        }
    }

    /// Reads currently available bytes into caller-owned storage.
    ///
    /// The call is nonblocking. [`Error::WouldBlock`] means no byte is
    /// available yet and the caller should await an Embassy timer before
    /// polling again.
    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        if !self.opened {
            return Err(Error::NotOpen);
        }
        if buffer.is_empty() {
            return Err(Error::InvalidArgument);
        }
        #[cfg(feature = "zephyr")]
        {
            let mut received = 0usize;
            // SAFETY: the mutable slice is valid for `buffer.len()` bytes and
            // the output length pointer is uniquely borrowed for this call.
            let result = unsafe {
                abi::embassy_zephyr_nrf7002_console_read(
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut received,
                )
            };
            map_result(result)?;
            if received > buffer.len() {
                return Err(Error::Protocol);
            }
            return Ok(received);
        }
        #[cfg(not(feature = "zephyr"))]
        {
            let _ = buffer;
            Err(Error::Unsupported)
        }
    }
}

/// Fills caller-owned storage from Zephyr's hardware-backed CSPRNG.
pub fn fill_random(buffer: &mut [u8]) -> Result<(), Error> {
    #[cfg(feature = "zephyr")]
    {
        // SAFETY: the slice is valid for `buffer.len()` writable bytes and is
        // uniquely borrowed for the complete synchronous call.
        return map_result(unsafe {
            abi::embassy_zephyr_nrf7002_random_fill(buffer.as_mut_ptr(), buffer.len())
        });
    }
    #[cfg(not(feature = "zephyr"))]
    {
        let _ = buffer;
        Err(Error::Unsupported)
    }
}

/// Opaque, safe Rust handle to one role-specific Zephyr L2 endpoint.
///
/// Construct with [`Platform::new`] and call [`Platform::open`] before using
/// the endpoint.  [`Platform::open_endpoint`] is a convenience for the common
/// immediate-open case.
pub struct Platform {
    adapter: Adapter<FfiBackend>,
}

impl Platform {
    /// Creates a closed station endpoint without touching Zephyr.
    pub const fn new() -> Self {
        Self::new_for(InterfaceRole::Station)
    }

    /// Creates a closed endpoint for one Rust-selected interface role.
    pub const fn new_for(role: InterfaceRole) -> Self {
        Self {
            adapter: Adapter::new(FfiBackend::new(role)),
        }
    }

    /// Opens a newly-created endpoint against the frozen foundation.
    pub fn open(&mut self) -> Result<(), Error> {
        self.adapter.open()
    }

    /// Creates and opens an endpoint in one operation.
    pub fn open_endpoint() -> Result<Self, Error> {
        let mut platform = Self::new();
        platform.open()?;
        Ok(platform)
    }

    /// Creates and opens an endpoint for one Rust-selected role.
    pub fn open_endpoint_for(role: InterfaceRole) -> Result<Self, Error> {
        let mut platform = Self::new_for(role);
        platform.open()?;
        Ok(platform)
    }

    /// Returns the role this endpoint was created for.
    pub const fn role(&self) -> InterfaceRole {
        self.adapter.backend.role
    }

    /// Returns whether this endpoint owns an open foundation handle.
    pub const fn is_open(&self) -> bool {
        self.adapter.opened
    }

    /// Returns interface metadata once the endpoint is open.
    pub const fn interface(&self) -> Option<InterfaceInfo> {
        self.adapter.interface
    }

    /// Returns the current link status.
    pub const fn status(&self) -> Status {
        self.adapter.status
    }

    /// Closes the endpoint.  Closing an already-closed endpoint is idempotent.
    pub fn close(&mut self) -> Result<(), Error> {
        self.adapter.close()
    }

    /// Requests association using borrowed credentials configured for this
    /// operation by the Zephyr supplicant.
    ///
    /// Credentials are borrowed for the call only and must not be retained by
    /// the foundation bridge.  They never cross into a Rust socket or frame
    /// API.
    pub fn connect(&mut self, request: ConnectRequest<'_>) -> Result<(), Error> {
        self.adapter.connect(request)
    }

    /// Convenience form of [`Platform::connect`] for a direct borrowed PSK.
    ///
    /// This method is equivalent to constructing [`ConnectRequest::new`]; it
    /// exists to keep call sites that already have separate SSID/security/
    /// passphrase values allocation-free and obvious.
    pub fn connect_psk(
        &mut self,
        ssid: &[u8],
        security: Security,
        passphrase: &[u8],
    ) -> Result<(), Error> {
        self.connect(ConnectRequest::new(ssid, security, passphrase))
    }

    /// Requests disassociation and controlled-port closure.
    pub fn disconnect(&mut self) -> Result<(), Error> {
        self.adapter.disconnect()
    }

    /// Waits for one bounded link event and translates its status.
    ///
    /// This method does not create a task or perform scheduling.  A timeout
    /// of zero requests the foundation's nonblocking behavior.
    pub fn poll(&mut self, timeout_ms: u32) -> Result<PollResult, Error> {
        self.adapter.poll(timeout_ms)
    }

    /// Receives directly into a caller-owned Ethernet buffer.
    ///
    /// A returned [`ReceiveResult::Filtered`] means the backend consumed an
    /// EAPOL/control frame.  The bytes in the buffer must not be forwarded.
    pub fn recv(&mut self, buffer: &mut [u8]) -> Result<ReceiveResult, Error> {
        self.adapter.recv(buffer)
    }

    /// Sends one complete Ethernet frame from a caller-owned buffer.
    ///
    /// EAPOL and VLAN-tagged EAPOL frames are rejected because Zephyr's
    /// supplicant owns the controlled port.  On success the returned length is
    /// the exact input length accepted by the foundation.
    pub fn send(&mut self, frame: &[u8]) -> Result<usize, Error> {
        self.adapter.send(frame)
    }
}

impl Default for Platform {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop closes the opaque handle without exposing any C resource to callers.
impl Drop for Platform {
    fn drop(&mut self) {
        let _ = self.adapter.close();
    }
}

/// Internal backend contract used by the state machine and host tests.
///
/// Keeping this trait private ensures no backend can make raw Zephyr values a
/// public API.  The production implementation below is the only one enabled
/// outside tests; tests use a fixed-size mock with no allocation.
trait Backend {
    fn abi_version(&mut self) -> u32;
    fn open(&mut self) -> Result<(), Error>;
    fn close(&mut self) -> Result<(), Error>;
    fn interface(&mut self, interface: &mut abi::InterfaceWire) -> Result<(), Error>;
    fn connect(&mut self, request: ConnectRequest<'_>) -> Result<(), Error>;
    fn disconnect(&mut self) -> Result<(), Error>;
    fn poll(&mut self, timeout_ms: u32, result: &mut abi::PollWire) -> Result<(), Error>;
    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, Error>;
    fn send(&mut self, frame: &[u8]) -> Result<(), Error>;
}

/// Backend implementation that calls the private Zephyr C ABI.
struct FfiBackend {
    handle: *mut c_void,
    opened: bool,
    role: InterfaceRole,
}

impl FfiBackend {
    const fn new(role: InterfaceRole) -> Self {
        Self {
            handle: null_mut(),
            opened: false,
            role,
        }
    }
}

impl Backend for FfiBackend {
    fn abi_version(&mut self) -> u32 {
        #[cfg(feature = "zephyr")]
        {
            // SAFETY: the symbol is supplied by the verified Zephyr
            // foundation package and takes no pointers.
            return unsafe { abi::embassy_zephyr_nrf7002_l2_abi_version() };
        }
        #[cfg(not(feature = "zephyr"))]
        {
            0
        }
    }

    fn open(&mut self) -> Result<(), Error> {
        if self.opened {
            return Err(Error::Busy);
        }
        #[cfg(feature = "zephyr")]
        {
            let mut handle = null_mut();
            // SAFETY: `handle` is a valid out-pointer for the duration of the
            // call; the C side returns an opaque handle only on success.
            let result = unsafe {
                abi::embassy_zephyr_nrf7002_l2_open_role(self.role.to_wire(), &mut handle)
            };
            map_result(result)?;
            if handle.is_null() {
                return Err(Error::Fault);
            }
            self.handle = handle;
            self.opened = true;
            return Ok(());
        }
        #[cfg(not(feature = "zephyr"))]
        {
            Err(Error::Unsupported)
        }
    }

    fn close(&mut self) -> Result<(), Error> {
        if !self.opened {
            return Ok(());
        }
        #[cfg(feature = "zephyr")]
        {
            // SAFETY: `handle` was returned by `embassy_zephyr_nrf7002_l2_open_role` and has not
            // been passed to close since `opened` became true.
            let result = unsafe { abi::embassy_zephyr_nrf7002_l2_close(self.handle) };
            self.handle = null_mut();
            self.opened = false;
            return map_result(result);
        }
        #[cfg(not(feature = "zephyr"))]
        {
            self.handle = null_mut();
            self.opened = false;
            Ok(())
        }
    }

    fn interface(&mut self, interface: &mut abi::InterfaceWire) -> Result<(), Error> {
        if !self.opened {
            return Err(Error::NotOpen);
        }
        #[cfg(feature = "zephyr")]
        {
            // SAFETY: `interface` is a valid uniquely-borrowed output object;
            // the handle is live for this call.
            let result =
                unsafe { abi::embassy_zephyr_nrf7002_l2_interface(self.handle, interface) };
            return map_result(result);
        }
        #[cfg(not(feature = "zephyr"))]
        {
            let _ = interface;
            Err(Error::Unsupported)
        }
    }

    fn connect(&mut self, request: ConnectRequest<'_>) -> Result<(), Error> {
        if !self.opened {
            return Err(Error::NotOpen);
        }
        #[cfg(feature = "zephyr")]
        {
            let params = wifi::connect_wire(request);
            // SAFETY: every pointer in `params` borrows caller slices only for
            // this synchronous call; the C bridge must not retain them.
            let result =
                unsafe { abi::embassy_zephyr_nrf7002_l2_connect_psk(self.handle, &params) };
            return map_result(result);
        }
        #[cfg(not(feature = "zephyr"))]
        {
            let _ = request;
            Err(Error::Unsupported)
        }
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        if !self.opened {
            return Err(Error::NotOpen);
        }
        #[cfg(feature = "zephyr")]
        {
            // SAFETY: the handle is live and owned by this backend.
            let result = unsafe { abi::embassy_zephyr_nrf7002_l2_disconnect(self.handle) };
            return map_result(result);
        }
        #[cfg(not(feature = "zephyr"))]
        {
            Err(Error::Unsupported)
        }
    }

    fn poll(&mut self, timeout_ms: u32, result: &mut abi::PollWire) -> Result<(), Error> {
        if !self.opened {
            return Err(Error::NotOpen);
        }
        #[cfg(feature = "zephyr")]
        {
            // SAFETY: `result` is a valid uniquely-borrowed output object;
            // the handle is live for this call.
            let status =
                unsafe { abi::embassy_zephyr_nrf7002_l2_poll(self.handle, timeout_ms, result) };
            return map_result(status);
        }
        #[cfg(not(feature = "zephyr"))]
        {
            let _ = (timeout_ms, result);
            Err(Error::Unsupported)
        }
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        if !self.opened {
            return Err(Error::NotOpen);
        }
        #[cfg(feature = "zephyr")]
        {
            let mut received = 0usize;
            // SAFETY: `buffer` is valid for `buffer.len()` writable bytes and
            // remains borrowed for the duration of the C call.
            let status = unsafe {
                abi::embassy_zephyr_nrf7002_l2_recv(
                    self.handle,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut received,
                )
            };
            map_result(status)?;
            return Ok(received);
        }
        #[cfg(not(feature = "zephyr"))]
        {
            let _ = buffer;
            Err(Error::Unsupported)
        }
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        if !self.opened {
            return Err(Error::NotOpen);
        }
        #[cfg(feature = "zephyr")]
        {
            // SAFETY: `frame` is a valid readable slice for this call only.
            let status = unsafe {
                abi::embassy_zephyr_nrf7002_l2_send(self.handle, frame.as_ptr(), frame.len())
            };
            return map_result(status);
        }
        #[cfg(not(feature = "zephyr"))]
        {
            let _ = frame;
            Err(Error::Unsupported)
        }
    }
}

/// The state machine is generic internally so all boundary behavior can be
/// tested without linking Zephyr.
struct Adapter<B: Backend> {
    backend: B,
    interface: Option<InterfaceInfo>,
    status: Status,
    opened: bool,
}

impl<B: Backend> Adapter<B> {
    const fn new(backend: B) -> Self {
        Self {
            backend,
            interface: None,
            status: Status::Down,
            opened: false,
        }
    }
}

impl<B: Backend> Adapter<B> {
    fn open(&mut self) -> Result<(), Error> {
        if self.opened {
            return Err(Error::Busy);
        }
        if self.backend.abi_version() != ABI_VERSION {
            return Err(Error::AbiMismatch);
        }
        self.backend.open()?;

        let mut wire = abi::InterfaceWire {
            abi_version: 0,
            struct_size: 0,
            mac: [0; abi::MAC_LEN],
            mtu: 0,
            reserved: 0,
            status: abi::STATUS_DOWN,
        };
        if let Err(error) = self.backend.interface(&mut wire) {
            let _ = self.backend.close();
            return Err(error);
        }
        if wire.abi_version != ABI_VERSION
            || wire.struct_size as usize != size_of::<abi::InterfaceWire>()
        {
            let _ = self.backend.close();
            return Err(Error::AbiMismatch);
        }
        let mac = match MacAddress::new(wire.mac) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.backend.close();
                return Err(error);
            }
        };
        let mtu = match Mtu::new(wire.mtu) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.backend.close();
                return Err(error);
            }
        };
        let status = match Status::from_wire(wire.status) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.backend.close();
                return Err(error);
            }
        };

        self.interface = Some(InterfaceInfo { mac, mtu, status });
        self.status = status;
        self.opened = true;
        Ok(())
    }

    fn close(&mut self) -> Result<(), Error> {
        if !self.opened {
            self.interface = None;
            self.status = Status::Down;
            return Ok(());
        }
        let result = self.backend.close();
        self.opened = false;
        self.interface = None;
        self.status = Status::Down;
        result
    }

    fn connect(&mut self, request: ConnectRequest<'_>) -> Result<(), Error> {
        self.require_open()?;
        request.validate()?;
        if matches!(self.status, Status::Connected | Status::Connecting) {
            return Err(Error::Busy);
        }
        self.backend.connect(request)?;
        self.status = Status::Connecting;
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        self.require_open()?;
        self.backend.disconnect()?;
        self.status = Status::Disconnected;
        Ok(())
    }

    fn poll(&mut self, timeout_ms: u32) -> Result<PollResult, Error> {
        self.require_open()?;
        let mut wire = abi::PollWire {
            event: abi::EVENT_NONE,
            status: abi::STATUS_DOWN,
        };
        match self.backend.poll(timeout_ms, &mut wire) {
            Ok(()) => {}
            Err(Error::WouldBlock) => return Err(Error::WouldBlock),
            Err(Error::TimedOut) => return Err(Error::TimedOut),
            Err(error) => return Err(error),
        }
        let status = Status::from_wire(wire.status)?;
        let event = WifiEvent::from_wire(wire.event)?;
        if matches!(event, Some(WifiEvent::Connected | WifiEvent::Roamed))
            && status != Status::Connected
        {
            return Err(Error::Protocol);
        }
        if matches!(event, Some(WifiEvent::Disconnected)) && status == Status::Connected {
            return Err(Error::Protocol);
        }
        self.status = status;
        Ok(PollResult {
            event,
            status: self.status,
        })
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<ReceiveResult, Error> {
        self.require_open()?;
        if buffer.len() < ETHERNET_HEADER_LEN {
            return Err(Error::BufferTooSmall);
        }
        let received = match self.backend.recv(buffer) {
            Ok(length) => length,
            Err(Error::WouldBlock) | Err(Error::TimedOut) => return Ok(ReceiveResult::Empty),
            Err(error) => return Err(error),
        };
        let Some(interface) = self.interface else {
            return Err(Error::Fault);
        };
        let mtu = interface.mtu;
        if received > buffer.len() {
            return Err(Error::Protocol);
        }
        if received > mtu.frame_len() || received > MAX_FRAME_LEN {
            return Err(Error::FrameTooLarge);
        }
        if received < ETHERNET_HEADER_LEN {
            return Err(Error::FrameTooShort);
        }
        if is_eapol(&buffer[..received]) {
            return Ok(ReceiveResult::Filtered);
        }
        validate_frame(&buffer[..received])?;
        Ok(ReceiveResult::Frame(received))
    }

    fn send(&mut self, frame: &[u8]) -> Result<usize, Error> {
        self.require_open()?;
        if !self.status.is_connected() {
            return Err(Error::NotConnected);
        }
        let Some(interface) = self.interface else {
            return Err(Error::Fault);
        };
        let mtu = interface.mtu;
        if frame.len() < ETHERNET_HEADER_LEN {
            return Err(Error::FrameTooShort);
        }
        if frame.len() > mtu.frame_len() || frame.len() > MAX_FRAME_LEN {
            return Err(Error::FrameTooLarge);
        }
        if is_eapol(frame) {
            return Err(Error::EapolFrame);
        }
        validate_frame(frame)?;
        if frame[abi::MAC_LEN..2 * abi::MAC_LEN] != interface.mac.as_bytes()[..] {
            return Err(Error::InvalidMac);
        }
        self.backend.send(frame)?;
        Ok(frame.len())
    }

    fn require_open(&self) -> Result<(), Error> {
        if self.opened {
            Ok(())
        } else {
            Err(Error::NotOpen)
        }
    }
}

impl<B: Backend> Drop for Adapter<B> {
    fn drop(&mut self) {
        if self.opened {
            let _ = self.backend.close();
            self.opened = false;
        }
    }
}

#[cfg(any(feature = "zephyr", test))]
fn map_result(result: i32) -> Result<(), Error> {
    match result {
        abi::RESULT_OK => Ok(()),
        abi::RESULT_EINVAL => Err(Error::InvalidArgument),
        abi::RESULT_ENOMEM => Err(Error::Io),
        abi::RESULT_EMSGSIZE => Err(Error::BufferTooSmall),
        abi::RESULT_EBUSY => Err(Error::Busy),
        abi::RESULT_EIO => Err(Error::Io),
        abi::RESULT_ENOTSUP => Err(Error::Unsupported),
        abi::RESULT_ETIMEDOUT => Err(Error::TimedOut),
        abi::RESULT_ENOTCONN => Err(Error::NotConnected),
        abi::RESULT_EAGAIN => Err(Error::WouldBlock),
        abi::RESULT_EBADF => Err(Error::NotOpen),
        abi::RESULT_ENODEV | abi::RESULT_ENETDOWN => Err(Error::NotReady),
        abi::RESULT_EPERM => Err(Error::NotConnected),
        abi::RESULT_EPROTO => Err(Error::Protocol),
        abi::RESULT_ESTATE => Err(Error::Fault),
        _ => Err(Error::Fault),
    }
}

const fn is_valid_unicast_mac(mac: &[u8; abi::MAC_LEN]) -> bool {
    let mut any = 0u8;
    let mut all_ones = 0xffu8;
    let mut index = 0;
    while index < abi::MAC_LEN {
        any |= mac[index];
        all_ones &= mac[index];
        index += 1;
    }
    (mac[0] & 1) == 0 && any != 0 && all_ones != 0xff
}

fn is_valid_destination_mac(mac: &[u8]) -> bool {
    if mac.len() != abi::MAC_LEN {
        return false;
    }
    let mut any = 0u8;
    for byte in mac {
        any |= *byte;
    }
    any != 0
}

fn validate_frame(frame: &[u8]) -> Result<(), Error> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(Error::FrameTooShort);
    }
    // A destination may be unicast, multicast, or broadcast, but an all-zero
    // address is never a valid Ethernet destination.
    if !is_valid_destination_mac(&frame[..abi::MAC_LEN]) {
        return Err(Error::InvalidMac);
    }
    // Source addresses must be ordinary station unicast addresses.  This
    // rejects malformed frames before they reach the Zephyr socket.
    let mut source = [0u8; abi::MAC_LEN];
    source.copy_from_slice(&frame[abi::MAC_LEN..2 * abi::MAC_LEN]);
    if !is_valid_unicast_mac(&source) {
        return Err(Error::InvalidMac);
    }
    Ok(())
}

/// Returns whether a frame is EAPOL, including bounded VLAN encapsulations.
///
/// Eight tags cover the supported Ethernet forms while keeping this
/// inspection bounded and allocation-free.  A truncated VLAN header is not
/// classified as EAPOL here; the ordinary frame length check still protects
/// the boundary.
fn is_eapol(frame: &[u8]) -> bool {
    if frame.len() < ETHERNET_HEADER_LEN {
        return false;
    }
    let mut offset = 12usize;
    let mut ether_type = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    let mut tags = 0;
    // The frame is bounded by MAX_FRAME_LEN, so this fixed cap cannot turn
    // into an unbounded parser even for adversarial VLAN stacks.
    while tags < 8 && matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        if frame.len() < offset + 6 {
            return false;
        }
        offset += 4;
        ether_type = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
        tags += 1;
    }
    ether_type == EAPOL_ETHERTYPE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    struct MockBackend {
        abi_version: u32,
        interface: abi::InterfaceWire,
        opened: bool,
        close_count: u8,
        next_poll: abi::PollWire,
        frame: [u8; MAX_FRAME_LEN],
        frame_len: usize,
        sent_len: usize,
        last_ssid: [u8; MAX_SSID_LEN],
        last_ssid_len: usize,
        last_security: Security,
        last_passphrase: [u8; MAX_PASSPHRASE_LEN],
        last_passphrase_len: usize,
    }

    impl MockBackend {
        fn new(status: u32) -> Self {
            Self {
                abi_version: ABI_VERSION,
                interface: abi::InterfaceWire {
                    abi_version: ABI_VERSION,
                    struct_size: size_of::<abi::InterfaceWire>() as u32,
                    mac: [0x02, 0x12, 0x34, 0x56, 0x78, 0x9a],
                    mtu: 1500,
                    reserved: 0,
                    status,
                },
                opened: false,
                close_count: 0,
                next_poll: abi::PollWire {
                    event: abi::EVENT_NONE,
                    status,
                },
                frame: [0; MAX_FRAME_LEN],
                frame_len: 0,
                sent_len: 0,
                last_ssid: [0; MAX_SSID_LEN],
                last_ssid_len: 0,
                last_security: Security::Open,
                last_passphrase: [0; MAX_PASSPHRASE_LEN],
                last_passphrase_len: 0,
            }
        }

        fn queue_frame(&mut self, frame: &[u8]) {
            self.frame[..frame.len()].copy_from_slice(frame);
            self.frame_len = frame.len();
        }
    }

    impl Backend for MockBackend {
        fn abi_version(&mut self) -> u32 {
            self.abi_version
        }

        fn open(&mut self) -> Result<(), Error> {
            self.opened = true;
            Ok(())
        }

        fn close(&mut self) -> Result<(), Error> {
            self.opened = false;
            self.close_count = self.close_count.saturating_add(1);
            Ok(())
        }

        fn interface(&mut self, interface: &mut abi::InterfaceWire) -> Result<(), Error> {
            *interface = self.interface;
            Ok(())
        }

        fn connect(&mut self, request: ConnectRequest<'_>) -> Result<(), Error> {
            let ssid = request.ssid();
            let security = request.security();
            let passphrase = request.passphrase();
            self.last_ssid[..ssid.len()].copy_from_slice(ssid);
            self.last_ssid_len = ssid.len();
            self.last_security = security;
            self.last_passphrase[..passphrase.len()].copy_from_slice(passphrase);
            self.last_passphrase_len = passphrase.len();
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn poll(&mut self, _timeout_ms: u32, result: &mut abi::PollWire) -> Result<(), Error> {
            *result = self.next_poll;
            self.next_poll.event = abi::EVENT_NONE;
            Ok(())
        }

        fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
            if self.frame_len == 0 {
                return Err(Error::WouldBlock);
            }
            if buffer.len() < self.frame_len {
                return Err(Error::BufferTooSmall);
            }
            buffer[..self.frame_len].copy_from_slice(&self.frame[..self.frame_len]);
            let length = self.frame_len;
            self.frame_len = 0;
            Ok(length)
        }

        fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
            self.sent_len = frame.len();
            Ok(())
        }
    }

    fn connected_adapter() -> Adapter<MockBackend> {
        let mut adapter = Adapter::new(MockBackend::new(abi::STATUS_CONNECTED));
        adapter.open().unwrap();
        adapter
    }

    fn data_frame(ether_type: u16, payload_len: usize) -> [u8; 64] {
        let mut frame = [0u8; 64];
        frame[0..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&[0x02, 0x12, 0x34, 0x56, 0x78, 0x9a]);
        frame[12..14].copy_from_slice(&ether_type.to_be_bytes());
        for (index, byte) in frame[14..14 + payload_len].iter_mut().enumerate() {
            *byte = index as u8;
        }
        frame
    }

    #[test]
    fn mac_and_mtu_validation_is_strict() {
        assert_eq!(MacAddress::new([0; 6]), Err(Error::InvalidMac));
        assert_eq!(MacAddress::new([0xff; 6]), Err(Error::InvalidMac));
        assert_eq!(
            MacAddress::new([0x01, 0, 0, 0, 0, 1]),
            Err(Error::InvalidMac)
        );
        assert!(MacAddress::new([0x02, 0, 0, 0, 0, 1]).is_ok());
        assert_eq!(Mtu::new(0), Err(Error::InvalidMtu));
        assert_eq!(Mtu::new(MIN_MTU - 1), Err(Error::InvalidMtu));
        assert!(Mtu::new(1500).is_ok());
        assert!(Mtu::new(MAX_MTU).is_ok());
        assert_eq!(Mtu::new(MAX_MTU + 1), Err(Error::InvalidMtu));
    }

    #[test]
    fn abi_and_interface_are_validated_before_exposure() {
        let mut backend = MockBackend::new(abi::STATUS_READY);
        backend.abi_version = ABI_VERSION + 1;
        let mut adapter = Adapter::new(backend);
        assert_eq!(adapter.open(), Err(Error::AbiMismatch));
        assert!(!adapter.opened);

        let mut backend = MockBackend::new(abi::STATUS_READY);
        backend.interface.mac = [0; 6];
        let mut adapter = Adapter::new(backend);
        assert_eq!(adapter.open(), Err(Error::InvalidMac));
        assert_eq!(adapter.backend.close_count, 1);
    }

    #[test]
    fn connect_and_poll_translate_owned_events() {
        let mut adapter = Adapter::new(MockBackend::new(abi::STATUS_READY));
        adapter.open().unwrap();
        assert_eq!(
            adapter.connect(ConnectRequest::new(b"proof-net", Security::Open, b"secret")),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            adapter.connect(ConnectRequest::new(
                b"proof-net",
                Security::Wpa2Psk,
                b"short"
            )),
            Err(Error::InvalidArgument)
        );
        let request = ConnectRequest::new(
            b"proof-net",
            Security::Wpa2Psk,
            b"correcthorsebatterystaple",
        );
        assert_eq!(adapter.connect(request), Ok(()));
        assert_eq!(adapter.status, Status::Connecting);
        assert_eq!(
            &adapter.backend.last_ssid[..adapter.backend.last_ssid_len],
            b"proof-net"
        );
        assert_eq!(adapter.backend.last_security, Security::Wpa2Psk);
        assert_eq!(
            &adapter.backend.last_passphrase[..adapter.backend.last_passphrase_len],
            b"correcthorsebatterystaple"
        );

        adapter.backend.next_poll = abi::PollWire {
            event: abi::EVENT_CONNECTED,
            status: abi::STATUS_CONNECTED,
        };
        let result = adapter.poll(0).unwrap();
        assert_eq!(result.event(), Some(WifiEvent::Connected));
        assert_eq!(result.status(), Status::Connected);

        adapter.backend.next_poll = abi::PollWire {
            event: abi::EVENT_ROAMED,
            status: abi::STATUS_CONNECTED,
        };
        assert_eq!(adapter.poll(10).unwrap().event(), Some(WifiEvent::Roamed));

        adapter.backend.next_poll = abi::PollWire {
            event: abi::EVENT_DISCONNECTED,
            status: abi::STATUS_DISCONNECTED,
        };
        assert_eq!(adapter.poll(10).unwrap().status(), Status::Disconnected);

        adapter.backend.next_poll = abi::PollWire {
            event: abi::EVENT_ADDRESS_CHANGED,
            status: abi::STATUS_DISCONNECTED,
        };
        assert_eq!(adapter.poll(0), Err(Error::Protocol));

        adapter.backend.next_poll = abi::PollWire {
            event: abi::EVENT_CONNECTED,
            status: abi::STATUS_READY,
        };
        assert_eq!(adapter.poll(0), Err(Error::Protocol));
    }

    #[test]
    fn connect_request_debug_redacts_credential_bytes() {
        let request = ConnectRequest::new(
            b"private-network",
            Security::Wpa2Psk,
            b"supersecret-passphrase",
        );
        let debug = format!("{request:?}");

        assert!(debug.contains("ssid_len"));
        assert!(debug.contains("passphrase_len"));
        assert!(!debug.contains("private-network"));
        assert!(!debug.contains("supersecret-passphrase"));
    }

    #[test]
    fn connect_rejects_unescaped_hostap_command_bytes() {
        let mut adapter = Adapter::new(MockBackend::new(abi::STATUS_READY));
        adapter.open().unwrap();

        assert_eq!(
            adapter.connect(ConnectRequest::new(
                b"quoted\"ssid",
                Security::Wpa2Psk,
                b"validpassword",
            )),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            adapter.connect(ConnectRequest::new(
                b"valid-ssid",
                Security::Wpa2Psk,
                b"back\\slash",
            )),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn send_rejects_bad_frames_and_eapol() {
        let mut adapter = connected_adapter();
        assert_eq!(
            adapter.send(&[0; ETHERNET_HEADER_LEN - 1]),
            Err(Error::FrameTooShort)
        );

        let mut oversized = [0u8; MAX_FRAME_LEN];
        oversized[0..6].copy_from_slice(&[0xff; 6]);
        oversized[6..12].copy_from_slice(&[0x02, 1, 2, 3, 4, 5]);
        oversized[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        // The mock interface has a 1500-byte MTU, so 1600 bytes is too large.
        assert_eq!(adapter.send(&oversized), Err(Error::FrameTooLarge));

        let mut eapol = data_frame(EAPOL_ETHERTYPE, 10);
        assert_eq!(adapter.send(&eapol[..24]), Err(Error::EapolFrame));
        eapol[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        eapol[14..16].copy_from_slice(&1u16.to_be_bytes());
        eapol[16..18].copy_from_slice(&EAPOL_ETHERTYPE.to_be_bytes());
        assert_eq!(adapter.send(&eapol[..28]), Err(Error::EapolFrame));

        let frame = data_frame(0x0800, 10);
        assert_eq!(adapter.send(&frame[..24]), Ok(24));
        assert_eq!(adapter.backend.sent_len, 24);

        let mut spoofed = frame;
        spoofed[6] ^= 0x02;
        assert_eq!(adapter.send(&spoofed[..24]), Err(Error::InvalidMac));
    }

    #[test]
    fn receive_filters_eapol_and_validates_data() {
        let mut adapter = connected_adapter();
        let mut buffer = [0u8; MAX_FRAME_LEN];

        adapter
            .backend
            .queue_frame(&data_frame(EAPOL_ETHERTYPE, 10)[..24]);
        assert_eq!(adapter.recv(&mut buffer), Ok(ReceiveResult::Filtered));

        let frame = data_frame(0x0800, 10);
        adapter.backend.queue_frame(&frame[..24]);
        assert_eq!(adapter.recv(&mut buffer), Ok(ReceiveResult::Frame(24)));

        adapter.backend.queue_frame(&[0; ETHERNET_HEADER_LEN - 1]);
        assert_eq!(adapter.recv(&mut buffer), Err(Error::FrameTooShort));

        assert_eq!(
            adapter.recv(&mut [0; ETHERNET_HEADER_LEN - 1]),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn close_is_idempotent_and_drop_closes_once() {
        let mut adapter = Adapter::new(MockBackend::new(abi::STATUS_READY));
        adapter.open().unwrap();
        assert_eq!(adapter.close(), Ok(()));
        assert_eq!(adapter.close(), Ok(()));
        assert_eq!(adapter.backend.close_count, 1);
    }

    #[test]
    fn vlan_eapol_detection_is_bounded() {
        let mut frame = data_frame(0x8100, 8);
        frame[14..16].copy_from_slice(&1u16.to_be_bytes());
        frame[16..18].copy_from_slice(&0x88a8u16.to_be_bytes());
        frame[18..20].copy_from_slice(&2u16.to_be_bytes());
        frame[20..22].copy_from_slice(&EAPOL_ETHERTYPE.to_be_bytes());
        assert!(is_eapol(&frame[..30]));
        assert!(!is_eapol(&frame[..19]));
    }

    #[test]
    fn backend_errors_do_not_escape_as_raw_codes() {
        assert_eq!(map_result(abi::RESULT_EINVAL), Err(Error::InvalidArgument));
        assert_eq!(map_result(abi::RESULT_ENOTCONN), Err(Error::NotConnected));
        assert_eq!(map_result(abi::RESULT_ENETDOWN), Err(Error::NotReady));
        assert_eq!(map_result(abi::RESULT_EPERM), Err(Error::NotConnected));
        assert_eq!(map_result(-12345), Err(Error::Fault));
    }
}
