//! Typed Rust ownership of the nRF70 Wi-Fi control plane.
//!
//! The controller is the only runtime policy owner. Zephyr sees explicit
//! commands and borrowed parameters, then returns observations through fixed
//! queues. Automatic supplicant reconnect and roaming are intentionally left
//! enabled, while their resulting link events remain observable here.

#![cfg_attr(not(feature = "zephyr"), allow(dead_code, unused_variables))]

#[cfg(feature = "zephyr")]
use core::mem::size_of;
#[cfg(feature = "zephyr")]
use core::ptr::null;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "zephyr")]
use super::map_result;
use super::{ConnectRequest, Error, MacAddress, Status, abi};

macro_rules! ffi_call {
    ($call:expr) => {{
        #[cfg(feature = "zephyr")]
        {
            // SAFETY: each call site passes only bounded values or pointers
            // borrowed for the duration of the synchronous ABI call.
            map_result(unsafe { $call })
        }
        #[cfg(not(feature = "zephyr"))]
        {
            Err(Error::Unsupported)
        }
    }};
}

static CONTROL_TAKEN: AtomicBool = AtomicBool::new(false);

/// Maximum number of channel selectors accepted by one scan request.
pub const MAX_SCAN_CHANNELS: usize = abi::MAX_SCAN_CHANNELS;
/// Maximum regulatory-channel records returned without allocation.
pub const MAX_REGULATORY_CHANNELS: usize = abi::MAX_REG_CHANNELS;

/// One independently controlled nRF70 virtual interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceRole {
    Station,
    AccessPoint,
}

impl InterfaceRole {
    pub(crate) const fn to_wire(self) -> u8 {
        match self {
            Self::Station => abi::ROLE_STA,
            Self::AccessPoint => abi::ROLE_AP,
        }
    }

    fn from_wire(value: u8) -> Result<Self, Error> {
        match value {
            abi::ROLE_STA => Ok(Self::Station),
            abi::ROLE_AP => Ok(Self::AccessPoint),
            _ => Err(Error::Protocol),
        }
    }
}

/// A concrete nRF7002 radio band.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Band {
    Ghz2_4,
    Ghz5,
}

impl Band {
    const fn to_wire(self) -> u8 {
        match self {
            Self::Ghz2_4 => abi::BAND_2_4_GHZ,
            Self::Ghz5 => abi::BAND_5_GHZ,
        }
    }

    fn from_wire(value: u8) -> Result<Option<Self>, Error> {
        match value {
            abi::BAND_2_4_GHZ => Ok(Some(Self::Ghz2_4)),
            abi::BAND_5_GHZ => Ok(Some(Self::Ghz5)),
            abi::BAND_ANY => Ok(None),
            _ => Err(Error::Protocol),
        }
    }
}

/// Radio bands included in a scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BandMask(u8);

impl BandMask {
    pub const GHZ_2_4: Self = Self(abi::BAND_MASK_2_4_GHZ);
    pub const GHZ_5: Self = Self(abi::BAND_MASK_5_GHZ);
    pub const BOTH: Self = Self(abi::BAND_MASK_2_4_GHZ | abi::BAND_MASK_5_GHZ);

    pub const fn contains(self, band: Band) -> bool {
        self.0 & (1 << band.to_wire()) != 0
    }
}

/// Requested channel width. `Automatic` explicitly authorizes the mechanism
/// layer to negotiate/select a supported width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelWidth {
    Automatic,
    Mhz20,
    Mhz40,
    Mhz80,
}

impl ChannelWidth {
    pub(crate) const fn to_wire(self) -> u8 {
        match self {
            Self::Automatic => abi::BANDWIDTH_AUTO,
            Self::Mhz20 => abi::BANDWIDTH_20_MHZ,
            Self::Mhz40 => abi::BANDWIDTH_40_MHZ,
            Self::Mhz80 => abi::BANDWIDTH_80_MHZ,
        }
    }
}

/// 802.11 management-frame protection requested by Rust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementFrameProtection {
    Disabled,
    Optional,
    Required,
}

impl ManagementFrameProtection {
    pub(crate) const fn to_wire(self) -> u8 {
        match self {
            Self::Disabled => abi::MFP_DISABLE,
            Self::Optional => abi::MFP_OPTIONAL,
            Self::Required => abi::MFP_REQUIRED,
        }
    }

    fn from_wire(value: u8) -> Result<Self, Error> {
        match value {
            abi::MFP_DISABLE => Ok(Self::Disabled),
            abi::MFP_OPTIONAL => Ok(Self::Optional),
            abi::MFP_REQUIRED => Ok(Self::Required),
            _ => Err(Error::Protocol),
        }
    }
}

/// Hidden-SSID behavior selected for a connection or SoftAP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiddenSsid {
    Visible,
    HideAndZeroLength,
    HideContents,
}

impl HiddenSsid {
    pub(crate) const fn to_wire(self) -> u8 {
        match self {
            Self::Visible => 0,
            Self::HideAndZeroLength => 1,
            Self::HideContents => 2,
        }
    }
}

/// Observed security. Unknown enterprise/WEP/DPP modes remain contained as
/// `Other` rather than exporting a Zephyr enum value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedSecurity {
    Open,
    Wpa2Psk,
    Wpa2PskSha256,
    Wpa3Sae,
    Wpa3SaeH2e,
    Wpa3SaeAutomatic,
    WpaPsk,
    WpaAutomaticPersonal,
    Other,
}

impl ObservedSecurity {
    fn from_wire(value: u8) -> Result<Self, Error> {
        match value {
            abi::SECURITY_OPEN => Ok(Self::Open),
            abi::SECURITY_WPA2_PSK => Ok(Self::Wpa2Psk),
            abi::SECURITY_WPA2_PSK_SHA256 => Ok(Self::Wpa2PskSha256),
            abi::SECURITY_WPA3_SAE => Ok(Self::Wpa3Sae),
            abi::SECURITY_WPA3_SAE_H2E => Ok(Self::Wpa3SaeH2e),
            abi::SECURITY_WPA3_SAE_AUTO => Ok(Self::Wpa3SaeAutomatic),
            abi::SECURITY_WPA_PSK => Ok(Self::WpaPsk),
            abi::SECURITY_WPA_AUTO_PERSONAL => Ok(Self::WpaAutomaticPersonal),
            abi::SECURITY_OTHER => Ok(Self::Other),
            _ => Err(Error::Protocol),
        }
    }
}

/// Fine-grained interface state observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceState {
    Disconnected,
    Disabled,
    Inactive,
    Scanning,
    Authenticating,
    Associating,
    Associated,
    FourWayHandshake,
    GroupHandshake,
    Completed,
    Unknown,
}

impl InterfaceState {
    fn from_wire(value: u8, enabled: bool) -> Self {
        if !enabled {
            return Self::Disabled;
        }
        match value {
            0 => Self::Disconnected,
            1 => Self::Disabled,
            2 => Self::Inactive,
            3 => Self::Scanning,
            4 => Self::Authenticating,
            5 => Self::Associating,
            6 => Self::Associated,
            7 => Self::FourWayHandshake,
            8 => Self::GroupHandshake,
            9 => Self::Completed,
            _ => Self::Unknown,
        }
    }
}

/// Negotiated Wi-Fi generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkMode {
    Legacy,
    Wifi1,
    Wifi2,
    Wifi3,
    Wifi4,
    Wifi5,
    Wifi6,
    Unknown,
}

impl LinkMode {
    fn from_wire(value: u8) -> Self {
        match value {
            0 => Self::Legacy,
            1 => Self::Wifi1,
            2 => Self::Wifi2,
            3 => Self::Wifi3,
            4 => Self::Wifi4,
            5 => Self::Wifi5,
            6 => Self::Wifi6,
            _ => Self::Unknown,
        }
    }
}

/// Compile-time capabilities in the frozen foundation package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WifiCapabilities {
    flags: u64,
    bands: BandMask,
    pub max_sta_associations: u8,
    pub max_ap_clients: u8,
    pub max_virtual_interfaces: u8,
    pub scan_queue_capacity: u16,
}

impl WifiCapabilities {
    const fn has(self, flag: u64) -> bool {
        self.flags & flag != 0
    }

    pub const fn station(self) -> bool {
        self.has(abi::CAP_STA)
    }
    pub const fn softap(self) -> bool {
        self.has(abi::CAP_SOFTAP)
    }
    pub const fn concurrent_sta_ap(self) -> bool {
        self.has(abi::CAP_CONCURRENT_STA_AP)
    }
    pub const fn scan(self) -> bool {
        self.has(abi::CAP_SCAN)
    }
    pub const fn regulatory_domain(self) -> bool {
        self.has(abi::CAP_REG_DOMAIN)
    }
    pub const fn power_save(self) -> bool {
        self.has(abi::CAP_POWER_SAVE)
    }
    pub const fn twt(self) -> bool {
        self.has(abi::CAP_TWT)
    }
    pub const fn raw_l2(self) -> bool {
        self.has(abi::CAP_RAW_L2)
    }
    pub const fn statistics(self) -> bool {
        self.has(abi::CAP_WIFI_STATS)
    }
    pub const fn ap_client_control(self) -> bool {
        self.has(abi::CAP_AP_CLIENT_CONTROL)
    }
    pub const fn runtime_credentials(self) -> bool {
        self.has(abi::CAP_RUNTIME_CREDENTIALS)
    }
    pub const fn bands(self) -> BandMask {
        self.bands
    }
}

/// Detailed status snapshot for one role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WifiStatus {
    pub role: InterfaceRole,
    pub enabled: bool,
    pub state: InterfaceState,
    pub band: Option<Band>,
    pub channel: Option<u16>,
    pub link_mode: LinkMode,
    pub security: ObservedSecurity,
    pub mfp: ManagementFrameProtection,
    pub rssi_dbm: i16,
    pub dtim_period: u8,
    pub twt_capable: bool,
    pub beacon_interval: u16,
    pub phy_rate_kbps: u32,
    ssid: [u8; abi::MAX_SSID_LEN],
    ssid_len: u8,
    pub bssid: Option<MacAddress>,
}

impl WifiStatus {
    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len as usize]
    }

    pub const fn link_status(&self) -> Status {
        if !self.enabled {
            Status::Down
        } else {
            match self.state {
                InterfaceState::Completed => Status::Connected,
                InterfaceState::Scanning
                | InterfaceState::Authenticating
                | InterfaceState::Associating
                | InterfaceState::Associated
                | InterfaceState::FourWayHandshake
                | InterfaceState::GroupHandshake => Status::Connecting,
                InterfaceState::Inactive => Status::Ready,
                InterfaceState::Disconnected => Status::Disconnected,
                InterfaceState::Disabled | InterfaceState::Unknown => Status::Down,
            }
        }
    }
}

/// One explicit band/channel scan selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BandChannel {
    pub band: Band,
    pub channel: u8,
}

impl BandChannel {
    pub const fn new(band: Band, channel: u8) -> Self {
        Self { band, channel }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanType {
    Active,
    Passive,
}

/// Borrowed scan policy. Every field is copied by the bridge before this call
/// returns; no Rust pointer is retained during the asynchronous scan.
#[derive(Clone, Copy, Debug)]
pub struct ScanRequest<'a> {
    pub scan_type: ScanType,
    pub bands: BandMask,
    pub ssid_filter: Option<&'a [u8]>,
    pub channels: &'a [BandChannel],
    pub active_dwell_ms: u16,
    pub passive_dwell_ms: u16,
    pub max_results: u16,
}

impl<'a> ScanRequest<'a> {
    pub const fn new() -> Self {
        Self {
            scan_type: ScanType::Active,
            bands: BandMask::BOTH,
            ssid_filter: None,
            channels: &[],
            active_dwell_ms: 0,
            passive_dwell_ms: 0,
            max_results: 0,
        }
    }
}

impl Default for ScanRequest<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanResult {
    ssid: [u8; abi::MAX_SSID_LEN],
    ssid_len: u8,
    pub band: Band,
    pub channel: u8,
    pub security: ObservedSecurity,
    pub mfp: ManagementFrameProtection,
    pub rssi_dbm: i8,
    pub bssid: MacAddress,
}

impl ScanResult {
    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len as usize]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanProgress {
    Pending {
        dropped_results: u32,
    },
    Result {
        network: ScanResult,
        dropped_results: u32,
    },
    Complete {
        outcome: Result<(), Error>,
        dropped_results: u32,
    },
}

/// SoftAP configuration selected entirely by Rust.
#[derive(Clone, Copy, Debug)]
pub struct AccessPointConfig<'a> {
    pub connection: ConnectRequest<'a>,
    pub max_clients: u8,
    pub max_inactivity_s: u32,
}

impl<'a> AccessPointConfig<'a> {
    pub const fn new(connection: ConnectRequest<'a>) -> Self {
        Self {
            connection,
            max_clients: 1,
            max_inactivity_s: 0,
        }
    }
}

/// Validated ISO/IEC 3166-1 alpha-2 regulatory code, or `00` world domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountryCode([u8; abi::COUNTRY_LEN]);

impl CountryCode {
    pub const WORLD: Self = Self(*b"00");

    pub const fn new(mut bytes: [u8; 2]) -> Result<Self, Error> {
        let mut index = 0;
        while index < 2 {
            if bytes[index] >= b'a' && bytes[index] <= b'z' {
                bytes[index] -= b'a' - b'A';
            }
            index += 1;
        }
        let world = bytes[0] == b'0' && bytes[1] == b'0';
        let letters = bytes[0] >= b'A' && bytes[0] <= b'Z' && bytes[1] >= b'A' && bytes[1] <= b'Z';
        if world || letters {
            Ok(Self(bytes))
        } else {
            Err(Error::InvalidArgument)
        }
    }

    pub const fn as_bytes(self) -> [u8; 2] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegulatoryChannel {
    pub center_frequency_mhz: u16,
    pub max_power_dbm: i8,
    pub supported: bool,
    pub passive_only: bool,
    pub dfs: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegulatoryDomain {
    pub country: CountryCode,
    pub total_channels: usize,
    pub written_channels: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerSaveMode {
    Legacy,
    Wmm,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerWakeup {
    Dtim,
    ListenInterval,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerExitStrategy {
    CustomAlgorithm,
    EveryTim,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerSaveParameter {
    Enabled(bool),
    ListenInterval(u16),
    Wakeup(PowerWakeup),
    Mode(PowerSaveMode),
    ExitStrategy(PowerExitStrategy),
    TimeoutMs(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowerSaveConfig {
    pub enabled: bool,
    pub wakeup: PowerWakeup,
    pub mode: PowerSaveMode,
    pub exit_strategy: PowerExitStrategy,
    pub listen_interval: u16,
    pub timeout_ms: u32,
    pub twt_flow_count: u8,
    pub twt_flow_mask: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwtNegotiation {
    Individual,
    Broadcast,
    WakeTbtt,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwtSetupCommand {
    Request,
    Suggest,
    Demand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwtSetup {
    pub interval_us: u64,
    pub wake_interval_us: u32,
    pub wake_ahead_us: u32,
    pub flow_id: u8,
    pub negotiation: TwtNegotiation,
    pub command: TwtSetupCommand,
    pub dialog_token: u8,
    pub trigger: bool,
    pub implicit: bool,
    pub announce: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WifiStatistics {
    pub beacons_received: u64,
    pub beacons_missed: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub overruns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlEventKind {
    Connected,
    ConnectionFailed,
    Disconnected,
    InterfaceUp,
    InterfaceDown,
    AccessPointStarted,
    AccessPointStopped,
    AccessPointClientJoined,
    AccessPointClientLeft,
    Twt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionFailure {
    Generic,
    WrongPassphrase,
    TimedOut,
    AccessPointNotFound,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectionReason {
    Success,
    Unspecified,
    Requested,
    AccessPointLeaving,
    Inactivity,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessPointFailure {
    Generic,
    ChannelNotSupported,
    ChannelNotAllowed,
    SsidNotAllowed,
    SecurityNotSupported,
    Unsupported,
    NotPermitted,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwtFailure {
    Unspecified,
    CommandFailed,
    Unsupported,
    StatusUnavailable,
    NotConnected,
    PeerNotWifi6,
    PeerNotTwtCapable,
    InProgress,
    InvalidFlow,
    IpUnavailable,
    FlowAlreadyExists,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwtEventOperation {
    Setup,
    Teardown,
}

/// Stable interpretation of a management event result. No Zephyr enum or
/// numeric status escapes the crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlEventStatus {
    Success,
    ConnectionFailed(ConnectionFailure),
    Disconnected(DisconnectionReason),
    AccessPointFailed(AccessPointFailure),
    TwtFailed(TwtFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlEvent {
    pub kind: ControlEventKind,
    pub role: InterfaceRole,
    pub status: ControlEventStatus,
    pub peer: Option<MacAddress>,
    pub peer_link_mode: Option<LinkMode>,
    pub peer_twt_capable: Option<bool>,
    pub twt_flow_id: Option<u8>,
    pub twt_operation: Option<TwtEventOperation>,
    /// Cumulative events dropped because Rust did not drain the fixed queue
    /// quickly enough. Query [`WifiController::status`] to resynchronize.
    pub dropped_events: u32,
}

/// Exclusive Rust command owner. The packet reactor may continue running on
/// another Embassy task; Zephyr serializes its own management operations.
pub struct WifiController {
    capabilities: WifiCapabilities,
}

impl WifiController {
    pub fn take() -> Result<Self, Error> {
        if CONTROL_TAKEN
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Busy);
        }
        let result = Self::initialize();
        if result.is_err() {
            CONTROL_TAKEN.store(false, Ordering::Release);
        }
        result
    }

    fn initialize() -> Result<Self, Error> {
        #[cfg(feature = "zephyr")]
        {
            if unsafe { abi::embassy_zephyr_nrf7002_l2_abi_version() } != abi::ABI_VERSION {
                return Err(Error::AbiMismatch);
            }
            map_result(unsafe { abi::embassy_zephyr_nrf7002_wifi_control_init() })?;
            let mut wire = abi::CapabilitiesWire {
                abi_version: 0,
                struct_size: 0,
                flags: 0,
                bands: 0,
                max_sta_associations: 0,
                max_ap_clients: 0,
                max_virtual_interfaces: 0,
                scan_queue_capacity: 0,
                reserved: 0,
            };
            map_result(unsafe { abi::embassy_zephyr_nrf7002_wifi_capabilities(&mut wire) })?;
            verify_wire(
                wire.abi_version,
                wire.struct_size,
                size_of::<abi::CapabilitiesWire>(),
            )?;
            let known_bands = abi::BAND_MASK_2_4_GHZ | abi::BAND_MASK_5_GHZ;
            let band_flags = (wire.flags & abi::CAP_BAND_2_4_GHZ != 0) as u8
                | (((wire.flags & abi::CAP_BAND_5_GHZ != 0) as u8) << 1);
            if wire.bands == 0
                || wire.bands & !known_bands != 0
                || wire.bands != band_flags
                || (wire.flags & abi::CAP_STA != 0) != (wire.max_sta_associations != 0)
                || (wire.flags & abi::CAP_SOFTAP != 0) != (wire.max_ap_clients != 0)
                || wire.max_virtual_interfaces == 0
            {
                return Err(Error::Protocol);
            }
            return Ok(Self {
                capabilities: WifiCapabilities {
                    flags: wire.flags,
                    bands: BandMask(wire.bands),
                    max_sta_associations: wire.max_sta_associations,
                    max_ap_clients: wire.max_ap_clients,
                    max_virtual_interfaces: wire.max_virtual_interfaces,
                    scan_queue_capacity: wire.scan_queue_capacity,
                },
            });
        }
        #[cfg(not(feature = "zephyr"))]
        Err(Error::Unsupported)
    }

    pub const fn capabilities(&self) -> WifiCapabilities {
        self.capabilities
    }

    pub fn set_enabled(&mut self, role: InterfaceRole, enabled: bool) -> Result<(), Error> {
        ffi_call!(abi::embassy_zephyr_nrf7002_wifi_set_enabled(
            role.to_wire(),
            enabled as u8
        ))
    }

    pub fn status(&mut self, role: InterfaceRole) -> Result<WifiStatus, Error> {
        #[cfg(feature = "zephyr")]
        {
            let mut wire: abi::StatusWire = unsafe { core::mem::zeroed() };
            map_result(unsafe {
                abi::embassy_zephyr_nrf7002_wifi_status(role.to_wire(), &mut wire)
            })?;
            verify_wire(
                wire.abi_version,
                wire.struct_size,
                size_of::<abi::StatusWire>(),
            )?;
            if wire.role != role.to_wire()
                || wire.enabled > 1
                || wire.twt_capable > 1
                || wire.ssid_len as usize > abi::MAX_SSID_LEN
            {
                return Err(Error::Protocol);
            }
            let enabled = wire.enabled != 0;
            let bssid = MacAddress::new(wire.bssid).ok();
            return Ok(WifiStatus {
                role,
                enabled,
                state: InterfaceState::from_wire(wire.state, enabled),
                band: Band::from_wire(wire.band)?,
                channel: (wire.channel != 0 && wire.channel != abi::CHANNEL_ANY as u16)
                    .then_some(wire.channel),
                link_mode: LinkMode::from_wire(wire.link_mode),
                security: ObservedSecurity::from_wire(wire.security)?,
                mfp: ManagementFrameProtection::from_wire(wire.mfp)?,
                rssi_dbm: wire.rssi_dbm,
                dtim_period: wire.dtim_period,
                twt_capable: wire.twt_capable != 0,
                beacon_interval: wire.beacon_interval,
                phy_rate_kbps: wire.phy_rate_kbps,
                ssid: wire.ssid,
                ssid_len: wire.ssid_len,
                bssid,
            });
        }
        #[cfg(not(feature = "zephyr"))]
        {
            let _ = role;
            Err(Error::Unsupported)
        }
    }

    pub fn start_scan(
        &mut self,
        role: InterfaceRole,
        request: ScanRequest<'_>,
    ) -> Result<(), Error> {
        validate_scan(&request)?;
        #[cfg(feature = "zephyr")]
        {
            let mut channels = [abi::BandChannelWire {
                band: 0,
                channel: 0,
            }; abi::MAX_SCAN_CHANNELS];
            for (wire, selected) in channels.iter_mut().zip(request.channels.iter()) {
                *wire = abi::BandChannelWire {
                    band: selected.band.to_wire(),
                    channel: selected.channel,
                };
            }
            let (ssid, ssid_len) = request
                .ssid_filter
                .map(|value| (value.as_ptr(), value.len() as u32))
                .unwrap_or((null(), 0));
            let wire = abi::ScanParamsWire {
                ssid,
                ssid_len,
                channels: if request.channels.is_empty() {
                    null()
                } else {
                    channels.as_ptr()
                },
                channel_count: request.channels.len() as u32,
                dwell_time_active_ms: request.active_dwell_ms,
                dwell_time_passive_ms: request.passive_dwell_ms,
                max_results: request.max_results,
                scan_type: match request.scan_type {
                    ScanType::Active => 0,
                    ScanType::Passive => 1,
                },
                bands: request.bands.0,
            };
            return map_result(unsafe {
                abi::embassy_zephyr_nrf7002_wifi_scan_start(role.to_wire(), &wire)
            });
        }
        #[cfg(not(feature = "zephyr"))]
        {
            let _ = role;
            Err(Error::Unsupported)
        }
    }

    pub fn poll_scan(&mut self) -> Result<ScanProgress, Error> {
        #[cfg(feature = "zephyr")]
        {
            let mut wire: abi::ScanPollWire = unsafe { core::mem::zeroed() };
            map_result(unsafe { abi::embassy_zephyr_nrf7002_wifi_scan_poll(&mut wire) })?;
            verify_wire(
                wire.abi_version,
                wire.struct_size,
                size_of::<abi::ScanPollWire>(),
            )?;
            return match wire.kind {
                abi::SCAN_PENDING => Ok(ScanProgress::Pending {
                    dropped_results: wire.dropped_results,
                }),
                abi::SCAN_COMPLETE => Ok(ScanProgress::Complete {
                    outcome: map_result(wire.status),
                    dropped_results: wire.dropped_results,
                }),
                abi::SCAN_RESULT => Ok(ScanProgress::Result {
                    network: scan_result_from_wire(wire.result)?,
                    dropped_results: wire.dropped_results,
                }),
                _ => Err(Error::Protocol),
            };
        }
        #[cfg(not(feature = "zephyr"))]
        Err(Error::Unsupported)
    }

    pub fn connect(&mut self, request: ConnectRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        #[cfg(feature = "zephyr")]
        {
            let wire = connect_wire(request);
            return map_result(unsafe {
                abi::embassy_zephyr_nrf7002_wifi_connect(abi::ROLE_STA, &wire)
            });
        }
        #[cfg(not(feature = "zephyr"))]
        Err(Error::Unsupported)
    }

    pub fn disconnect(&mut self, role: InterfaceRole) -> Result<(), Error> {
        ffi_call!(abi::embassy_zephyr_nrf7002_wifi_disconnect(role.to_wire()))
    }

    pub fn start_access_point(&mut self, config: AccessPointConfig<'_>) -> Result<(), Error> {
        config.connection.validate()?;
        if config.max_clients != 1
            || config.connection.band().is_none()
            || config.connection.channel().is_none()
        {
            return Err(Error::InvalidArgument);
        }
        #[cfg(feature = "zephyr")]
        {
            let wire = abi::ApParamsWire {
                connection: connect_wire(config.connection),
                max_inactivity_s: config.max_inactivity_s,
                max_clients: config.max_clients,
                reserved: [0; 3],
            };
            return map_result(unsafe { abi::embassy_zephyr_nrf7002_wifi_ap_start(&wire) });
        }
        #[cfg(not(feature = "zephyr"))]
        Err(Error::Unsupported)
    }

    pub fn stop_access_point(&mut self) -> Result<(), Error> {
        ffi_call!(abi::embassy_zephyr_nrf7002_wifi_ap_stop())
    }

    pub fn disconnect_access_point_client(&mut self, mac: MacAddress) -> Result<(), Error> {
        ffi_call!(abi::embassy_zephyr_nrf7002_wifi_ap_disconnect_client(
            mac.as_bytes().as_ptr()
        ))
    }

    pub fn set_country(
        &mut self,
        role: InterfaceRole,
        country: CountryCode,
        force: bool,
    ) -> Result<(), Error> {
        let bytes = country.as_bytes();
        ffi_call!(abi::embassy_zephyr_nrf7002_wifi_set_country(
            role.to_wire(),
            bytes.as_ptr(),
            force as u8
        ))
    }

    pub fn regulatory_domain(
        &mut self,
        role: InterfaceRole,
        output: &mut [RegulatoryChannel],
    ) -> Result<RegulatoryDomain, Error> {
        #[cfg(feature = "zephyr")]
        {
            let mut country = [0; abi::COUNTRY_LEN];
            let mut count = 0u32;
            let mut wire = [abi::RegChannelWire::default(); abi::MAX_REG_CHANNELS];
            map_result(unsafe {
                abi::embassy_zephyr_nrf7002_wifi_get_reg_domain(
                    role.to_wire(),
                    country.as_mut_ptr(),
                    wire.as_mut_ptr(),
                    wire.len() as u32,
                    &mut count,
                )
            })?;
            if count as usize > abi::MAX_REG_CHANNELS {
                return Err(Error::Protocol);
            }
            let written = core::cmp::min(output.len(), count as usize);
            for (destination, source) in output.iter_mut().zip(wire.iter()).take(written) {
                *destination = RegulatoryChannel {
                    center_frequency_mhz: source.center_frequency_mhz,
                    max_power_dbm: source.max_power_dbm,
                    supported: source.flags & abi::REG_SUPPORTED != 0,
                    passive_only: source.flags & abi::REG_PASSIVE_ONLY != 0,
                    dfs: source.flags & abi::REG_DFS != 0,
                };
            }
            return Ok(RegulatoryDomain {
                country: CountryCode::new(country)?,
                total_channels: count as usize,
                written_channels: written,
            });
        }
        #[cfg(not(feature = "zephyr"))]
        {
            let _ = (role, output);
            Err(Error::Unsupported)
        }
    }

    pub fn set_power_save(&mut self, parameter: PowerSaveParameter) -> Result<(), Error> {
        let wire = match parameter {
            PowerSaveParameter::Enabled(value) => abi::PowerParamWire {
                parameter: 0,
                value8: value as u8,
                value16: 0,
                value32: 0,
            },
            PowerSaveParameter::ListenInterval(value) => abi::PowerParamWire {
                parameter: 1,
                value8: 0,
                value16: value,
                value32: 0,
            },
            PowerSaveParameter::Wakeup(value) => abi::PowerParamWire {
                parameter: 2,
                value8: match value {
                    PowerWakeup::Dtim => 0,
                    PowerWakeup::ListenInterval => 1,
                },
                value16: 0,
                value32: 0,
            },
            PowerSaveParameter::Mode(value) => abi::PowerParamWire {
                parameter: 3,
                value8: match value {
                    PowerSaveMode::Legacy => 0,
                    PowerSaveMode::Wmm => 1,
                },
                value16: 0,
                value32: 0,
            },
            PowerSaveParameter::ExitStrategy(value) => abi::PowerParamWire {
                parameter: 4,
                value8: match value {
                    PowerExitStrategy::CustomAlgorithm => 0,
                    PowerExitStrategy::EveryTim => 1,
                },
                value16: 0,
                value32: 0,
            },
            PowerSaveParameter::TimeoutMs(value) => abi::PowerParamWire {
                parameter: 5,
                value8: 0,
                value16: 0,
                value32: value,
            },
        };
        ffi_call!(abi::embassy_zephyr_nrf7002_wifi_set_power(&wire))
    }

    pub fn power_save(&mut self) -> Result<PowerSaveConfig, Error> {
        #[cfg(feature = "zephyr")]
        {
            let mut wire: abi::PowerConfigWire = unsafe { core::mem::zeroed() };
            map_result(unsafe { abi::embassy_zephyr_nrf7002_wifi_get_power(&mut wire) })?;
            verify_wire(
                wire.abi_version,
                wire.struct_size,
                size_of::<abi::PowerConfigWire>(),
            )?;
            return Ok(PowerSaveConfig {
                enabled: match wire.enabled {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Protocol),
                },
                wakeup: match wire.wakeup_mode {
                    0 => PowerWakeup::Dtim,
                    1 => PowerWakeup::ListenInterval,
                    _ => return Err(Error::Protocol),
                },
                mode: match wire.mode {
                    0 => PowerSaveMode::Legacy,
                    1 => PowerSaveMode::Wmm,
                    _ => return Err(Error::Protocol),
                },
                exit_strategy: match wire.exit_strategy {
                    0 => PowerExitStrategy::CustomAlgorithm,
                    1 => PowerExitStrategy::EveryTim,
                    _ => return Err(Error::Protocol),
                },
                listen_interval: wire.listen_interval,
                timeout_ms: wire.timeout_ms,
                twt_flow_count: wire.twt_flow_count,
                twt_flow_mask: wire.twt_flow_mask,
            });
        }
        #[cfg(not(feature = "zephyr"))]
        Err(Error::Unsupported)
    }

    pub fn setup_twt(&mut self, setup: TwtSetup) -> Result<(), Error> {
        if setup.flow_id >= 8 || setup.interval_us == 0 || setup.wake_interval_us == 0 {
            return Err(Error::InvalidArgument);
        }
        let wire = abi::TwtSetupWire {
            interval_us: setup.interval_us,
            wake_interval_us: setup.wake_interval_us,
            wake_ahead_us: setup.wake_ahead_us,
            flow_id: setup.flow_id,
            negotiation_type: match setup.negotiation {
                TwtNegotiation::Individual => 0,
                TwtNegotiation::Broadcast => 1,
                TwtNegotiation::WakeTbtt => 2,
            },
            setup_command: match setup.command {
                TwtSetupCommand::Request => 0,
                TwtSetupCommand::Suggest => 1,
                TwtSetupCommand::Demand => 2,
            },
            dialog_token: setup.dialog_token,
            trigger: setup.trigger as u8,
            implicit: setup.implicit as u8,
            announce: setup.announce as u8,
            reserved: 0,
        };
        ffi_call!(abi::embassy_zephyr_nrf7002_wifi_twt_setup(&wire))
    }

    pub fn teardown_twt(&mut self, flow: Option<u8>) -> Result<(), Error> {
        if flow.is_some_and(|id| id >= 8) {
            return Err(Error::InvalidArgument);
        }
        ffi_call!(abi::embassy_zephyr_nrf7002_wifi_twt_teardown(
            flow.unwrap_or(0),
            flow.is_none() as u8
        ))
    }

    pub fn statistics(&mut self, role: InterfaceRole) -> Result<WifiStatistics, Error> {
        #[cfg(feature = "zephyr")]
        {
            let mut wire: abi::StatsWire = unsafe { core::mem::zeroed() };
            map_result(unsafe {
                abi::embassy_zephyr_nrf7002_wifi_get_stats(role.to_wire(), &mut wire)
            })?;
            verify_wire(
                wire.abi_version,
                wire.struct_size,
                size_of::<abi::StatsWire>(),
            )?;
            return Ok(WifiStatistics {
                beacons_received: wire.beacons_received,
                beacons_missed: wire.beacons_missed,
                rx_bytes: wire.rx_bytes,
                tx_bytes: wire.tx_bytes,
                rx_packets: wire.rx_packets,
                tx_packets: wire.tx_packets,
                rx_errors: wire.rx_errors,
                tx_errors: wire.tx_errors,
                overruns: wire.overruns,
            });
        }
        #[cfg(not(feature = "zephyr"))]
        {
            let _ = role;
            Err(Error::Unsupported)
        }
    }

    pub fn reset_statistics(&mut self, role: InterfaceRole) -> Result<(), Error> {
        ffi_call!(abi::embassy_zephyr_nrf7002_wifi_reset_stats(role.to_wire()))
    }

    pub fn poll_event(&mut self) -> Result<ControlEvent, Error> {
        #[cfg(feature = "zephyr")]
        {
            let mut wire: abi::EventWire = unsafe { core::mem::zeroed() };
            map_result(unsafe { abi::embassy_zephyr_nrf7002_wifi_event_poll(&mut wire) })?;
            verify_wire(
                wire.abi_version,
                wire.struct_size,
                size_of::<abi::EventWire>(),
            )?;
            if wire.peer_mac_set > 1 {
                return Err(Error::Protocol);
            }
            let kind = match wire.event {
                abi::EVENT_CONNECTED => ControlEventKind::Connected,
                abi::EVENT_CONNECTION_FAILED => ControlEventKind::ConnectionFailed,
                abi::EVENT_DISCONNECTED => ControlEventKind::Disconnected,
                abi::EVENT_INTERFACE_UP => ControlEventKind::InterfaceUp,
                abi::EVENT_INTERFACE_DOWN => ControlEventKind::InterfaceDown,
                abi::EVENT_AP_STARTED => ControlEventKind::AccessPointStarted,
                abi::EVENT_AP_STOPPED => ControlEventKind::AccessPointStopped,
                abi::EVENT_AP_CLIENT_JOINED => ControlEventKind::AccessPointClientJoined,
                abi::EVENT_AP_CLIENT_LEFT => ControlEventKind::AccessPointClientLeft,
                abi::EVENT_TWT => ControlEventKind::Twt,
                _ => return Err(Error::Protocol),
            };
            let peer_event = matches!(
                kind,
                ControlEventKind::AccessPointClientJoined | ControlEventKind::AccessPointClientLeft
            );
            if (wire.peer_mac_set != 0) != peer_event {
                return Err(Error::Protocol);
            }
            let twt_event = kind == ControlEventKind::Twt;
            if peer_event && wire.value1 > 1 || twt_event && (wire.value0 >= 8 || wire.value1 > 1) {
                return Err(Error::Protocol);
            }
            return Ok(ControlEvent {
                kind,
                role: InterfaceRole::from_wire(wire.role)?,
                status: event_status(kind, wire.status)?,
                peer: if wire.peer_mac_set != 0 {
                    Some(MacAddress::new(wire.peer_mac)?)
                } else {
                    None
                },
                peer_link_mode: peer_event.then(|| LinkMode::from_wire(wire.value0 as u8)),
                peer_twt_capable: peer_event.then_some(wire.value1 != 0),
                twt_flow_id: twt_event.then_some(wire.value0 as u8),
                twt_operation: if twt_event {
                    Some(match wire.value1 {
                        0 => TwtEventOperation::Setup,
                        1 => TwtEventOperation::Teardown,
                        _ => return Err(Error::Protocol),
                    })
                } else {
                    None
                },
                dropped_events: wire.dropped_events,
            });
        }
        #[cfg(not(feature = "zephyr"))]
        Err(Error::Unsupported)
    }
}

fn event_status(kind: ControlEventKind, status: i32) -> Result<ControlEventStatus, Error> {
    match kind {
        ControlEventKind::Connected
        | ControlEventKind::InterfaceUp
        | ControlEventKind::InterfaceDown
        | ControlEventKind::AccessPointClientJoined
        | ControlEventKind::AccessPointClientLeft
            if status == 0 =>
        {
            Ok(ControlEventStatus::Success)
        }
        ControlEventKind::ConnectionFailed => {
            Ok(ControlEventStatus::ConnectionFailed(match status {
                1 => ConnectionFailure::Generic,
                2 => ConnectionFailure::WrongPassphrase,
                3 => ConnectionFailure::TimedOut,
                4 => ConnectionFailure::AccessPointNotFound,
                _ => ConnectionFailure::Unknown,
            }))
        }
        ControlEventKind::Disconnected => Ok(ControlEventStatus::Disconnected(match status {
            0 => DisconnectionReason::Success,
            1 => DisconnectionReason::Unspecified,
            2 => DisconnectionReason::Requested,
            3 => DisconnectionReason::AccessPointLeaving,
            4 => DisconnectionReason::Inactivity,
            _ => DisconnectionReason::Unknown,
        })),
        ControlEventKind::AccessPointStarted | ControlEventKind::AccessPointStopped => {
            if status == 0 {
                Ok(ControlEventStatus::Success)
            } else {
                Ok(ControlEventStatus::AccessPointFailed(match status {
                    1 => AccessPointFailure::Generic,
                    2 => AccessPointFailure::ChannelNotSupported,
                    3 => AccessPointFailure::ChannelNotAllowed,
                    4 => AccessPointFailure::SsidNotAllowed,
                    5 => AccessPointFailure::SecurityNotSupported,
                    6 => AccessPointFailure::Unsupported,
                    7 => AccessPointFailure::NotPermitted,
                    _ => AccessPointFailure::Unknown,
                }))
            }
        }
        ControlEventKind::Twt => {
            if status == 0 {
                Ok(ControlEventStatus::Success)
            } else {
                Ok(ControlEventStatus::TwtFailed(match status {
                    1 => TwtFailure::CommandFailed,
                    2 => TwtFailure::Unsupported,
                    3 => TwtFailure::StatusUnavailable,
                    4 => TwtFailure::NotConnected,
                    5 => TwtFailure::PeerNotWifi6,
                    6 => TwtFailure::PeerNotTwtCapable,
                    7 => TwtFailure::InProgress,
                    8 => TwtFailure::InvalidFlow,
                    9 => TwtFailure::IpUnavailable,
                    10 => TwtFailure::FlowAlreadyExists,
                    _ => TwtFailure::Unknown,
                }))
            }
        }
        _ => Err(Error::Protocol),
    }
}

impl Drop for WifiController {
    fn drop(&mut self) {
        CONTROL_TAKEN.store(false, Ordering::Release);
    }
}

fn validate_scan(request: &ScanRequest<'_>) -> Result<(), Error> {
    if request.bands.0 == 0
        || request.bands.0 & !BandMask::BOTH.0 != 0
        || request.channels.len() > abi::MAX_SCAN_CHANNELS
        || request
            .ssid_filter
            .is_some_and(|ssid| ssid.is_empty() || ssid.len() > abi::MAX_SSID_LEN)
        || request
            .channels
            .iter()
            .any(|entry| entry.channel == 0 || entry.channel >= abi::CHANNEL_ANY)
    {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn scan_result_from_wire(wire: abi::ScanResultWire) -> Result<ScanResult, Error> {
    if wire.ssid_len as usize > abi::MAX_SSID_LEN || wire.bssid_len as usize != abi::MAC_LEN {
        return Err(Error::Protocol);
    }
    Ok(ScanResult {
        ssid: wire.ssid,
        ssid_len: wire.ssid_len,
        band: Band::from_wire(wire.band)?.ok_or(Error::Protocol)?,
        channel: wire.channel,
        security: ObservedSecurity::from_wire(wire.security)?,
        mfp: ManagementFrameProtection::from_wire(wire.mfp)?,
        rssi_dbm: wire.rssi_dbm,
        bssid: MacAddress::new(wire.bssid)?,
    })
}

pub(crate) fn connect_wire(request: ConnectRequest<'_>) -> abi::ConnectParamsWire {
    abi::ConnectParamsWire {
        ssid: request.ssid().as_ptr(),
        ssid_len: request.ssid().len() as u32,
        psk: request.passphrase().as_ptr(),
        psk_len: request.passphrase().len() as u32,
        bssid: request
            .bssid()
            .map(|value| *value.as_bytes())
            .unwrap_or([0; abi::MAC_LEN]),
        security: request.security().to_wire(),
        mfp: request.mfp().to_wire(),
        band: request.band().map(Band::to_wire).unwrap_or(abi::BAND_ANY),
        channel: request.channel().unwrap_or(abi::CHANNEL_ANY),
        bandwidth: request.channel_width().to_wire(),
        hidden_ssid: request.hidden_ssid().to_wire(),
        bssid_set: request.bssid().is_some() as u8,
        reserved: 0,
        timeout_ms: request.timeout_ms(),
    }
}

fn verify_wire(version: u32, struct_size: u32, expected: usize) -> Result<(), Error> {
    if version == abi::ABI_VERSION && struct_size as usize == expected {
        Ok(())
    } else {
        Err(Error::AbiMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_codes_are_normalized_and_validated() {
        assert_eq!(CountryCode::new(*b"us").unwrap().as_bytes(), *b"US");
        assert_eq!(CountryCode::new(*b"00").unwrap(), CountryCode::WORLD);
        assert_eq!(CountryCode::new(*b"U1"), Err(Error::InvalidArgument));
    }

    #[test]
    fn scan_rejects_oversized_channel_list() {
        let channels = [BandChannel::new(Band::Ghz2_4, 1); MAX_SCAN_CHANNELS + 1];
        let mut request = ScanRequest::new();
        request.channels = &channels;
        assert_eq!(validate_scan(&request), Err(Error::InvalidArgument));
    }

    #[test]
    fn event_statuses_are_stable_rust_enums() {
        assert_eq!(
            event_status(ControlEventKind::ConnectionFailed, 2),
            Ok(ControlEventStatus::ConnectionFailed(
                ConnectionFailure::WrongPassphrase
            ))
        );
        assert_eq!(
            event_status(ControlEventKind::Disconnected, 2),
            Ok(ControlEventStatus::Disconnected(
                DisconnectionReason::Requested
            ))
        );
        assert_eq!(
            event_status(ControlEventKind::AccessPointStarted, 3),
            Ok(ControlEventStatus::AccessPointFailed(
                AccessPointFailure::ChannelNotAllowed
            ))
        );
        assert_eq!(
            event_status(ControlEventKind::InterfaceUp, 1),
            Err(Error::Protocol)
        );
    }
}
