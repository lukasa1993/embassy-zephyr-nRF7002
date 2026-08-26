//! Packed host/RPU protocol codecs.
//!
//! All encoders write fields explicitly in little-endian order. No C ABI,
//! bindgen output, unaligned reference, or transmute is used.

/// Common host message header length.
pub const HOST_MESSAGE_HEADER_LEN: usize = 12;
/// Packed UMAC command/event header length.
pub const UMAC_HEADER_LEN: usize = 36;
/// Packed system initialization command length, without the outer host header.
pub const SYSTEM_INIT_LEN: usize = 366;
/// Maximum command/event buffer used by the native control path.
pub const MAX_CONTROL_MESSAGE_LEN: usize = 1024;
/// HPQM descriptor block length.
pub const HPQM_INFO_LEN: usize = 56;
/// Maximum SSID length.
pub const MAX_SSID_LEN: usize = 32;
/// Maximum scan IE storage in Nordic's wire structure.
pub const MAX_SCAN_IE_LEN: usize = 400;
/// Maximum scan SSID count.
pub const MAX_SCAN_SSIDS: usize = 2;
/// Maximum scan frequency count.
pub const MAX_SCAN_FREQUENCIES: usize = 64;
/// nRF70 RF parameter byte count.
pub const RF_PARAMS_LEN: usize = 200;
/// Number of firmware RX pools.
pub const RX_POOL_COUNT: usize = 3;

/// Codec failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// Caller storage is too small.
    BufferTooSmall,
    /// A declared length is invalid.
    InvalidLength,
    /// A numeric command or event value is not supported by this codec.
    InvalidValue(u32),
    /// A fixed-capacity field exceeds its wire limit.
    LimitExceeded,
    /// A message type does not match the expected protocol layer.
    WrongMessageType,
}

/// Top-level host/RPU message category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum HostMessageType {
    /// System configuration and status.
    System = 0,
    /// Reserved supplicant channel.
    Supplicant = 1,
    /// Data path.
    Data = 2,
    /// UMAC control path.
    Umac = 3,
}

impl HostMessageType {
    fn from_i32(value: i32) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::System),
            1 => Ok(Self::Supplicant),
            2 => Ok(Self::Data),
            3 => Ok(Self::Umac),
            other => Err(ProtocolError::InvalidValue(other as u32)),
        }
    }
}

/// Borrowed parsed host message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostMessageRef<'a> {
    /// Whether firmware asks the host to return the event buffer.
    pub resubmit: bool,
    /// Message category.
    pub message_type: HostMessageType,
    /// Category-specific packed body.
    pub payload: &'a [u8],
}

/// Encodes one complete host message.
pub fn encode_host_message(
    out: &mut [u8],
    message_type: HostMessageType,
    resubmit: bool,
    payload: &[u8],
) -> Result<usize, ProtocolError> {
    let total = HOST_MESSAGE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if total > out.len() || total > u32::MAX as usize {
        return Err(ProtocolError::BufferTooSmall);
    }
    let mut writer = Writer::new(out);
    writer.u32(total as u32)?;
    writer.u32(bool_u32(resubmit))?;
    writer.i32(message_type as i32)?;
    writer.bytes(payload)?;
    Ok(writer.len())
}

/// Parses one complete host message from a larger event scratch buffer.
pub fn parse_host_message(bytes: &[u8]) -> Result<HostMessageRef<'_>, ProtocolError> {
    if bytes.len() < HOST_MESSAGE_HEADER_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let declared = read_u32(bytes, 0) as usize;
    if declared < HOST_MESSAGE_HEADER_LEN || declared > bytes.len() {
        return Err(ProtocolError::InvalidLength);
    }
    let resubmit = read_u32(bytes, 4) != 0;
    let message_type = HostMessageType::from_i32(read_i32(bytes, 8))?;
    Ok(HostMessageRef {
        resubmit,
        message_type,
        payload: &bytes[HOST_MESSAGE_HEADER_LEN..declared],
    })
}

/// One host port queue descriptor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Hpq {
    /// Queue push register.
    pub enqueue_address: u32,
    /// Queue pop register.
    pub dequeue_address: u32,
}

/// Queue map published by firmware at `RPU_MEM_HPQ_INFO`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HpqmInfo {
    pub event_busy: Hpq,
    pub event_available: Hpq,
    pub command_busy: Hpq,
    pub command_available: Hpq,
    pub rx_buffer_busy: [Hpq; RX_POOL_COUNT],
}

impl HpqmInfo {
    /// Parses the packed 56-byte queue map.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < HPQM_INFO_LEN {
            return Err(ProtocolError::InvalidLength);
        }
        let mut reader = Reader::new(bytes);
        Ok(Self {
            event_busy: reader.hpq()?,
            event_available: reader.hpq()?,
            command_busy: reader.hpq()?,
            command_available: reader.hpq()?,
            rx_buffer_busy: [reader.hpq()?, reader.hpq()?, reader.hpq()?],
        })
    }
}

/// UMAC interface identifiers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InterfaceIds {
    /// `ifaceindex` is valid.
    pub ifaceindex: Option<i32>,
    /// `wiphy_index` is valid.
    pub wiphy_index: Option<i32>,
    /// `wdev_id` is valid.
    pub wdev_id: Option<u64>,
}

impl InterfaceIds {
    const WDEV_VALID: u32 = 1 << 0;
    const IFINDEX_VALID: u32 = 1 << 1;
    const WIPHY_VALID: u32 = 1 << 2;

    fn encode(self, writer: &mut Writer<'_>) -> Result<(), ProtocolError> {
        let mut valid = 0u32;
        if self.wdev_id.is_some() {
            valid |= Self::WDEV_VALID;
        }
        if self.ifaceindex.is_some() {
            valid |= Self::IFINDEX_VALID;
        }
        if self.wiphy_index.is_some() {
            valid |= Self::WIPHY_VALID;
        }
        writer.u32(valid)?;
        writer.i32(self.ifaceindex.unwrap_or(0))?;
        writer.i32(self.wiphy_index.unwrap_or(0))?;
        writer.u64(self.wdev_id.unwrap_or(0))
    }
}

/// Parsed UMAC header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UmacHeader {
    pub port_id: u32,
    pub sequence: u32,
    pub command_event: u32,
    pub result: i32,
    pub valid_ids: u32,
    pub ifaceindex: i32,
    pub wiphy_index: i32,
    pub wdev_id: u64,
}

impl UmacHeader {
    /// Parses a packed UMAC header.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < UMAC_HEADER_LEN {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(Self {
            port_id: read_u32(bytes, 0),
            sequence: read_u32(bytes, 4),
            command_event: read_u32(bytes, 8),
            result: read_i32(bytes, 12),
            valid_ids: read_u32(bytes, 16),
            ifaceindex: read_i32(bytes, 20),
            wiphy_index: read_i32(bytes, 24),
            wdev_id: read_u64(bytes, 28),
        })
    }
}

/// UMAC command numbers pinned to NCS v3.4.0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum UmacCommand {
    TriggerScan = 0,
    GetScanResults = 1,
    Authenticate = 2,
    Associate = 3,
    Deauthenticate = 4,
    SetWiphy = 5,
    NewKey = 6,
    DeleteKey = 7,
    SetKey = 8,
    NewInterface = 15,
    SetInterface = 16,
    DeleteInterface = 17,
    SetInterfaceFlags = 18,
    NewStation = 19,
    DeleteStation = 20,
    SetStation = 21,
    GetStation = 22,
    RegisterFrame = 29,
    Frame = 30,
    SetPowerSave = 33,
    GetChannel = 38,
    GetTxPower = 39,
    GetInterface = 40,
    GetWiphy = 41,
    GetInterfaceHardwareAddress = 42,
    SetInterfaceHardwareAddress = 43,
    GetRegulatory = 44,
    RequestSetRegulatory = 46,
    ConfigureUapsd = 47,
    ConfigureTwt = 48,
    TeardownTwt = 49,
    AbortScan = 50,
    MulticastFilter = 51,
    ChangeMacAddress = 52,
    SetPowerSaveTimeout = 53,
    GetConnectionInfo = 54,
    GetPowerSaveInfo = 55,
    SetListenInterval = 56,
    ConfigureExtendedPowerSave = 57,
    ConfigureQuietPeriod = 58,
    PowerSaveExitStrategy = 59,
}

/// Important UMAC event values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum UmacEvent {
    Unspecified = 256,
    ScanStarted = 257,
    ScanAborted = 258,
    ScanDone = 259,
    ScanResult = 260,
    Authenticate = 261,
    Associate = 262,
    Connect = 263,
    Deauthenticate = 264,
    Disassociate = 265,
    NewStation = 266,
    DeleteStation = 267,
    GetStation = 268,
    Disconnect = 271,
    Frame = 272,
    FrameCookie = 273,
    FrameTxStatus = 274,
    InterfaceFlagsStatus = 275,
    NewInterface = 281,
    GetInterfaceHardwareAddress = 283,
    GetRegulatory = 284,
    ScanDisplayResult = 291,
    CommandStatus = 292,
    BssInfo = 293,
    TwtConfigured = 294,
    TwtTornDown = 295,
    TwtSleep = 296,
}

/// Encodes a raw UMAC command body behind the fixed header.
pub fn encode_umac_command(
    out: &mut [u8],
    command: UmacCommand,
    ids: InterfaceIds,
    body: &[u8],
) -> Result<usize, ProtocolError> {
    let inner_len = UMAC_HEADER_LEN
        .checked_add(body.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if inner_len + HOST_MESSAGE_HEADER_LEN > MAX_CONTROL_MESSAGE_LEN {
        return Err(ProtocolError::LimitExceeded);
    }
    let mut inner = [0u8; MAX_CONTROL_MESSAGE_LEN - HOST_MESSAGE_HEADER_LEN];
    let mut writer = Writer::new(&mut inner[..inner_len]);
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(command as u32)?;
    writer.i32(0)?;
    ids.encode(&mut writer)?;
    writer.bytes(body)?;
    encode_host_message(out, HostMessageType::Umac, false, &inner[..inner_len])
}

/// Parses a UMAC event and returns its body after the 36-byte header.
pub fn parse_umac_event(message: HostMessageRef<'_>) -> Result<(UmacHeader, &[u8]), ProtocolError> {
    if message.message_type != HostMessageType::Umac {
        return Err(ProtocolError::WrongMessageType);
    }
    let header = UmacHeader::parse(message.payload)?;
    Ok((header, &message.payload[UMAC_HEADER_LEN..]))
}

/// Firmware receive-buffer pool settings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxPoolConfig {
    pub buffer_size: u16,
    pub buffer_count: u16,
}

/// UMAC data settings in the system init command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataConfig {
    pub rate_protection_type: u8,
    pub aggregation: bool,
    pub wmm: bool,
    pub max_tx_aggregation_sessions: u8,
    pub max_rx_aggregation_sessions: u8,
    pub max_tx_aggregation: u8,
    pub reorder_buffer_size: u8,
    /// 0, 1, 2, or 3 for 8, 16, 32, or 64 KiB.
    pub max_rx_ampdu_size: i32,
}

impl Default for DataConfig {
    fn default() -> Self {
        Self {
            rate_protection_type: 0,
            aggregation: true,
            wmm: true,
            max_tx_aggregation_sessions: 4,
            max_rx_aggregation_sessions: 4,
            max_tx_aggregation: 16,
            reorder_buffer_size: 16,
            max_rx_ampdu_size: 3,
        }
    }
}

/// Temperature and battery-triggered calibration settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemperatureBatteryConfig {
    pub temperature_calibration_enabled: u32,
    pub temperature_calibration_bitmap: u32,
    pub battery_calibration_bitmap: u32,
    pub monitor_period_us: u32,
    pub very_low_voltage_threshold: i32,
    pub low_voltage_threshold: i32,
    pub high_voltage_threshold: i32,
    pub temperature_threshold: i32,
    pub battery_threshold: i32,
}

impl Default for TemperatureBatteryConfig {
    fn default() -> Self {
        Self {
            temperature_calibration_enabled: 1,
            temperature_calibration_bitmap: 0x7b,
            battery_calibration_bitmap: 1 << 5,
            monitor_period_us: 1024 * 1024,
            very_low_voltage_threshold: 8,
            low_voltage_threshold: 12,
            high_voltage_threshold: 14,
            temperature_threshold: 40,
            battery_threshold: 0,
        }
    }
}

/// Full packed `NRF_WIFI_CMD_INIT` configuration.
#[derive(Clone)]
pub struct SystemInitConfig {
    pub wdev_id: u32,
    pub sleep_enable: u32,
    pub hardware_bringup_time: u32,
    pub software_bringup_time: u32,
    pub beacon_timeout: u32,
    pub calibrate_sleep_clock: u32,
    pub phy_calibration_bitmap: u32,
    pub mac_address: [u8; 6],
    pub rf_params: [u8; RF_PARAMS_LEN],
    pub rf_params_valid: bool,
    pub rx_pools: [RxPoolConfig; RX_POOL_COUNT],
    pub data: DataConfig,
    pub temperature_battery: TemperatureBatteryConfig,
    pub tcp_ip_checksum_offload: bool,
    pub country_code: [u8; 2],
    /// 0 for all bands; 1 for 2.4 GHz only.
    pub operating_band: u32,
    pub management_buffer_offload: bool,
    pub feature_flags: u32,
    pub disable_beamforming: bool,
    pub disconnect_timeout: u32,
    pub power_save_exit_strategy: u8,
    pub watchdog_timer: u32,
    pub keep_alive_enabled: bool,
    pub keep_alive_period_s: u32,
    pub display_scan_bss_limit: u32,
    pub disable_coexistence_priority_window_for_scan: u32,
    pub raw_scan_enabled: bool,
    pub max_ps_poll_fail_count: u32,
    pub stbc_enabled_in_ht: u32,
    pub dynamic_bandwidth_signalling: u32,
    pub dynamic_energy_detection: u32,
    pub bluetooth_slot_time_ms: u32,
    pub bluetooth_coexistence_disabled: u32,
    pub abort_scan_on_bss_limit: bool,
}

impl SystemInitConfig {
    /// Creates a system-mode baseline. Board RF bytes must come from a Nordic
    /// generated or measured board configuration.
    pub const fn new(mac_address: [u8; 6], rf_params: [u8; RF_PARAMS_LEN]) -> Self {
        Self {
            wdev_id: 0,
            sleep_enable: 0,
            hardware_bringup_time: 7300,
            software_bringup_time: 5000,
            beacon_timeout: 20000,
            calibrate_sleep_clock: 1,
            phy_calibration_bitmap: 0x0003_007b,
            mac_address,
            rf_params,
            rf_params_valid: true,
            rx_pools: [
                RxPoolConfig {
                    buffer_size: 1600,
                    buffer_count: 8,
                },
                RxPoolConfig {
                    buffer_size: 0,
                    buffer_count: 0,
                },
                RxPoolConfig {
                    buffer_size: 0,
                    buffer_count: 0,
                },
            ],
            data: DataConfig {
                rate_protection_type: 0,
                aggregation: true,
                wmm: true,
                max_tx_aggregation_sessions: 4,
                max_rx_aggregation_sessions: 4,
                max_tx_aggregation: 16,
                reorder_buffer_size: 16,
                max_rx_ampdu_size: 3,
            },
            temperature_battery: TemperatureBatteryConfig {
                temperature_calibration_enabled: 1,
                temperature_calibration_bitmap: 0x7b,
                battery_calibration_bitmap: 1 << 5,
                monitor_period_us: 1024 * 1024,
                very_low_voltage_threshold: 8,
                low_voltage_threshold: 12,
                high_voltage_threshold: 14,
                temperature_threshold: 40,
                battery_threshold: 0,
            },
            tcp_ip_checksum_offload: false,
            country_code: *b"00",
            operating_band: 0,
            // Nordic's system-mode host enables firmware management-frame
            // buffering. WPA authentication depends on this mode.
            management_buffer_offload: true,
            feature_flags: 0,
            disable_beamforming: false,
            disconnect_timeout: 0,
            power_save_exit_strategy: 1,
            watchdog_timer: 0x00ff_ffff,
            keep_alive_enabled: false,
            keep_alive_period_s: 0,
            display_scan_bss_limit: 150,
            disable_coexistence_priority_window_for_scan: 0,
            raw_scan_enabled: false,
            max_ps_poll_fail_count: 10,
            stbc_enabled_in_ht: 0,
            dynamic_bandwidth_signalling: 0,
            dynamic_energy_detection: 0,
            bluetooth_slot_time_ms: 0,
            bluetooth_coexistence_disabled: 1,
            abort_scan_on_bss_limit: false,
        }
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        let total_rx: u32 = self
            .rx_pools
            .iter()
            .map(|pool| pool.buffer_size as u32 * pool.buffer_count as u32)
            .sum();
        // Packet RAM available after RPU_MEM_PKT_BASE is 180224 bytes. Keep
        // enough room for TX tokens and command bounce storage.
        if total_rx > 128 * 1024
            || self.data.reorder_buffer_size == 0
            || self.data.reorder_buffer_size > 64
            || !(0..=3).contains(&self.data.max_rx_ampdu_size)
        {
            return Err(ProtocolError::LimitExceeded);
        }
        Ok(())
    }
}

/// Encodes Nordic's packed 366-byte system initialization command.
pub fn encode_system_init(
    out: &mut [u8],
    config: &SystemInitConfig,
) -> Result<usize, ProtocolError> {
    config.validate()?;
    let mut body = [0u8; SYSTEM_INIT_LEN];
    let mut writer = Writer::new(&mut body);
    writer.u32(0)?; // NRF_WIFI_CMD_INIT
    writer.u32(SYSTEM_INIT_LEN as u32)?;
    writer.u32(config.wdev_id)?;
    writer.u32(config.sleep_enable)?;
    writer.u32(config.hardware_bringup_time)?;
    writer.u32(config.software_bringup_time)?;
    writer.u32(config.beacon_timeout)?;
    writer.u32(config.calibrate_sleep_clock)?;
    writer.u32(config.phy_calibration_bitmap)?;
    writer.bytes(&config.mac_address)?;
    writer.bytes(&config.rf_params)?;
    writer.u8(u8::from(config.rf_params_valid))?;
    for pool in config.rx_pools {
        writer.u16(pool.buffer_size)?;
        writer.u16(pool.buffer_count)?;
    }
    writer.u8(config.data.rate_protection_type)?;
    writer.u8(u8::from(config.data.aggregation))?;
    writer.u8(u8::from(config.data.wmm))?;
    writer.u8(config.data.max_tx_aggregation_sessions)?;
    writer.u8(config.data.max_rx_aggregation_sessions)?;
    writer.u8(config.data.max_tx_aggregation)?;
    writer.u8(config.data.reorder_buffer_size)?;
    writer.i32(config.data.max_rx_ampdu_size)?;
    let temp = config.temperature_battery;
    writer.u32(temp.temperature_calibration_enabled)?;
    writer.u32(temp.temperature_calibration_bitmap)?;
    writer.u32(temp.battery_calibration_bitmap)?;
    writer.u32(temp.monitor_period_us)?;
    writer.i32(temp.very_low_voltage_threshold)?;
    writer.i32(temp.low_voltage_threshold)?;
    writer.i32(temp.high_voltage_threshold)?;
    writer.i32(temp.temperature_threshold)?;
    writer.i32(temp.battery_threshold)?;
    writer.u8(u8::from(config.tcp_ip_checksum_offload))?;
    writer.bytes(&config.country_code)?;
    writer.u32(config.operating_band)?;
    writer.u8(u8::from(config.management_buffer_offload))?;
    writer.u32(config.feature_flags)?;
    writer.u32(bool_u32(config.disable_beamforming))?;
    writer.u32(config.disconnect_timeout)?;
    writer.u8(config.power_save_exit_strategy)?;
    writer.u32(config.watchdog_timer)?;
    writer.u8(u8::from(config.keep_alive_enabled))?;
    writer.u32(config.keep_alive_period_s)?;
    writer.u32(config.display_scan_bss_limit)?;
    writer.u32(config.disable_coexistence_priority_window_for_scan)?;
    writer.u8(u8::from(config.raw_scan_enabled))?;
    writer.u32(config.max_ps_poll_fail_count)?;
    writer.u32(config.stbc_enabled_in_ht)?;
    writer.u32(config.dynamic_bandwidth_signalling)?;
    writer.u32(config.dynamic_energy_detection)?;
    writer.u32(config.bluetooth_slot_time_ms)?;
    writer.u32(config.bluetooth_coexistence_disabled)?;
    writer.u8(u8::from(config.abort_scan_on_bss_limit))?;
    if writer.len() != SYSTEM_INIT_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    encode_host_message(out, HostMessageType::System, false, &body)
}

/// Interface type values shared with the firmware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum InterfaceType {
    Unspecified = 0,
    AdHoc = 1,
    Station = 2,
    AccessPoint = 3,
    ApVlan = 4,
    Wds = 5,
    Monitor = 6,
    Mesh = 7,
    P2pClient = 8,
    P2pGroupOwner = 9,
    P2pDevice = 10,
}

/// Encodes `NRF_WIFI_UMAC_CMD_NEW_INTERFACE`.
pub fn encode_new_interface(
    out: &mut [u8],
    wdev_id: u32,
    interface_type: InterfaceType,
    mac_address: [u8; 6],
    interface_name: &[u8],
) -> Result<usize, ProtocolError> {
    if interface_name.len() > 16 {
        return Err(ProtocolError::LimitExceeded);
    }
    let mut body = [0u8; 38];
    let mut writer = Writer::new(&mut body);
    writer.u32((1 << 1) | (1 << 2) | (1 << 3))?;
    writer.i32(interface_type as i32)?;
    writer.i32(0)?;
    writer.u32(0)?;
    writer.bytes(&mac_address)?;
    writer.fixed_bytes(interface_name, 16)?;
    encode_umac_command(
        out,
        UmacCommand::NewInterface,
        InterfaceIds {
            wdev_id: Some(wdev_id as u64),
            ..InterfaceIds::default()
        },
        &body,
    )
}

/// Scan purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ScanReason {
    Display = 0,
    Connect = 1,
}

/// Borrowed scan request.
pub struct ScanRequest<'a> {
    pub reason: ScanReason,
    pub passive: bool,
    pub ssids: [&'a [u8]; MAX_SCAN_SSIDS],
    pub ssid_count: u8,
    /// Bit 0 is 2.4 GHz, bit 1 is 5 GHz. Zero asks for both.
    pub bands: u8,
    pub no_cck: bool,
    pub information_elements: &'a [u8],
    pub mac_address: [u8; 6],
    pub active_dwell_ms: u16,
    pub passive_dwell_ms: u16,
    pub skip_local_admin_macs: bool,
    pub center_frequencies_mhz: &'a [u32],
}

impl<'a> ScanRequest<'a> {
    /// Creates a full-band display scan with no directed SSID.
    pub const fn all_bands() -> Self {
        Self {
            reason: ScanReason::Display,
            passive: false,
            ssids: [&[], &[]],
            ssid_count: 0,
            bands: 0,
            no_cck: false,
            information_elements: &[],
            mac_address: [0; 6],
            active_dwell_ms: 0,
            passive_dwell_ms: 0,
            skip_local_admin_macs: false,
            center_frequencies_mhz: &[],
        }
    }
}

/// Encodes `NRF_WIFI_UMAC_CMD_TRIGGER_SCAN`.
pub fn encode_scan(
    out: &mut [u8],
    wdev_id: u32,
    request: &ScanRequest<'_>,
) -> Result<usize, ProtocolError> {
    if request.ssid_count as usize > MAX_SCAN_SSIDS
        || request.center_frequencies_mhz.len() > MAX_SCAN_FREQUENCIES
        || request.information_elements.len() > MAX_SCAN_IE_LEN
    {
        return Err(ProtocolError::LimitExceeded);
    }
    for ssid in request.ssids.iter().take(request.ssid_count as usize) {
        if ssid.len() > MAX_SSID_LEN {
            return Err(ProtocolError::LimitExceeded);
        }
    }

    // scan_reason plus the fixed scan_params prefix and flexible frequency list.
    const FIXED: usize = 4 + 486;
    let body_len = FIXED + request.center_frequencies_mhz.len() * 4;
    if UMAC_HEADER_LEN + body_len + HOST_MESSAGE_HEADER_LEN > MAX_CONTROL_MESSAGE_LEN {
        return Err(ProtocolError::LimitExceeded);
    }
    let mut body = [0u8; MAX_CONTROL_MESSAGE_LEN - UMAC_HEADER_LEN - HOST_MESSAGE_HEADER_LEN];
    let mut writer = Writer::new(&mut body[..body_len]);
    writer.i32(request.reason as i32)?;
    writer.u16(bool_u16(request.passive))?;
    writer.u8(request.ssid_count)?;
    for index in 0..MAX_SCAN_SSIDS {
        let ssid = if index < request.ssid_count as usize {
            request.ssids[index]
        } else {
            &[]
        };
        writer.u8(ssid.len() as u8)?;
        writer.fixed_bytes(ssid, MAX_SSID_LEN)?;
    }
    writer.u8(u8::from(request.no_cck))?;
    writer.u8(request.bands)?;
    writer.u16(request.information_elements.len() as u16)?;
    writer.fixed_bytes(request.information_elements, MAX_SCAN_IE_LEN)?;
    writer.bytes(&request.mac_address)?;
    writer.u16(request.active_dwell_ms)?;
    writer.u16(request.passive_dwell_ms)?;
    writer.u16(request.center_frequencies_mhz.len() as u16)?;
    writer.u8(u8::from(request.skip_local_admin_macs))?;
    for frequency in request.center_frequencies_mhz {
        writer.u32(*frequency)?;
    }
    if writer.len() != body_len {
        return Err(ProtocolError::InvalidLength);
    }
    encode_umac_command(
        out,
        UmacCommand::TriggerScan,
        InterfaceIds {
            wdev_id: Some(wdev_id as u64),
            ..InterfaceIds::default()
        },
        &body[..body_len],
    )
}

/// Encodes scan-result retrieval after `ScanDone`.
pub fn encode_get_scan_results(
    out: &mut [u8],
    wdev_id: u32,
    reason: ScanReason,
) -> Result<usize, ProtocolError> {
    encode_umac_command(
        out,
        UmacCommand::GetScanResults,
        InterfaceIds {
            wdev_id: Some(wdev_id as u64),
            ..InterfaceIds::default()
        },
        &(reason as i32).to_le_bytes(),
    )
}

/// Encodes a station deauthentication command.
pub fn encode_deauthenticate(
    out: &mut [u8],
    wdev_id: u32,
    bssid: [u8; 6],
    reason_code: u16,
    local_state_change: bool,
) -> Result<usize, ProtocolError> {
    let mut body = [0u8; 14];
    let mut writer = Writer::new(&mut body);
    writer.u32(1)?; // NRF_WIFI_CMD_MLME_MAC_ADDR_VALID
    writer.u16(bool_u16(local_state_change))?;
    writer.u16(reason_code)?;
    writer.bytes(&bssid)?;
    encode_umac_command(
        out,
        UmacCommand::Deauthenticate,
        InterfaceIds {
            wdev_id: Some(wdev_id as u64),
            ..InterfaceIds::default()
        },
        &body,
    )
}

/// Data command/event numbers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DataCommand {
    ManagementBufferConfig = 0,
    TransmitBuffer = 1,
    TransmitDone = 2,
    ReceiveBuffer = 3,
    CarrierOn = 4,
    CarrierOff = 5,
    PowerManagementMode = 6,
    PowerSaveGetFrames = 7,
}

/// Packed data-path command header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataHeader {
    pub command: u32,
    pub length: u32,
}

impl DataHeader {
    /// Parses the fixed eight-byte data header.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < 8 {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(Self {
            command: read_u32(bytes, 0),
            length: read_u32(bytes, 4),
        })
    }
}

const fn bool_u16(value: bool) -> u16 {
    if value { 1 } else { 0 }
}

const fn bool_u32(value: bool) -> u32 {
    if value { 1 } else { 0 }
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn len(&self) -> usize {
        self.position
    }

    fn u8(&mut self, value: u8) -> Result<(), ProtocolError> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), ProtocolError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), ProtocolError> {
        self.bytes(&value.to_le_bytes())
    }

    fn i32(&mut self, value: i32) -> Result<(), ProtocolError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), ProtocolError> {
        self.bytes(&value.to_le_bytes())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), ProtocolError> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or(ProtocolError::BufferTooSmall)?;
        let target = self
            .bytes
            .get_mut(self.position..end)
            .ok_or(ProtocolError::BufferTooSmall)?;
        target.copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn fixed_bytes(&mut self, value: &[u8], width: usize) -> Result<(), ProtocolError> {
        if value.len() > width {
            return Err(ProtocolError::LimitExceeded);
        }
        self.bytes(value)?;
        let zeros = width - value.len();
        let end = self
            .position
            .checked_add(zeros)
            .ok_or(ProtocolError::BufferTooSmall)?;
        let target = self
            .bytes
            .get_mut(self.position..end)
            .ok_or(ProtocolError::BufferTooSmall)?;
        target.fill(0);
        self.position = end;
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let end = self.position + 4;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(ProtocolError::InvalidLength)?;
        self.position = end;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn hpq(&mut self) -> Result<Hpq, ProtocolError> {
        Ok(Hpq {
            enqueue_address: self.u32()?,
            dequeue_address: self.u32()?,
        })
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_message_round_trip() {
        let mut bytes = [0u8; 32];
        let len =
            encode_host_message(&mut bytes, HostMessageType::Umac, true, &[1, 2, 3, 4]).unwrap();
        assert_eq!(len, 16);
        let parsed = parse_host_message(&bytes[..len]).unwrap();
        assert_eq!(parsed.message_type, HostMessageType::Umac);
        assert!(parsed.resubmit);
        assert_eq!(parsed.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn hpqm_layout_is_exact() {
        let mut bytes = [0u8; HPQM_INFO_LEN];
        for (index, chunk) in bytes.chunks_exact_mut(4).enumerate() {
            chunk.copy_from_slice(&(index as u32).to_le_bytes());
        }
        let hpqm = HpqmInfo::parse(&bytes).unwrap();
        assert_eq!(
            hpqm.event_busy,
            Hpq {
                enqueue_address: 0,
                dequeue_address: 1
            }
        );
        assert_eq!(hpqm.command_available.dequeue_address, 7);
        assert_eq!(hpqm.rx_buffer_busy[2].dequeue_address, 13);
    }

    #[test]
    fn system_init_is_exact_size() {
        let config = SystemInitConfig::new([2, 0, 0, 0, 0, 1], [0; RF_PARAMS_LEN]);
        let mut bytes = [0u8; SYSTEM_INIT_LEN + HOST_MESSAGE_HEADER_LEN];
        let len = encode_system_init(&mut bytes, &config).unwrap();
        assert_eq!(len, SYSTEM_INIT_LEN + HOST_MESSAGE_HEADER_LEN);
        assert_eq!(read_u32(&bytes, 0) as usize, len);
        assert_eq!(read_u32(&bytes, HOST_MESSAGE_HEADER_LEN), 0);
        assert_eq!(
            read_u32(&bytes, HOST_MESSAGE_HEADER_LEN + 4),
            SYSTEM_INIT_LEN as u32
        );
        assert_eq!(bytes[HOST_MESSAGE_HEADER_LEN + 309], 1);
    }

    #[test]
    fn scan_encoder_checks_limits() {
        let request = ScanRequest::all_bands();
        let mut bytes = [0u8; MAX_CONTROL_MESSAGE_LEN];
        let len = encode_scan(&mut bytes, 7, &request).unwrap();
        assert!(len > UMAC_HEADER_LEN + HOST_MESSAGE_HEADER_LEN);
        assert_eq!(read_u32(&bytes, HOST_MESSAGE_HEADER_LEN + 16), 1);
        assert_eq!(read_i32(&bytes, HOST_MESSAGE_HEADER_LEN + 20), 0);
        assert_eq!(read_u64(&bytes, HOST_MESSAGE_HEADER_LEN + 28), 7);
    }
}
