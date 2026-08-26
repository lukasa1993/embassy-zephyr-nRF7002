//! Packed host/RPU protocol codecs.
//!
//! All encoders write fields explicitly in little-endian order. No C ABI,
//! bindgen output, unaligned reference, or transmute is used.

use crate::codec::{Writer, read_i32, read_u32, read_u64};

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

const MAX_UMAC_INNER_LEN: usize = MAX_CONTROL_MESSAGE_LEN - HOST_MESSAGE_HEADER_LEN;
const MAX_SCAN_BODY_LEN: usize = MAX_UMAC_INNER_LEN - UMAC_HEADER_LEN;

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
    let total = validated_host_message_len(out.len(), payload.len())?;
    let mut writer = Writer::new(out);
    writer.u32(total as u32)?;
    writer.u32(bool_u32(resubmit))?;
    writer.i32(message_type as i32)?;
    writer.bytes(payload)?;
    Ok(writer.len())
}

fn validated_host_message_len(out_len: usize, payload_len: usize) -> Result<usize, ProtocolError> {
    let total = HOST_MESSAGE_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(ProtocolError::InvalidLength)?;
    if total > out_len {
        return Err(ProtocolError::BufferTooSmall);
    }
    if total > u32::MAX as usize {
        return Err(ProtocolError::BufferTooSmall);
    }
    Ok(total)
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
        let (event_busy, event_available, command_busy, command_available) =
            read_primary_queues(&mut reader)?;
        Ok(Self {
            event_busy,
            event_available,
            command_busy,
            command_available,
            rx_buffer_busy: read_rx_queues(&mut reader)?,
        })
    }
}

fn read_primary_queues(reader: &mut Reader<'_>) -> Result<(Hpq, Hpq, Hpq, Hpq), ProtocolError> {
    Ok((reader.hpq()?, reader.hpq()?, reader.hpq()?, reader.hpq()?))
}

fn read_rx_queues(reader: &mut Reader<'_>) -> Result<[Hpq; RX_POOL_COUNT], ProtocolError> {
    Ok([reader.hpq()?, reader.hpq()?, reader.hpq()?])
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
        writer.u32(self.valid_mask())?;
        writer.i32(self.ifaceindex.unwrap_or(0))?;
        writer.i32(self.wiphy_index.unwrap_or(0))?;
        writer.u64(self.wdev_id.unwrap_or(0))
    }

    fn valid_mask(self) -> u32 {
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
        valid
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
    let inner_len = validated_umac_inner_len(body.len())?;
    let mut inner = [0u8; MAX_UMAC_INNER_LEN];
    let mut writer = Writer::new(&mut inner[..inner_len]);
    write_umac_header(&mut writer, command, ids)?;
    writer.bytes(body)?;
    encode_host_message(out, HostMessageType::Umac, false, &inner[..inner_len])
}

fn validated_umac_inner_len(body_len: usize) -> Result<usize, ProtocolError> {
    let inner_len = UMAC_HEADER_LEN
        .checked_add(body_len)
        .ok_or(ProtocolError::InvalidLength)?;
    if inner_len > MAX_UMAC_INNER_LEN {
        return Err(ProtocolError::LimitExceeded);
    }
    Ok(inner_len)
}

fn write_umac_header(
    writer: &mut Writer<'_>,
    command: UmacCommand,
    ids: InterfaceIds,
) -> Result<(), ProtocolError> {
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(command as u32)?;
    writer.i32(0)?;
    ids.encode(writer)
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
    write_system_init_body(&mut writer, config)?;
    if writer.len() != SYSTEM_INIT_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    encode_host_message(out, HostMessageType::System, false, &body)
}

fn write_system_init_body(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    write_system_init_front(writer, config)?;
    write_system_init_middle(writer, config)?;
    write_system_init_back(writer, config)
}

fn write_system_init_front(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    write_system_init_identity(writer, config)?;
    write_system_init_timing(writer, config)?;
    write_system_init_radio(writer, config)?;
    write_system_init_rx_pools(writer, config)
}

fn write_system_init_identity(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    writer.u32(0)?; // NRF_WIFI_CMD_INIT
    writer.u32(SYSTEM_INIT_LEN as u32)?;
    writer.u32(config.wdev_id)?;
    writer.u32(config.sleep_enable)?;
    Ok(())
}

fn write_system_init_timing(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    writer.u32(config.hardware_bringup_time)?;
    writer.u32(config.software_bringup_time)?;
    writer.u32(config.beacon_timeout)?;
    writer.u32(config.calibrate_sleep_clock)?;
    Ok(())
}

fn write_system_init_radio(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    writer.u32(config.phy_calibration_bitmap)?;
    writer.bytes(&config.mac_address)?;
    writer.bytes(&config.rf_params)?;
    writer.u8(u8::from(config.rf_params_valid))
}

fn write_system_init_rx_pools(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    for pool in config.rx_pools {
        writer.u16(pool.buffer_size)?;
        writer.u16(pool.buffer_count)?;
    }
    Ok(())
}

fn write_system_init_middle(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    write_system_init_data_rates(writer, config.data)?;
    write_system_init_data_limits(writer, config.data)?;
    write_system_init_temperature_calibration(writer, config.temperature_battery)?;
    write_system_init_environment_thresholds(writer, config.temperature_battery)
}

fn write_system_init_data_rates(
    writer: &mut Writer<'_>,
    data: DataConfig,
) -> Result<(), ProtocolError> {
    writer.u8(data.rate_protection_type)?;
    writer.u8(u8::from(data.aggregation))?;
    writer.u8(u8::from(data.wmm))?;
    writer.u8(data.max_tx_aggregation_sessions)?;
    Ok(())
}

fn write_system_init_data_limits(
    writer: &mut Writer<'_>,
    data: DataConfig,
) -> Result<(), ProtocolError> {
    writer.u8(data.max_rx_aggregation_sessions)?;
    writer.u8(data.max_tx_aggregation)?;
    writer.u8(data.reorder_buffer_size)?;
    writer.i32(data.max_rx_ampdu_size)
}

fn write_system_init_temperature_calibration(
    writer: &mut Writer<'_>,
    temp: TemperatureBatteryConfig,
) -> Result<(), ProtocolError> {
    writer.u32(temp.temperature_calibration_enabled)?;
    writer.u32(temp.temperature_calibration_bitmap)?;
    writer.u32(temp.battery_calibration_bitmap)?;
    writer.u32(temp.monitor_period_us)?;
    Ok(())
}

fn write_system_init_environment_thresholds(
    writer: &mut Writer<'_>,
    temp: TemperatureBatteryConfig,
) -> Result<(), ProtocolError> {
    writer.i32(temp.very_low_voltage_threshold)?;
    writer.i32(temp.low_voltage_threshold)?;
    writer.i32(temp.high_voltage_threshold)?;
    writer.i32(temp.temperature_threshold)?;
    writer.i32(temp.battery_threshold)
}

fn write_system_init_back(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    write_system_init_network(writer, config)?;
    write_system_init_power(writer, config)?;
    write_system_init_scan_policy(writer, config)?;
    write_system_init_coexistence(writer, config)
}

fn write_system_init_network(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    writer.u8(u8::from(config.tcp_ip_checksum_offload))?;
    writer.bytes(&config.country_code)?;
    writer.u32(config.operating_band)?;
    writer.u8(u8::from(config.management_buffer_offload))?;
    writer.u32(config.feature_flags)
}

fn write_system_init_power(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    writer.u32(bool_u32(config.disable_beamforming))?;
    writer.u32(config.disconnect_timeout)?;
    writer.u8(config.power_save_exit_strategy)?;
    writer.u32(config.watchdog_timer)?;
    Ok(())
}

fn write_system_init_scan_policy(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    writer.u8(u8::from(config.keep_alive_enabled))?;
    writer.u32(config.keep_alive_period_s)?;
    writer.u32(config.display_scan_bss_limit)?;
    writer.u32(config.disable_coexistence_priority_window_for_scan)?;
    writer.u8(u8::from(config.raw_scan_enabled))?;
    writer.u32(config.max_ps_poll_fail_count)
}

fn write_system_init_coexistence(
    writer: &mut Writer<'_>,
    config: &SystemInitConfig,
) -> Result<(), ProtocolError> {
    writer.u32(config.stbc_enabled_in_ht)?;
    writer.u32(config.dynamic_bandwidth_signalling)?;
    writer.u32(config.dynamic_energy_detection)?;
    writer.u32(config.bluetooth_slot_time_ms)?;
    writer.u32(config.bluetooth_coexistence_disabled)?;
    writer.u8(u8::from(config.abort_scan_on_bss_limit))
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
    write_new_interface_metadata(&mut writer, interface_type)?;
    write_new_interface_identity(&mut writer, mac_address, interface_name)?;
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

fn write_new_interface_metadata(
    writer: &mut Writer<'_>,
    interface_type: InterfaceType,
) -> Result<(), ProtocolError> {
    writer.u32((1 << 1) | (1 << 2) | (1 << 3))?;
    writer.i32(interface_type as i32)?;
    writer.i32(0)?;
    writer.u32(0)
}

fn write_new_interface_identity(
    writer: &mut Writer<'_>,
    mac_address: [u8; 6],
    interface_name: &[u8],
) -> Result<(), ProtocolError> {
    writer.bytes(&mac_address)?;
    writer.fixed(interface_name, 16)
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
    validate_scan_request(request)?;
    let body_len = scan_body_len(request.center_frequencies_mhz.len())?;
    let mut body = [0u8; MAX_SCAN_BODY_LEN];
    let mut writer = Writer::new(&mut body[..body_len]);
    write_scan_body(&mut writer, request)?;
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

fn validate_scan_request(request: &ScanRequest<'_>) -> Result<(), ProtocolError> {
    validate_scan_capacities(request)?;
    validate_scan_ssids(request)
}

fn validate_scan_capacities(request: &ScanRequest<'_>) -> Result<(), ProtocolError> {
    if request.ssid_count as usize > MAX_SCAN_SSIDS {
        return Err(ProtocolError::LimitExceeded);
    }
    if request.center_frequencies_mhz.len() > MAX_SCAN_FREQUENCIES {
        return Err(ProtocolError::LimitExceeded);
    }
    if request.information_elements.len() > MAX_SCAN_IE_LEN {
        return Err(ProtocolError::LimitExceeded);
    }
    Ok(())
}

fn validate_scan_ssids(request: &ScanRequest<'_>) -> Result<(), ProtocolError> {
    for ssid in request.ssids.iter().take(request.ssid_count as usize) {
        if ssid.len() > MAX_SSID_LEN {
            return Err(ProtocolError::LimitExceeded);
        }
    }
    Ok(())
}

fn scan_body_len(frequency_count: usize) -> Result<usize, ProtocolError> {
    // scan_reason plus the fixed scan_params prefix and flexible frequency list.
    const FIXED: usize = 4 + 486;
    let frequencies_len = frequency_count
        .checked_mul(4)
        .ok_or(ProtocolError::InvalidLength)?;
    let body_len = FIXED
        .checked_add(frequencies_len)
        .ok_or(ProtocolError::InvalidLength)?;
    if body_len > MAX_SCAN_BODY_LEN {
        return Err(ProtocolError::LimitExceeded);
    }
    Ok(body_len)
}

fn write_scan_body(
    writer: &mut Writer<'_>,
    request: &ScanRequest<'_>,
) -> Result<(), ProtocolError> {
    write_scan_header(writer, request)?;
    write_scan_ssids(writer, request)?;
    write_scan_options(writer, request)?;
    write_scan_frequencies(writer, request.center_frequencies_mhz)
}

fn write_scan_header(
    writer: &mut Writer<'_>,
    request: &ScanRequest<'_>,
) -> Result<(), ProtocolError> {
    writer.i32(request.reason as i32)?;
    writer.u16(bool_u16(request.passive))?;
    writer.u8(request.ssid_count)
}

fn write_scan_ssids(
    writer: &mut Writer<'_>,
    request: &ScanRequest<'_>,
) -> Result<(), ProtocolError> {
    for index in 0..MAX_SCAN_SSIDS {
        let ssid = if index < request.ssid_count as usize {
            request.ssids[index]
        } else {
            &[]
        };
        writer.u8(ssid.len() as u8)?;
        writer.fixed(ssid, MAX_SSID_LEN)?;
    }
    Ok(())
}

fn write_scan_options(
    writer: &mut Writer<'_>,
    request: &ScanRequest<'_>,
) -> Result<(), ProtocolError> {
    writer.u8(u8::from(request.no_cck))?;
    writer.u8(request.bands)?;
    writer.u16(request.information_elements.len() as u16)?;
    writer.fixed(request.information_elements, MAX_SCAN_IE_LEN)?;
    writer.bytes(&request.mac_address)?;
    write_scan_timing(writer, request)
}

fn write_scan_timing(
    writer: &mut Writer<'_>,
    request: &ScanRequest<'_>,
) -> Result<(), ProtocolError> {
    writer.u16(request.active_dwell_ms)?;
    writer.u16(request.passive_dwell_ms)?;
    writer.u16(request.center_frequencies_mhz.len() as u16)?;
    writer.u8(u8::from(request.skip_local_admin_macs))
}

fn write_scan_frequencies(
    writer: &mut Writer<'_>,
    frequencies: &[u32],
) -> Result<(), ProtocolError> {
    for frequency in frequencies {
        writer.u32(*frequency)?;
    }
    Ok(())
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
    write_deauthenticate_body(&mut writer, bssid, reason_code, local_state_change)?;
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

fn write_deauthenticate_body(
    writer: &mut Writer<'_>,
    bssid: [u8; 6],
    reason_code: u16,
    local_state_change: bool,
) -> Result<(), ProtocolError> {
    writer.u32(1)?; // NRF_WIFI_CMD_MLME_MAC_ADDR_VALID
    writer.u16(bool_u16(local_state_change))?;
    writer.u16(reason_code)?;
    writer.bytes(&bssid)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_message_round_trip_and_length_boundaries() {
        let mut bytes = [0u8; 32];
        let len =
            encode_host_message(&mut bytes, HostMessageType::Umac, true, &[1, 2, 3, 4]).unwrap();
        assert_eq!(len, 16);
        let parsed = parse_host_message(&bytes[..len]).unwrap();
        assert_eq!(parsed.message_type, HostMessageType::Umac);
        assert!(parsed.resubmit);
        assert_eq!(parsed.payload, &[1, 2, 3, 4]);

        for message_type in [
            HostMessageType::System,
            HostMessageType::Supplicant,
            HostMessageType::Data,
            HostMessageType::Umac,
        ] {
            let len = encode_host_message(&mut bytes, message_type, false, &[]).unwrap();
            let parsed = parse_host_message(&bytes[..len]).unwrap();
            assert_eq!(parsed.message_type, message_type);
            assert!(!parsed.resubmit);
        }

        assert_eq!(
            validated_host_message_len(HOST_MESSAGE_HEADER_LEN - 1, 0),
            Err(ProtocolError::BufferTooSmall)
        );
        assert_eq!(
            validated_host_message_len(usize::MAX, usize::MAX),
            Err(ProtocolError::InvalidLength)
        );
        if usize::BITS > u32::BITS {
            assert_eq!(
                validated_host_message_len(usize::MAX, u32::MAX as usize),
                Err(ProtocolError::BufferTooSmall)
            );
        }

        assert_eq!(
            parse_host_message(&bytes[..HOST_MESSAGE_HEADER_LEN - 1]),
            Err(ProtocolError::InvalidLength)
        );
        let mut invalid = [0u8; HOST_MESSAGE_HEADER_LEN];
        invalid[..4].copy_from_slice(&((HOST_MESSAGE_HEADER_LEN - 1) as u32).to_le_bytes());
        assert_eq!(
            parse_host_message(&invalid),
            Err(ProtocolError::InvalidLength)
        );
        invalid[..4].copy_from_slice(&((HOST_MESSAGE_HEADER_LEN + 1) as u32).to_le_bytes());
        assert_eq!(
            parse_host_message(&invalid),
            Err(ProtocolError::InvalidLength)
        );
        invalid[..4].copy_from_slice(&(HOST_MESSAGE_HEADER_LEN as u32).to_le_bytes());
        invalid[8..12].copy_from_slice(&4i32.to_le_bytes());
        assert_eq!(
            parse_host_message(&invalid),
            Err(ProtocolError::InvalidValue(4))
        );
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
        assert_eq!(
            HpqmInfo::parse(&bytes[..HPQM_INFO_LEN - 1]),
            Err(ProtocolError::InvalidLength)
        );
    }

    #[test]
    fn system_init_defaults_and_wire_image_are_exact() {
        let config = SystemInitConfig::new([2, 0, 0, 0, 0, 1], [0; RF_PARAMS_LEN]);
        assert_eq!(config.data, DataConfig::default());
        assert_eq!(
            config.temperature_battery,
            TemperatureBatteryConfig::default()
        );
        assert!(config.rf_params_valid);
        assert_eq!(config.rx_pools[0].buffer_size, 1600);
        assert_eq!(config.rx_pools[0].buffer_count, 8);
        assert_eq!(config.rx_pools[1], RxPoolConfig::default());
        assert_eq!(config.rx_pools[2], RxPoolConfig::default());
        assert!(!config.tcp_ip_checksum_offload);
        assert!(config.management_buffer_offload);
        assert!(!config.disable_beamforming);
        assert!(!config.keep_alive_enabled);
        assert!(!config.raw_scan_enabled);
        assert!(!config.abort_scan_on_bss_limit);
        assert_eq!(config.temperature_battery.monitor_period_us, 1024 * 1024);
        let mut bytes = [0u8; SYSTEM_INIT_LEN + HOST_MESSAGE_HEADER_LEN];
        let len = encode_system_init(&mut bytes, &config).unwrap();
        assert_eq!(len, SYSTEM_INIT_LEN + HOST_MESSAGE_HEADER_LEN);
        assert_eq!(read_u32(&bytes, 0) as usize, len);
        assert_eq!(read_u32(&bytes, HOST_MESSAGE_HEADER_LEN), 0);
        assert_eq!(
            read_u32(&bytes, HOST_MESSAGE_HEADER_LEN + 4),
            SYSTEM_INIT_LEN as u32
        );
        assert_eq!(read_u32(&bytes, HOST_MESSAGE_HEADER_LEN + 28), 1);
        assert_eq!(bytes[HOST_MESSAGE_HEADER_LEN + 309], 1);
        assert_eq!(
            parse_host_message(&bytes).unwrap().message_type,
            HostMessageType::System
        );
        assert!(!parse_host_message(&bytes).unwrap().resubmit);
    }

    #[test]
    fn system_init_rejects_each_resource_limit_independently() {
        let mut out = [0u8; SYSTEM_INIT_LEN + HOST_MESSAGE_HEADER_LEN];
        let mut config = SystemInitConfig::new([0; 6], [0; RF_PARAMS_LEN]);
        config.rx_pools[0] = RxPoolConfig {
            buffer_size: u16::MAX,
            buffer_count: 3,
        };
        assert_eq!(
            encode_system_init(&mut out, &config),
            Err(ProtocolError::LimitExceeded)
        );

        for reorder_size in [0, 65] {
            let mut config = SystemInitConfig::new([0; 6], [0; RF_PARAMS_LEN]);
            config.data.reorder_buffer_size = reorder_size;
            assert_eq!(
                encode_system_init(&mut out, &config),
                Err(ProtocolError::LimitExceeded)
            );
        }
        for ampdu_size in [-1, 4] {
            let mut config = SystemInitConfig::new([0; 6], [0; RF_PARAMS_LEN]);
            config.data.max_rx_ampdu_size = ampdu_size;
            assert_eq!(
                encode_system_init(&mut out, &config),
                Err(ProtocolError::LimitExceeded)
            );
        }
    }

    #[test]
    fn umac_header_and_interface_id_encodings_are_exact() {
        assert_eq!(
            MAX_UMAC_INNER_LEN,
            MAX_CONTROL_MESSAGE_LEN - HOST_MESSAGE_HEADER_LEN
        );
        assert_eq!(MAX_SCAN_BODY_LEN, MAX_UMAC_INNER_LEN - UMAC_HEADER_LEN);
        let ids = InterfaceIds {
            ifaceindex: Some(-3),
            wiphy_index: Some(5),
            wdev_id: Some(0x0102_0304_0506_0708),
        };
        assert_eq!(ids.valid_mask(), 0b111);
        assert_eq!(InterfaceIds::default().valid_mask(), 0);
        let mut bytes = [0u8; 128];
        let len = encode_umac_command(&mut bytes, UmacCommand::SetInterface, ids, &[0xaa]).unwrap();
        let outer = parse_host_message(&bytes[..len]).unwrap();
        assert_eq!(outer.message_type, HostMessageType::Umac);
        assert!(!outer.resubmit);
        let header = UmacHeader::parse(outer.payload).unwrap();
        assert_eq!(header.command_event, UmacCommand::SetInterface as u32);
        assert_eq!(header.valid_ids, 0b111);
        assert_eq!(header.ifaceindex, -3);
        assert_eq!(header.wiphy_index, 5);
        assert_eq!(header.wdev_id, 0x0102_0304_0506_0708);
        assert_eq!(&outer.payload[UMAC_HEADER_LEN..], &[0xaa]);
        assert_eq!(
            UmacHeader::parse(&outer.payload[..UMAC_HEADER_LEN - 1]),
            Err(ProtocolError::InvalidLength)
        );

        let oversized = [0u8; MAX_UMAC_INNER_LEN - UMAC_HEADER_LEN + 1];
        assert_eq!(
            encode_umac_command(&mut bytes, UmacCommand::SetInterface, ids, &oversized),
            Err(ProtocolError::LimitExceeded)
        );
    }

    #[test]
    fn new_interface_and_deauthentication_bodies_are_exact() {
        let mut bytes = [0u8; 128];
        let mac = [2, 1, 2, 3, 4, 5];
        let len =
            encode_new_interface(&mut bytes, 9, InterfaceType::Station, mac, b"wlan0").unwrap();
        let outer = parse_host_message(&bytes[..len]).unwrap();
        let header = UmacHeader::parse(outer.payload).unwrap();
        assert_eq!(header.command_event, UmacCommand::NewInterface as u32);
        assert_eq!(header.wdev_id, 9);
        let body = &outer.payload[UMAC_HEADER_LEN..];
        assert_eq!(read_u32(body, 0), 0b1110);
        assert_eq!(read_i32(body, 4), InterfaceType::Station as i32);
        assert_eq!(&body[16..22], &mac);
        assert_eq!(&body[22..27], b"wlan0");
        assert!(body[27..].iter().all(|byte| *byte == 0));
        assert_eq!(
            encode_new_interface(&mut bytes, 9, InterfaceType::Station, mac, &[0; 17]),
            Err(ProtocolError::LimitExceeded)
        );

        let bssid = [6, 7, 8, 9, 10, 11];
        let len = encode_deauthenticate(&mut bytes, 9, bssid, 7, true).unwrap();
        let outer = parse_host_message(&bytes[..len]).unwrap();
        let header = UmacHeader::parse(outer.payload).unwrap();
        assert_eq!(header.command_event, UmacCommand::Deauthenticate as u32);
        let body = &outer.payload[UMAC_HEADER_LEN..];
        assert_eq!(read_u32(body, 0), 1);
        assert_eq!(u16::from_le_bytes([body[4], body[5]]), 1);
        assert_eq!(u16::from_le_bytes([body[6], body[7]]), 7);
        assert_eq!(&body[8..], &bssid);
    }

    #[test]
    fn scan_encoder_writes_every_option_and_checks_each_limit() {
        let defaults = ScanRequest::all_bands();
        assert!(!defaults.passive);
        assert!(!defaults.no_cck);
        assert!(!defaults.skip_local_admin_macs);
        let frequencies = [2412, 2437];
        let request = ScanRequest {
            reason: ScanReason::Connect,
            passive: true,
            ssids: [b"one", b"two"],
            ssid_count: 1,
            bands: 1,
            no_cck: true,
            information_elements: &[0xdd, 1, 0xaa],
            mac_address: [2, 3, 4, 5, 6, 7],
            active_dwell_ms: 11,
            passive_dwell_ms: 22,
            skip_local_admin_macs: true,
            center_frequencies_mhz: &frequencies,
        };
        let mut bytes = [0u8; MAX_CONTROL_MESSAGE_LEN];
        let len = encode_scan(&mut bytes, 7, &request).unwrap();
        assert_eq!(len, HOST_MESSAGE_HEADER_LEN + UMAC_HEADER_LEN + 490 + 8);
        assert_eq!(read_u32(&bytes, HOST_MESSAGE_HEADER_LEN + 16), 1);
        assert_eq!(read_i32(&bytes, HOST_MESSAGE_HEADER_LEN + 20), 0);
        assert_eq!(read_u64(&bytes, HOST_MESSAGE_HEADER_LEN + 28), 7);
        let body = &bytes[HOST_MESSAGE_HEADER_LEN + UMAC_HEADER_LEN..len];
        assert_eq!(read_i32(body, 0), ScanReason::Connect as i32);
        assert_eq!(u16::from_le_bytes([body[4], body[5]]), 1);
        assert_eq!(body[6], 1);
        assert_eq!(body[7], 3);
        assert_eq!(&body[8..11], b"one");
        assert_eq!(body[40], 0);
        assert_eq!(body[73], 1);
        assert_eq!(body[74], 1);
        assert_eq!(u16::from_le_bytes([body[75], body[76]]), 3);
        assert_eq!(&body[77..80], &[0xdd, 1, 0xaa]);
        assert_eq!(&body[477..483], &[2, 3, 4, 5, 6, 7]);
        assert_eq!(u16::from_le_bytes([body[483], body[484]]), 11);
        assert_eq!(u16::from_le_bytes([body[485], body[486]]), 22);
        assert_eq!(u16::from_le_bytes([body[487], body[488]]), 2);
        assert_eq!(body[489], 1);
        assert_eq!(read_u32(body, 490), 2412);
        assert_eq!(read_u32(body, 494), 2437);

        let mut invalid = ScanRequest::all_bands();
        invalid.ssid_count = 3;
        assert_eq!(
            encode_scan(&mut bytes, 7, &invalid),
            Err(ProtocolError::LimitExceeded)
        );
        let too_many_frequencies = [0u32; MAX_SCAN_FREQUENCIES + 1];
        invalid = ScanRequest::all_bands();
        invalid.center_frequencies_mhz = &too_many_frequencies;
        assert_eq!(
            encode_scan(&mut bytes, 7, &invalid),
            Err(ProtocolError::LimitExceeded)
        );
        let too_many_ies = [0u8; MAX_SCAN_IE_LEN + 1];
        invalid = ScanRequest::all_bands();
        invalid.information_elements = &too_many_ies;
        assert_eq!(
            encode_scan(&mut bytes, 7, &invalid),
            Err(ProtocolError::LimitExceeded)
        );
        let oversized_ssid = [0u8; MAX_SSID_LEN + 1];
        invalid = ScanRequest::all_bands();
        invalid.ssids[0] = &oversized_ssid;
        invalid.ssid_count = 1;
        assert_eq!(
            encode_scan(&mut bytes, 7, &invalid),
            Err(ProtocolError::LimitExceeded)
        );
    }

    #[test]
    fn data_header_checks_its_exact_boundary() {
        let bytes = [1, 0, 0, 0, 8, 0, 0, 0];
        assert_eq!(
            DataHeader::parse(&bytes),
            Ok(DataHeader {
                command: 1,
                length: 8,
            })
        );
        assert_eq!(
            DataHeader::parse(&bytes[..7]),
            Err(ProtocolError::InvalidLength)
        );
    }
}
