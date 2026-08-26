//! Station control codecs and event parsing for the pinned Nordic UMAC ABI.
//!
//! The large authentication and association structures exceed the original
//! 1024-byte scratch limit. These codecs write directly into caller storage
//! and do not allocate.

use super::codec::{Writer, read_i32, read_u16, read_u32, read_u64};
use super::protocol::{
    HostMessageRef, HostMessageType, ProtocolError, UMAC_HEADER_LEN, UmacCommand, UmacEvent,
    UmacHeader, parse_umac_event,
};

/// Largest station command encoded by this module.
pub const MAX_STATION_MESSAGE_LEN: usize = 2048;
/// Maximum key material bytes in Nordic's ABI.
pub const MAX_KEY_LEN: usize = 256;
/// Maximum key sequence bytes in Nordic's ABI.
pub const MAX_KEY_SEQUENCE_LEN: usize = 256;
/// Maximum information-element bytes in Nordic's ABI.
pub const MAX_IE_LEN: usize = 400;
/// Maximum SAE element bytes in Nordic's ABI.
pub const MAX_SAE_LEN: usize = 256;
/// Maximum pairwise cipher suite count in association commands.
pub const MAX_PAIRWISE_CIPHERS: usize = 7;
/// Maximum AKM suite count in association commands.
pub const MAX_AKM_SUITES: usize = 2;

/// IEEE RSN CCMP-128 cipher suite selector.
pub const RSN_CIPHER_CCMP_128: u32 = 0x000f_ac04;
/// IEEE RSN GCMP-128 cipher suite selector.
pub const RSN_CIPHER_GCMP_128: u32 = 0x000f_ac08;
/// IEEE RSN BIP-CMAC-128 management cipher selector.
pub const RSN_CIPHER_BIP_CMAC_128: u32 = 0x000f_ac06;
/// IEEE RSN PSK AKM suite selector.
pub const RSN_AKM_PSK: u32 = 0x000f_ac02;
/// IEEE RSN SAE AKM suite selector.
pub const RSN_AKM_SAE: u32 = 0x000f_ac08;
/// IEEE RSN PSK-SHA256 AKM suite selector.
pub const RSN_AKM_PSK_SHA256: u32 = 0x000f_ac06;
/// IEEE 802.1X controlled-port EtherType.
pub const EAPOL_ETHERTYPE: u16 = 0x888e;

const HOST_HEADER_LEN: usize = 12;
const KEY_INFO_LEN: usize = 535;
const AUTH_INFO_LEN: usize = 1672;
const AUTH_BODY_LEN: usize = 4 + AUTH_INFO_LEN;
const CONNECT_COMMON_INFO_LEN: usize = 1563;
const ASSOC_BODY_LEN: usize = 4 + CONNECT_COMMON_INFO_LEN + 6;
const MLME_FIXED_BODY_LEN: usize = 439;
const SCAN_RESULT_FIXED_BODY_LEN: usize = 70;

/// Full authentication host-message length.
pub const AUTH_MESSAGE_LEN: usize = HOST_HEADER_LEN + UMAC_HEADER_LEN + AUTH_BODY_LEN;
/// Full association host-message length.
pub const ASSOC_MESSAGE_LEN: usize = HOST_HEADER_LEN + UMAC_HEADER_LEN + ASSOC_BODY_LEN;
/// Full key command host-message length.
pub const KEY_MESSAGE_LEN: usize = HOST_HEADER_LEN + UMAC_HEADER_LEN + 4 + KEY_INFO_LEN + 6;

const INDEX_WDEV_VALID: u32 = 1 << 0;

const AUTH_KEY_INFO_VALID: u32 = 1 << 0;
const AUTH_FREQUENCY_VALID: u32 = 1 << 2;
const AUTH_SSID_VALID: u32 = 1 << 3;
const AUTH_SAE_VALID: u32 = 1 << 5;
const AUTH_LOCAL_STATE_CHANGE: u16 = 1 << 0;

const ASSOC_PREVIOUS_BSSID_VALID: u32 = 1 << 0;
const CONNECT_MAC_VALID: u32 = 1 << 0;
const CONNECT_FREQUENCY_VALID: u32 = 1 << 2;
const CONNECT_BG_SCAN_VALID: u32 = 1 << 4;
const CONNECT_SSID_VALID: u32 = 1 << 5;
const CONNECT_WPA_IE_VALID: u32 = 1 << 6;
const CONNECT_WPA_VERSIONS_VALID: u32 = 1 << 7;
const CONNECT_PAIRWISE_VALID: u32 = 1 << 8;
const CONNECT_GROUP_VALID: u32 = 1 << 9;
const CONNECT_AKM_VALID: u32 = 1 << 10;
const CONNECT_MFP_VALID: u32 = 1 << 11;
const CONNECT_CONTROL_PORT_ETHERTYPE_VALID: u32 = 1 << 12;
const CONNECT_CONTROL_PORT_NO_ENCRYPT_VALID: u32 = 1 << 13;
const CONNECT_PREVIOUS_BSSID_VALID: u32 = 1 << 15;
const CONNECT_SECURITY_VALID: u32 = 1 << 16;

const WPA_VERSION_2: u32 = 1 << 1;
const KEY_DATA_VALID: u32 = 1 << 0;
const KEY_TYPE_VALID: u32 = 1 << 1;
const KEY_INDEX_VALID: u32 = 1 << 2;
const KEY_SEQUENCE_VALID: u32 = 1 << 3;
const KEY_CIPHER_VALID: u32 = 1 << 4;
const KEY_MAC_VALID: u32 = 1 << 0;
const SET_STATION_FLAGS_VALID: u32 = 1 << 12;
const STATION_FLAG_AUTHORIZED: u32 = 1 << 1;
const CHANGE_STATION_INFO_LEN: usize = 789;

const EVENT_REGULATORY_CHANGE: u32 = 289;

/// Authentication method used by the firmware MLME command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum AuthenticationType {
    OpenSystem = 0,
    SharedKey = 1,
    FastTransition = 2,
    NetworkEap = 3,
    Sae = 4,
    Automatic = 6,
}

/// Firmware key category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum KeyType {
    Group = 0,
    Pairwise = 1,
    Peer = 2,
}

/// Management-frame protection setting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum MfpMode {
    Disabled = 0,
    Required = 1,
}

/// Firmware connection protection mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConnectionType {
    Open = 0,
    Secure = 1,
}

/// Firmware power-save state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum PowerSaveState {
    Disabled = 0,
    Enabled = 1,
}

/// Security-key material for a key command.
pub struct KeyConfig<'a> {
    pub cipher_suite: u32,
    pub key_type: KeyType,
    pub key_index: u8,
    pub key: &'a [u8],
    pub sequence: &'a [u8],
    /// Nordic key flags, such as default-key flags.
    pub flags: u16,
}

impl<'a> KeyConfig<'a> {
    /// Creates one pairwise key with no sequence value.
    pub const fn pairwise(cipher_suite: u32, key_index: u8, key: &'a [u8]) -> Self {
        Self {
            cipher_suite,
            key_type: KeyType::Pairwise,
            key_index,
            key,
            sequence: &[],
            flags: 0,
        }
    }
}

/// BSS metadata copied from a trusted scan result into authentication.
#[derive(Default)]
pub struct BssContext<'a> {
    pub scan_width: i32,
    pub signal_dbm: i32,
    pub from_beacon: bool,
    pub information_elements: &'a [u8],
    pub capability: u16,
    pub beacon_interval: u16,
    pub tsf: u64,
}

/// Authentication command input.
pub struct AuthenticationRequest<'a> {
    pub frequency_mhz: u32,
    pub bssid: [u8; 6],
    pub ssid: &'a [u8],
    pub auth_type: AuthenticationType,
    pub local_state_change: bool,
    pub information_elements: &'a [u8],
    pub sae_data: &'a [u8],
    pub key: Option<&'a KeyConfig<'a>>,
    pub bss: BssContext<'a>,
}

/// Association security fields.
pub struct AssociationSecurity<'a> {
    pub pairwise_ciphers: &'a [u32],
    pub group_cipher: u32,
    pub akm_suites: &'a [u32],
    pub mfp: MfpMode,
    pub rsn_information_element: &'a [u8],
}

/// Association command input.
pub struct AssociationRequest<'a> {
    pub frequency_mhz: u32,
    pub bssid: [u8; 6],
    pub ssid: &'a [u8],
    pub security: Option<AssociationSecurity<'a>>,
    pub background_scan_period_s: u16,
    pub previous_bssid: Option<[u8; 6]>,
    pub bss_max_idle_s: u16,
}

/// Parsed MLME authentication, association, or disconnect event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlmeEvent<'a> {
    pub header: UmacHeader,
    pub valid_fields: u32,
    pub frequency_mhz: u32,
    pub signal_dbm: i32,
    pub flags: u32,
    pub cookie: u64,
    pub bssid: [u8; 6],
    pub frame: &'a [u8],
    pub request_information_elements: &'a [u8],
}

/// Borrowed scan-result event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanResultEvent<'a> {
    pub header: UmacHeader,
    pub valid_fields: u32,
    pub frequency_mhz: u32,
    pub channel_width: u32,
    pub seen_ms_ago: u32,
    pub status: i32,
    pub signal: i32,
    pub bssid: [u8; 6],
    pub beacon_interval: u16,
    pub capability: u16,
    pub information_elements: &'a [u8],
    pub beacon_information_elements: &'a [u8],
}

/// Control-plane event classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlEvent<'a> {
    ScanDone {
        header: UmacHeader,
        status: i32,
        scan_type: u32,
    },
    ScanResult(ScanResultEvent<'a>),
    Authentication(MlmeEvent<'a>),
    Association(MlmeEvent<'a>),
    Deauthentication(MlmeEvent<'a>),
    Disassociation(MlmeEvent<'a>),
    CommandStatus {
        header: UmacHeader,
        command: u32,
        status: u32,
    },
    InterfaceState {
        header: UmacHeader,
        status: i32,
    },
    RegulatoryChange {
        header: UmacHeader,
        country: [u8; 2],
    },
    Other {
        header: UmacHeader,
        body: &'a [u8],
    },
}

/// Encodes `NRF_WIFI_UMAC_CMD_AUTHENTICATE`.
pub fn encode_authenticate(
    out: &mut [u8],
    wdev_id: u32,
    request: &AuthenticationRequest<'_>,
) -> Result<usize, ProtocolError> {
    validate_authentication_request(request)?;
    encode_umac(
        out,
        UmacCommand::Authenticate,
        Some(wdev_id),
        AUTH_BODY_LEN,
        |writer| write_authentication_body(writer, request),
    )
}

fn validate_authentication_request(
    request: &AuthenticationRequest<'_>,
) -> Result<(), ProtocolError> {
    validate_ssid(request.ssid)?;
    validate_ie(request.information_elements)?;
    validate_ie(request.bss.information_elements)?;
    if request.sae_data.len() > MAX_SAE_LEN {
        return Err(ProtocolError::LimitExceeded);
    }
    validate_optional_key(request.key)
}

fn validate_optional_key(key: Option<&KeyConfig<'_>>) -> Result<(), ProtocolError> {
    if let Some(key) = key {
        validate_key(key)?;
    }
    Ok(())
}

fn authentication_valid_fields(request: &AuthenticationRequest<'_>) -> u32 {
    // Match nrf_wifi_sys_fmac_auth: BSSID and authentication IEs are copied
    // into auth_info but do not have outer command-valid bits.
    let mut valid = AUTH_FREQUENCY_VALID | AUTH_SSID_VALID;
    if request.key.is_some() {
        valid |= AUTH_KEY_INFO_VALID;
    }
    if !request.sae_data.is_empty() {
        valid |= AUTH_SAE_VALID;
    }
    valid
}

fn write_authentication_body(
    writer: &mut Writer<'_>,
    request: &AuthenticationRequest<'_>,
) -> Result<(), ProtocolError> {
    write_authentication_header(writer, request)?;
    write_authentication_security(writer, request)?;
    write_authentication_sae(writer, request)?;
    write_authentication_bss(writer, request)
}

fn write_authentication_header(
    writer: &mut Writer<'_>,
    request: &AuthenticationRequest<'_>,
) -> Result<(), ProtocolError> {
    writer.u32(authentication_valid_fields(request))?;
    writer.u32(request.frequency_mhz)?;
    writer.u16(if request.local_state_change {
        AUTH_LOCAL_STATE_CHANGE
    } else {
        0
    })?;
    writer.i32(request.auth_type as i32)
}

fn write_authentication_security(
    writer: &mut Writer<'_>,
    request: &AuthenticationRequest<'_>,
) -> Result<(), ProtocolError> {
    write_key_info(writer, request.key)?;
    writer.ssid(request.ssid)?;
    writer.ie(request.information_elements)
}

fn write_authentication_sae(
    writer: &mut Writer<'_>,
    request: &AuthenticationRequest<'_>,
) -> Result<(), ProtocolError> {
    writer.i32(request.sae_data.len() as i32)?;
    writer.fixed(request.sae_data, MAX_SAE_LEN)?;
    writer.bytes(&request.bssid)
}

fn write_authentication_bss(
    writer: &mut Writer<'_>,
    request: &AuthenticationRequest<'_>,
) -> Result<(), ProtocolError> {
    write_authentication_bss_observation(writer, &request.bss)?;
    write_authentication_bss_timing(writer, &request.bss)
}

fn write_authentication_bss_observation(
    writer: &mut Writer<'_>,
    bss: &BssContext<'_>,
) -> Result<(), ProtocolError> {
    writer.i32(bss.scan_width)?;
    writer.i32(bss.signal_dbm)?;
    writer.i32(if bss.from_beacon { 1 } else { 0 })?;
    writer.ie(bss.information_elements)
}

fn write_authentication_bss_timing(
    writer: &mut Writer<'_>,
    bss: &BssContext<'_>,
) -> Result<(), ProtocolError> {
    writer.u16(bss.capability)?;
    writer.u16(bss.beacon_interval)?;
    writer.u64(bss.tsf)
}

/// Encodes `NRF_WIFI_UMAC_CMD_ASSOCIATE`.
pub fn encode_associate(
    out: &mut [u8],
    wdev_id: u32,
    request: &AssociationRequest<'_>,
) -> Result<usize, ProtocolError> {
    validate_association_request(request)?;
    encode_umac(
        out,
        UmacCommand::Associate,
        Some(wdev_id),
        ASSOC_BODY_LEN,
        |writer| write_association_body(writer, request),
    )
}

fn validate_association_request(request: &AssociationRequest<'_>) -> Result<(), ProtocolError> {
    validate_ssid(request.ssid)?;
    if let Some(security) = &request.security {
        validate_ie(security.rsn_information_element)?;
        validate_association_security_counts(security)?;
    }
    Ok(())
}

fn validate_association_security_counts(
    security: &AssociationSecurity<'_>,
) -> Result<(), ProtocolError> {
    if security.pairwise_ciphers.is_empty()
        || security.pairwise_ciphers.len() > MAX_PAIRWISE_CIPHERS
    {
        return Err(ProtocolError::LimitExceeded);
    }
    if security.akm_suites.is_empty() || security.akm_suites.len() > MAX_AKM_SUITES {
        return Err(ProtocolError::LimitExceeded);
    }
    Ok(())
}

fn association_valid_fields(request: &AssociationRequest<'_>) -> u32 {
    let mut valid = CONNECT_MAC_VALID
        | CONNECT_FREQUENCY_VALID
        | CONNECT_SSID_VALID
        | CONNECT_CONTROL_PORT_ETHERTYPE_VALID
        | CONNECT_CONTROL_PORT_NO_ENCRYPT_VALID;
    if request.background_scan_period_s != 0 {
        valid |= CONNECT_BG_SCAN_VALID;
    }
    if request.previous_bssid.is_some() {
        valid |= CONNECT_PREVIOUS_BSSID_VALID;
    }
    if request.security.is_some() {
        valid |= CONNECT_WPA_IE_VALID
            | CONNECT_WPA_VERSIONS_VALID
            | CONNECT_PAIRWISE_VALID
            | CONNECT_GROUP_VALID
            | CONNECT_AKM_VALID
            | CONNECT_MFP_VALID
            | CONNECT_SECURITY_VALID;
    }
    valid
}

fn write_association_body(
    writer: &mut Writer<'_>,
    request: &AssociationRequest<'_>,
) -> Result<(), ProtocolError> {
    write_association_header(writer, request)?;
    write_association_ciphers(writer, request.security.as_ref())?;
    write_association_network(writer, request)?;
    write_association_control_port(writer)?;
    write_association_previous_bssid(writer, request)
}

fn write_association_header(
    writer: &mut Writer<'_>,
    request: &AssociationRequest<'_>,
) -> Result<(), ProtocolError> {
    write_association_validity(writer, request)?;
    write_association_frequency(writer, request)
}

fn write_association_validity(
    writer: &mut Writer<'_>,
    request: &AssociationRequest<'_>,
) -> Result<(), ProtocolError> {
    writer.u32(if request.previous_bssid.is_some() {
        ASSOC_PREVIOUS_BSSID_VALID
    } else {
        0
    })?;
    writer.u32(association_valid_fields(request))
}

fn write_association_frequency(
    writer: &mut Writer<'_>,
    request: &AssociationRequest<'_>,
) -> Result<(), ProtocolError> {
    writer.u32(request.frequency_mhz)?;
    writer.u32(0)?;
    writer.u32(if request.security.is_some() {
        WPA_VERSION_2
    } else {
        0
    })
}

fn write_association_ciphers(
    writer: &mut Writer<'_>,
    security: Option<&AssociationSecurity<'_>>,
) -> Result<(), ProtocolError> {
    let pairwise = security.map(|value| value.pairwise_ciphers).unwrap_or(&[]);
    writer.i32(pairwise.len() as i32)?;
    writer.fixed_u32(pairwise, MAX_PAIRWISE_CIPHERS)?;
    write_association_group_and_akm(writer, security)
}

fn write_association_group_and_akm(
    writer: &mut Writer<'_>,
    security: Option<&AssociationSecurity<'_>>,
) -> Result<(), ProtocolError> {
    writer.u32(security.map(|value| value.group_cipher).unwrap_or(0))?;
    let akm = security.map(|value| value.akm_suites).unwrap_or(&[]);
    writer.u32(akm.len() as u32)?;
    writer.fixed_u32(akm, MAX_AKM_SUITES)?;
    writer.i32(
        security
            .map(|value| value.mfp as i32)
            .unwrap_or(MfpMode::Disabled as i32),
    )
}

fn write_association_network(
    writer: &mut Writer<'_>,
    request: &AssociationRequest<'_>,
) -> Result<(), ProtocolError> {
    writer.u32(0)?;
    writer.u16(request.background_scan_period_s)?;
    writer.bytes(&request.bssid)?;
    writer.bytes(&[0; 6])?;
    write_association_network_names(writer, request)
}

fn write_association_network_names(
    writer: &mut Writer<'_>,
    request: &AssociationRequest<'_>,
) -> Result<(), ProtocolError> {
    writer.ssid(request.ssid)?;
    writer.ie(request
        .security
        .as_ref()
        .map(|value| value.rsn_information_element)
        .unwrap_or(&[]))
}

fn write_association_control_port(writer: &mut Writer<'_>) -> Result<(), ProtocolError> {
    writer.u32(0)?;
    writer.u16(0)?;
    writer.zeros(4 * 256)?;
    writer.u16(EAPOL_ETHERTYPE)?;
    writer.u8(1)?;
    writer.u8(1)
}

fn write_association_previous_bssid(
    writer: &mut Writer<'_>,
    request: &AssociationRequest<'_>,
) -> Result<(), ProtocolError> {
    let previous = request.previous_bssid.unwrap_or([0; 6]);
    writer.bytes(&previous)?;
    writer.u16(request.bss_max_idle_s)?;
    writer.bytes(&previous)
}

/// Encodes `NRF_WIFI_UMAC_CMD_NEW_KEY` or `NRF_WIFI_UMAC_CMD_DEL_KEY`.
pub fn encode_key_command(
    out: &mut [u8],
    wdev_id: u32,
    command: UmacCommand,
    peer: Option<[u8; 6]>,
    key: &KeyConfig<'_>,
) -> Result<usize, ProtocolError> {
    validate_key_command(command)?;
    validate_key(key)?;
    encode_umac(
        out,
        command,
        Some(wdev_id),
        4 + KEY_INFO_LEN + 6,
        |writer| {
            writer.u32(if peer.is_some() { KEY_MAC_VALID } else { 0 })?;
            write_key_info(writer, Some(key))?;
            writer.bytes(&peer.unwrap_or([0; 6]))
        },
    )
}

fn validate_key_command(command: UmacCommand) -> Result<(), ProtocolError> {
    if command != UmacCommand::NewKey && command != UmacCommand::DeleteKey {
        return Err(ProtocolError::InvalidValue(command as u32));
    }
    Ok(())
}

/// Encodes `NRF_WIFI_UMAC_CMD_SET_KEY`.
pub fn encode_set_key(
    out: &mut [u8],
    wdev_id: u32,
    key: &KeyConfig<'_>,
) -> Result<usize, ProtocolError> {
    validate_key(key)?;
    encode_umac(
        out,
        UmacCommand::SetKey,
        Some(wdev_id),
        KEY_INFO_LEN,
        |writer| write_default_key_info(writer, key),
    )
}

/// Encodes `NRF_WIFI_UMAC_CMD_SET_IFFLAGS`.
pub fn encode_interface_state(
    out: &mut [u8],
    wdev_id: u32,
    up: bool,
    firmware_index: i8,
) -> Result<usize, ProtocolError> {
    encode_umac(
        out,
        UmacCommand::SetInterfaceFlags,
        Some(wdev_id),
        5,
        |writer| {
            writer.i32(if up { 1 } else { 0 })?;
            writer.u8(firmware_index as u8)
        },
    )
}

/// Encodes `NRF_WIFI_UMAC_CMD_REQ_SET_REG`.
pub fn encode_set_regulatory(
    out: &mut [u8],
    _wdev_id: u32,
    country: [u8; 2],
    user_hint_type: u32,
    force: bool,
) -> Result<usize, ProtocolError> {
    // "00" is Nordic's explicit world regulatory domain. Otherwise require
    // an ISO/IEC 3166 alpha-2 value.
    if country != *b"00" && !country.iter().all(|value| value.is_ascii_alphabetic()) {
        return Err(ProtocolError::InvalidValue(
            u16::from_be_bytes(country) as u32
        ));
    }
    encode_umac(out, UmacCommand::RequestSetRegulatory, None, 10, |writer| {
        let mut valid = 1 | (1 << 1);
        if force {
            valid |= 1 << 2;
        }
        writer.u32(valid)?;
        writer.u32(user_hint_type)?;
        writer.bytes(&country)
    })
}

/// Encodes `NRF_WIFI_UMAC_CMD_SET_POWER_SAVE`.
pub fn encode_power_save(
    out: &mut [u8],
    wdev_id: u32,
    state: PowerSaveState,
) -> Result<usize, ProtocolError> {
    encode_umac(out, UmacCommand::SetPowerSave, Some(wdev_id), 4, |writer| {
        writer.i32(state as i32)
    })
}

/// Encodes `NRF_WIFI_UMAC_CMD_SET_POWER_SAVE_TIMEOUT`.
pub fn encode_power_save_timeout(
    out: &mut [u8],
    wdev_id: u32,
    timeout_ms: i32,
) -> Result<usize, ProtocolError> {
    encode_umac(
        out,
        UmacCommand::SetPowerSaveTimeout,
        Some(wdev_id),
        4,
        |writer| writer.i32(timeout_ms),
    )
}

/// Encodes `NRF_WIFI_UMAC_CMD_SET_STATION` for controlled-port authorization.
pub fn encode_station_authorized(
    out: &mut [u8],
    wdev_id: u32,
    peer: [u8; 6],
    authorized: bool,
) -> Result<usize, ProtocolError> {
    encode_umac(
        out,
        UmacCommand::SetStation,
        Some(wdev_id),
        4 + CHANGE_STATION_INFO_LEN,
        |writer| write_station_authorized_body(writer, peer, authorized),
    )
}

fn write_station_authorized_body(
    writer: &mut Writer<'_>,
    peer: [u8; 6],
    authorized: bool,
) -> Result<(), ProtocolError> {
    write_station_authorized_flags(writer, authorized)?;
    writer.zeros(512)?;
    writer.bytes(&peer)?;
    writer.zeros(3)
}

fn write_station_authorized_flags(
    writer: &mut Writer<'_>,
    authorized: bool,
) -> Result<(), ProtocolError> {
    writer.u32(SET_STATION_FLAGS_VALID)?;
    writer.zeros(260)?;
    writer.u32(STATION_FLAG_AUTHORIZED)?;
    writer.u32(if authorized {
        STATION_FLAG_AUTHORIZED
    } else {
        0
    })
}

/// Parses one UMAC control event.
pub fn parse_control_event(message: HostMessageRef<'_>) -> Result<ControlEvent<'_>, ProtocolError> {
    let (header, body) = parse_umac_event(message)?;
    if is_scan_or_connection_event(header.command_event) {
        return parse_scan_or_connection_event(header, body);
    }
    if is_disconnect_event(header.command_event) {
        return parse_disconnect_event(header, body);
    }
    parse_status_event(header, body)
}

fn is_scan_or_connection_event(event: u32) -> bool {
    matches!(event, 259..=263)
}

fn is_disconnect_event(event: u32) -> bool {
    event == UmacEvent::Deauthenticate as u32 || event == UmacEvent::Disassociate as u32
}

fn parse_scan_or_connection_event(
    header: UmacHeader,
    body: &[u8],
) -> Result<ControlEvent<'_>, ProtocolError> {
    const SCAN_DONE: u32 = UmacEvent::ScanDone as u32;
    const SCAN_RESULT: u32 = UmacEvent::ScanResult as u32;
    const AUTHENTICATE: u32 = UmacEvent::Authenticate as u32;
    const ASSOCIATE: u32 = UmacEvent::Associate as u32;
    match header.command_event {
        SCAN_DONE => parse_scan_done_event(header, body),
        SCAN_RESULT => parse_scan_result_event(header, body),
        AUTHENTICATE => parse_authentication_event(header, body),
        ASSOCIATE => parse_association_event(header, body),
        _ => Ok(ControlEvent::Other { header, body }),
    }
}

fn parse_scan_done_event(
    header: UmacHeader,
    body: &[u8],
) -> Result<ControlEvent<'_>, ProtocolError> {
    require_len(body, 8)?;
    Ok(ControlEvent::ScanDone {
        header,
        status: read_i32(body, 0),
        scan_type: read_u32(body, 4),
    })
}

fn parse_scan_result_event(
    header: UmacHeader,
    body: &[u8],
) -> Result<ControlEvent<'_>, ProtocolError> {
    Ok(ControlEvent::ScanResult(parse_scan_result(header, body)?))
}

fn parse_authentication_event(
    header: UmacHeader,
    body: &[u8],
) -> Result<ControlEvent<'_>, ProtocolError> {
    Ok(ControlEvent::Authentication(parse_mlme(header, body)?))
}

fn parse_association_event(
    header: UmacHeader,
    body: &[u8],
) -> Result<ControlEvent<'_>, ProtocolError> {
    Ok(ControlEvent::Association(parse_mlme(header, body)?))
}

fn parse_disconnect_event(
    header: UmacHeader,
    body: &[u8],
) -> Result<ControlEvent<'_>, ProtocolError> {
    if header.command_event == UmacEvent::Deauthenticate as u32 {
        Ok(ControlEvent::Deauthentication(parse_mlme(header, body)?))
    } else {
        Ok(ControlEvent::Disassociation(parse_mlme(header, body)?))
    }
}

fn parse_status_event(header: UmacHeader, body: &[u8]) -> Result<ControlEvent<'_>, ProtocolError> {
    const COMMAND_STATUS: u32 = UmacEvent::CommandStatus as u32;
    const INTERFACE_FLAGS_STATUS: u32 = UmacEvent::InterfaceFlagsStatus as u32;
    match header.command_event {
        COMMAND_STATUS => parse_command_status_event(header, body),
        INTERFACE_FLAGS_STATUS => parse_interface_status_event(header, body),
        EVENT_REGULATORY_CHANGE => parse_regulatory_change_event(header, body),
        _ => Ok(ControlEvent::Other { header, body }),
    }
}

fn parse_command_status_event(
    header: UmacHeader,
    body: &[u8],
) -> Result<ControlEvent<'_>, ProtocolError> {
    require_len(body, 8)?;
    Ok(ControlEvent::CommandStatus {
        header,
        command: read_u32(body, 0),
        status: read_u32(body, 4),
    })
}

fn parse_interface_status_event(
    header: UmacHeader,
    body: &[u8],
) -> Result<ControlEvent<'_>, ProtocolError> {
    require_len(body, 4)?;
    Ok(ControlEvent::InterfaceState {
        header,
        status: read_i32(body, 0),
    })
}

fn parse_regulatory_change_event(
    header: UmacHeader,
    body: &[u8],
) -> Result<ControlEvent<'_>, ProtocolError> {
    require_len(body, 9)?;
    Ok(ControlEvent::RegulatoryChange {
        header,
        country: [body[7], body[8]],
    })
}

fn parse_mlme<'a>(header: UmacHeader, body: &'a [u8]) -> Result<MlmeEvent<'a>, ProtocolError> {
    require_len(body, MLME_FIXED_BODY_LEN)?;
    let (frame_end, required) = mlme_variable_extents(body)?;
    Ok(MlmeEvent {
        header,
        valid_fields: read_u32(body, 0),
        frequency_mhz: read_u32(body, 4),
        signal_dbm: read_i32(body, 8),
        flags: read_u32(body, 12),
        cookie: read_u64(body, 16),
        bssid: body[428..434]
            .try_into()
            .map_err(|_| ProtocolError::InvalidLength)?,
        frame: &body[28..frame_end],
        request_information_elements: &body[MLME_FIXED_BODY_LEN..required],
    })
}

fn mlme_variable_extents(body: &[u8]) -> Result<(usize, usize), ProtocolError> {
    let frame_len = read_i32(body, 24);
    if frame_len < 0 || frame_len as usize > 400 {
        return Err(ProtocolError::InvalidLength);
    }
    let request_ie_len = read_u32(body, 435) as usize;
    let required = MLME_FIXED_BODY_LEN
        .checked_add(request_ie_len)
        .ok_or(ProtocolError::InvalidLength)?;
    require_len(body, required)?;
    Ok((28 + frame_len as usize, required))
}

fn parse_scan_result<'a>(
    header: UmacHeader,
    body: &'a [u8],
) -> Result<ScanResultEvent<'a>, ProtocolError> {
    require_len(body, SCAN_RESULT_FIXED_BODY_LEN)?;
    let (ies_end, beacon_end) = scan_result_variable_extents(body)?;
    let signal = normalized_scan_signal(read_u32(body, 48), read_i32(body, 52));
    Ok(ScanResultEvent {
        header,
        valid_fields: read_u32(body, 0),
        frequency_mhz: read_u32(body, 8),
        channel_width: read_u32(body, 12),
        seen_ms_ago: read_u32(body, 16),
        status: read_i32(body, 24),
        signal,
        bssid: body[56..62]
            .try_into()
            .map_err(|_| ProtocolError::InvalidLength)?,
        beacon_interval: read_u16(body, 44),
        capability: read_u16(body, 46),
        information_elements: &body[SCAN_RESULT_FIXED_BODY_LEN..ies_end],
        beacon_information_elements: &body[ies_end..beacon_end],
    })
}

fn scan_result_variable_extents(body: &[u8]) -> Result<(usize, usize), ProtocolError> {
    let ies_len = read_u32(body, 62) as usize;
    let beacon_len = read_u32(body, 66) as usize;
    let ies_end = SCAN_RESULT_FIXED_BODY_LEN
        .checked_add(ies_len)
        .ok_or(ProtocolError::InvalidLength)?;
    let beacon_end = ies_end
        .checked_add(beacon_len)
        .ok_or(ProtocolError::InvalidLength)?;
    require_len(body, beacon_end)?;
    Ok((ies_end, beacon_end))
}

fn normalized_scan_signal(signal_type: u32, signal: i32) -> i32 {
    if signal_type == 2 {
        signal / 100
    } else {
        signal
    }
}

fn encode_umac<F>(
    out: &mut [u8],
    command: UmacCommand,
    wdev_id: Option<u32>,
    body_len: usize,
    encode_body: F,
) -> Result<usize, ProtocolError>
where
    F: FnOnce(&mut Writer<'_>) -> Result<(), ProtocolError>,
{
    let total = validated_station_message_len(out.len(), body_len)?;
    let mut writer = Writer::new(&mut out[..total]);
    write_station_headers(&mut writer, total, command, wdev_id)?;
    encode_body(&mut writer)?;
    if writer.len() != total {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(total)
}

fn validated_station_message_len(out_len: usize, body_len: usize) -> Result<usize, ProtocolError> {
    let total = HOST_HEADER_LEN
        .checked_add(UMAC_HEADER_LEN)
        .and_then(|value| value.checked_add(body_len))
        .ok_or(ProtocolError::InvalidLength)?;
    if total > out_len {
        return Err(ProtocolError::BufferTooSmall);
    }
    if total > MAX_STATION_MESSAGE_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    Ok(total)
}

fn write_station_headers(
    writer: &mut Writer<'_>,
    total: usize,
    command: UmacCommand,
    wdev_id: Option<u32>,
) -> Result<(), ProtocolError> {
    write_station_host_header(writer, total)?;
    write_station_command_header(writer, command)?;
    write_station_index_header(writer, wdev_id)
}

fn write_station_host_header(writer: &mut Writer<'_>, total: usize) -> Result<(), ProtocolError> {
    writer.u32(total as u32)?;
    writer.u32(0)?;
    writer.i32(HostMessageType::Umac as i32)
}

fn write_station_command_header(
    writer: &mut Writer<'_>,
    command: UmacCommand,
) -> Result<(), ProtocolError> {
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(command as u32)?;
    writer.i32(0)
}

fn write_station_index_header(
    writer: &mut Writer<'_>,
    wdev_id: Option<u32>,
) -> Result<(), ProtocolError> {
    writer.u32(if wdev_id.is_some() {
        INDEX_WDEV_VALID
    } else {
        0
    })?;
    writer.i32(0)?;
    writer.i32(0)?;
    writer.u64(wdev_id.unwrap_or(0) as u64)
}

fn validate_ssid(ssid: &[u8]) -> Result<(), ProtocolError> {
    if ssid.len() > 32 {
        Err(ProtocolError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn validate_ie(ie: &[u8]) -> Result<(), ProtocolError> {
    if ie.len() > MAX_IE_LEN {
        Err(ProtocolError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn validate_key(key: &KeyConfig<'_>) -> Result<(), ProtocolError> {
    if key.key.len() > MAX_KEY_LEN {
        return Err(ProtocolError::LimitExceeded);
    }
    if key.sequence.len() > MAX_KEY_SEQUENCE_LEN {
        return Err(ProtocolError::LimitExceeded);
    }
    if key.key_index > 3 {
        return Err(ProtocolError::LimitExceeded);
    }
    Ok(())
}

fn write_key_info(
    writer: &mut Writer<'_>,
    key: Option<&KeyConfig<'_>>,
) -> Result<(), ProtocolError> {
    let Some(key) = key else {
        return writer.zeros(KEY_INFO_LEN);
    };
    let mut valid = KEY_TYPE_VALID | KEY_INDEX_VALID | KEY_CIPHER_VALID;
    if !key.key.is_empty() {
        valid |= KEY_DATA_VALID;
    }
    if !key.sequence.is_empty() {
        valid |= KEY_SEQUENCE_VALID;
    }
    write_key_info_header(writer, key, valid)?;
    write_key_info_material(writer, key)
}

fn write_key_info_header(
    writer: &mut Writer<'_>,
    key: &KeyConfig<'_>,
    valid: u32,
) -> Result<(), ProtocolError> {
    writer.u32(valid)?;
    writer.u32(key.cipher_suite)?;
    writer.u16(key.flags)?;
    writer.i32(key.key_type as i32)
}

fn write_key_info_material(
    writer: &mut Writer<'_>,
    key: &KeyConfig<'_>,
) -> Result<(), ProtocolError> {
    writer.u32(key.key.len() as u32)?;
    writer.fixed(key.key, MAX_KEY_LEN)?;
    writer.i32(key.sequence.len() as i32)?;
    writer.fixed(key.sequence, MAX_KEY_SEQUENCE_LEN)?;
    writer.u8(key.key_index)
}

fn write_default_key_info(
    writer: &mut Writer<'_>,
    key: &KeyConfig<'_>,
) -> Result<(), ProtocolError> {
    // nrf_wifi_sys_fmac_set_key accepts only the key index as a valid field;
    // the default-key selection flags are carried independently.
    write_default_key_header(writer, key)?;
    write_default_key_material(writer, key)
}

fn write_default_key_header(
    writer: &mut Writer<'_>,
    key: &KeyConfig<'_>,
) -> Result<(), ProtocolError> {
    writer.u32(KEY_INDEX_VALID)?;
    writer.u32(0)?;
    writer.u16(key.flags)?;
    writer.i32(0)
}

fn write_default_key_material(
    writer: &mut Writer<'_>,
    key: &KeyConfig<'_>,
) -> Result<(), ProtocolError> {
    writer.u32(0)?;
    writer.zeros(MAX_KEY_LEN)?;
    writer.i32(0)?;
    writer.zeros(MAX_KEY_SEQUENCE_LEN)?;
    writer.u8(key.key_index)
}

fn require_len(bytes: &[u8], len: usize) -> Result<(), ProtocolError> {
    if bytes.len() < len {
        Err(ProtocolError::InvalidLength)
    } else {
        Ok(())
    }
}

impl Writer<'_> {
    fn ssid(&mut self, value: &[u8]) -> Result<(), ProtocolError> {
        validate_ssid(value)?;
        self.u8(value.len() as u8)?;
        self.fixed(value, 32)
    }

    fn ie(&mut self, value: &[u8]) -> Result<(), ProtocolError> {
        validate_ie(value)?;
        self.u16(value.len() as u16)?;
        self.fixed(value, MAX_IE_LEN)
    }
}

#[cfg(test)]
mod tests {
    use std::vec;
    use std::vec::Vec;

    use super::super::protocol::{HostMessageType, encode_host_message};
    use super::*;

    fn event_payload(event: u32, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![0; UMAC_HEADER_LEN];
        payload[8..12].copy_from_slice(&event.to_le_bytes());
        payload.extend_from_slice(body);
        payload
    }

    fn event_message(payload: &[u8]) -> HostMessageRef<'_> {
        HostMessageRef {
            resubmit: false,
            message_type: HostMessageType::Umac,
            payload,
        }
    }

    #[test]
    fn auth_and_assoc_lengths_match_the_packed_abi() {
        let auth = AuthenticationRequest {
            frequency_mhz: 2412,
            bssid: [1, 2, 3, 4, 5, 6],
            ssid: b"test",
            auth_type: AuthenticationType::OpenSystem,
            local_state_change: false,
            information_elements: &[],
            sae_data: &[],
            key: None,
            bss: BssContext::default(),
        };
        let mut bytes = [0u8; MAX_STATION_MESSAGE_LEN];
        assert_eq!(
            encode_authenticate(&mut bytes, 1, &auth).unwrap(),
            AUTH_MESSAGE_LEN
        );
        assert_eq!(read_u32(&bytes, HOST_HEADER_LEN + 16), INDEX_WDEV_VALID);
        assert_eq!(read_i32(&bytes, HOST_HEADER_LEN + 20), 0);
        assert_eq!(read_u64(&bytes, HOST_HEADER_LEN + 28), 1);
        assert_eq!(
            read_u32(&bytes, HOST_HEADER_LEN + UMAC_HEADER_LEN),
            AUTH_FREQUENCY_VALID | AUTH_SSID_VALID
        );

        let assoc = AssociationRequest {
            frequency_mhz: 2412,
            bssid: [1, 2, 3, 4, 5, 6],
            ssid: b"test",
            security: None,
            background_scan_period_s: 0,
            previous_bssid: None,
            bss_max_idle_s: 0,
        };
        assert_eq!(
            encode_associate(&mut bytes, 1, &assoc).unwrap(),
            ASSOC_MESSAGE_LEN
        );
    }

    #[test]
    fn complete_authentication_body_is_exact() {
        let key = KeyConfig {
            cipher_suite: RSN_CIPHER_CCMP_128,
            key_type: KeyType::Pairwise,
            key_index: 2,
            key: &[0x55; 16],
            sequence: &[1, 2, 3],
            flags: 9,
        };
        let request = AuthenticationRequest {
            frequency_mhz: 2437,
            bssid: [1, 2, 3, 4, 5, 6],
            ssid: b"secure",
            auth_type: AuthenticationType::Sae,
            local_state_change: true,
            information_elements: &[0xdd, 1, 0xaa],
            sae_data: &[7, 8],
            key: Some(&key),
            bss: BssContext {
                scan_width: 2,
                signal_dbm: -55,
                from_beacon: true,
                information_elements: &[0x30, 0],
                capability: 0x1234,
                beacon_interval: 100,
                tsf: 0x0102_0304_0506_0708,
            },
        };
        let mut bytes = [0u8; MAX_STATION_MESSAGE_LEN];
        let len = encode_authenticate(&mut bytes, 5, &request).unwrap();
        assert_eq!(len, AUTH_MESSAGE_LEN);
        let body = &bytes[HOST_HEADER_LEN + UMAC_HEADER_LEN..len];
        assert_eq!(
            read_u32(body, 0),
            AUTH_FREQUENCY_VALID | AUTH_SSID_VALID | AUTH_KEY_INFO_VALID | AUTH_SAE_VALID
        );
        assert_eq!(read_u32(body, 4), 2437);
        assert_eq!(read_u16(body, 8), AUTH_LOCAL_STATE_CHANGE);
        assert_eq!(read_i32(body, 10), AuthenticationType::Sae as i32);
        assert_eq!(read_u32(body, 14), 0b1_1111);
        assert_eq!(read_u32(body, 18), RSN_CIPHER_CCMP_128);
        assert_eq!(read_u16(body, 22), 9);
        assert_eq!(body[548], 2);
        assert_eq!(body[549], 6);
        assert_eq!(&body[550..556], b"secure");
        assert_eq!(read_u16(body, 582), 3);
        assert_eq!(&body[584..587], &[0xdd, 1, 0xaa]);
        assert_eq!(read_i32(body, 984), 2);
        assert_eq!(&body[988..990], &[7, 8]);
        assert_eq!(&body[1244..1250], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(read_i32(body, 1250), 2);
        assert_eq!(read_i32(body, 1254), -55);
        assert_eq!(read_i32(body, 1258), 1);
        assert_eq!(read_u16(body, 1664), 0x1234);
        assert_eq!(read_u16(body, 1666), 100);
        assert_eq!(read_u64(body, 1668), 0x0102_0304_0506_0708);
    }

    #[test]
    fn authentication_rejects_each_fixed_capacity_limit() {
        let mut bytes = [0u8; MAX_STATION_MESSAGE_LEN];
        let oversized_ssid = [0; 33];
        let oversized_ie = [0; MAX_IE_LEN + 1];
        let oversized_sae = [0; MAX_SAE_LEN + 1];
        let oversized_key = [0; MAX_KEY_LEN + 1];
        let oversized_sequence = [0; MAX_KEY_SEQUENCE_LEN + 1];
        let invalid_keys = [
            KeyConfig::pairwise(RSN_CIPHER_CCMP_128, 0, &oversized_key),
            KeyConfig {
                cipher_suite: RSN_CIPHER_CCMP_128,
                key_type: KeyType::Pairwise,
                key_index: 0,
                key: &[0; 16],
                sequence: &oversized_sequence,
                flags: 0,
            },
            KeyConfig {
                cipher_suite: RSN_CIPHER_CCMP_128,
                key_type: KeyType::Pairwise,
                key_index: 4,
                key: &[0; 16],
                sequence: &[],
                flags: 0,
            },
        ];

        let base = |ssid, information_elements, sae_data, key, bss_information_elements| {
            AuthenticationRequest {
                frequency_mhz: 2412,
                bssid: [0; 6],
                ssid,
                auth_type: AuthenticationType::OpenSystem,
                local_state_change: false,
                information_elements,
                sae_data,
                key,
                bss: BssContext {
                    information_elements: bss_information_elements,
                    ..BssContext::default()
                },
            }
        };
        for request in [
            base(&oversized_ssid, &[], &[], None, &[]),
            base(b"ok", &oversized_ie, &[], None, &[]),
            base(b"ok", &[], &[], None, &oversized_ie),
            base(b"ok", &[], &oversized_sae, None, &[]),
        ] {
            assert_eq!(
                encode_authenticate(&mut bytes, 1, &request),
                Err(ProtocolError::LimitExceeded)
            );
        }
        for key in &invalid_keys {
            let request = base(b"ok", &[], &[], Some(key), &[]);
            assert_eq!(
                encode_authenticate(&mut bytes, 1, &request),
                Err(ProtocolError::LimitExceeded)
            );
        }
    }

    #[test]
    fn secure_association_body_and_limits_are_exact() {
        let security = AssociationSecurity {
            pairwise_ciphers: &[RSN_CIPHER_CCMP_128, RSN_CIPHER_GCMP_128],
            group_cipher: RSN_CIPHER_CCMP_128,
            akm_suites: &[RSN_AKM_PSK],
            mfp: MfpMode::Required,
            rsn_information_element: &[0x30, 0],
        };
        let previous = [6, 5, 4, 3, 2, 1];
        let request = AssociationRequest {
            frequency_mhz: 2462,
            bssid: [1, 2, 3, 4, 5, 6],
            ssid: b"secure",
            security: Some(security),
            background_scan_period_s: 9,
            previous_bssid: Some(previous),
            bss_max_idle_s: 30,
        };
        let mut bytes = [0u8; MAX_STATION_MESSAGE_LEN];
        let len = encode_associate(&mut bytes, 7, &request).unwrap();
        assert_eq!(len, ASSOC_MESSAGE_LEN);
        let body = &bytes[HOST_HEADER_LEN + UMAC_HEADER_LEN..len];
        assert_eq!(read_u32(body, 0), ASSOC_PREVIOUS_BSSID_VALID);
        assert_eq!(
            read_u32(body, 4),
            CONNECT_MAC_VALID
                | CONNECT_FREQUENCY_VALID
                | CONNECT_BG_SCAN_VALID
                | CONNECT_SSID_VALID
                | CONNECT_WPA_IE_VALID
                | CONNECT_WPA_VERSIONS_VALID
                | CONNECT_PAIRWISE_VALID
                | CONNECT_GROUP_VALID
                | CONNECT_AKM_VALID
                | CONNECT_MFP_VALID
                | CONNECT_CONTROL_PORT_ETHERTYPE_VALID
                | CONNECT_CONTROL_PORT_NO_ENCRYPT_VALID
                | CONNECT_PREVIOUS_BSSID_VALID
                | CONNECT_SECURITY_VALID
        );
        assert_eq!(read_u32(body, 8), 2462);
        assert_eq!(read_u32(body, 16), WPA_VERSION_2);
        assert_eq!(read_i32(body, 20), 2);
        assert_eq!(read_u32(body, 24), RSN_CIPHER_CCMP_128);
        assert_eq!(read_u32(body, 28), RSN_CIPHER_GCMP_128);
        assert_eq!(read_u32(body, 52), RSN_CIPHER_CCMP_128);
        assert_eq!(read_u32(body, 56), 1);
        assert_eq!(read_u32(body, 60), RSN_AKM_PSK);
        assert_eq!(read_i32(body, 68), MfpMode::Required as i32);
        assert_eq!(read_u16(body, 76), 9);
        assert_eq!(&body[78..84], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(body[90], 6);
        assert_eq!(&body[91..97], b"secure");
        assert_eq!(read_u16(body, 123), 2);
        assert_eq!(read_u16(body, 1555), EAPOL_ETHERTYPE);
        assert_eq!(&body[1559..1565], &previous);
        assert_eq!(read_u16(body, 1565), 30);
        assert_eq!(&body[1567..1573], &previous);

        let oversized_ie = [0; MAX_IE_LEN + 1];
        let too_many_pairwise = [0; MAX_PAIRWISE_CIPHERS + 1];
        let too_many_akm = [0; MAX_AKM_SUITES + 1];
        for security in [
            AssociationSecurity {
                pairwise_ciphers: &[],
                group_cipher: 0,
                akm_suites: &[1],
                mfp: MfpMode::Disabled,
                rsn_information_element: &[],
            },
            AssociationSecurity {
                pairwise_ciphers: &too_many_pairwise,
                group_cipher: 0,
                akm_suites: &[1],
                mfp: MfpMode::Disabled,
                rsn_information_element: &[],
            },
            AssociationSecurity {
                pairwise_ciphers: &[1],
                group_cipher: 0,
                akm_suites: &[],
                mfp: MfpMode::Disabled,
                rsn_information_element: &[],
            },
            AssociationSecurity {
                pairwise_ciphers: &[1],
                group_cipher: 0,
                akm_suites: &too_many_akm,
                mfp: MfpMode::Disabled,
                rsn_information_element: &[],
            },
            AssociationSecurity {
                pairwise_ciphers: &[1],
                group_cipher: 0,
                akm_suites: &[1],
                mfp: MfpMode::Disabled,
                rsn_information_element: &oversized_ie,
            },
        ] {
            let request = AssociationRequest {
                frequency_mhz: 2412,
                bssid: [0; 6],
                ssid: b"ok",
                security: Some(security),
                background_scan_period_s: 0,
                previous_bssid: None,
                bss_max_idle_s: 0,
            };
            assert_eq!(
                encode_associate(&mut bytes, 1, &request),
                Err(ProtocolError::LimitExceeded)
            );
        }
    }

    #[test]
    fn key_length_matches_the_packed_abi() {
        let key = KeyConfig::pairwise(RSN_CIPHER_CCMP_128, 0, &[0x55; 16]);
        let mut bytes = [0u8; MAX_STATION_MESSAGE_LEN];
        assert_eq!(
            encode_key_command(
                &mut bytes,
                1,
                UmacCommand::NewKey,
                Some([1, 2, 3, 4, 5, 6]),
                &key,
            )
            .unwrap(),
            KEY_MESSAGE_LEN
        );
        let body = HOST_HEADER_LEN + UMAC_HEADER_LEN;
        assert_eq!(read_u32(&bytes, body), KEY_MAC_VALID);
        assert_eq!(
            read_u32(&bytes, body + 4),
            KEY_DATA_VALID | KEY_TYPE_VALID | KEY_INDEX_VALID | KEY_CIPHER_VALID
        );

        let group = KeyConfig {
            cipher_suite: RSN_CIPHER_CCMP_128,
            key_type: KeyType::Group,
            key_index: 1,
            key: &[0x66; 16],
            sequence: &[0; 8],
            flags: 1 << 4,
        };
        encode_key_command(&mut bytes, 1, UmacCommand::NewKey, None, &group).unwrap();
        assert_eq!(read_u32(&bytes, body), 0);
        assert_eq!(
            read_u32(&bytes, body + 4),
            KEY_DATA_VALID
                | KEY_TYPE_VALID
                | KEY_INDEX_VALID
                | KEY_SEQUENCE_VALID
                | KEY_CIPHER_VALID
        );
        assert_eq!(
            u16::from_le_bytes([bytes[body + 12], bytes[body + 13]]),
            1 << 4
        );

        let default_group = KeyConfig {
            cipher_suite: 0,
            key_type: KeyType::Group,
            key_index: 1,
            key: &[],
            sequence: &[],
            flags: (1 << 0) | (1 << 4),
        };
        encode_set_key(&mut bytes, 1, &default_group).unwrap();
        assert_eq!(read_u32(&bytes, body), KEY_INDEX_VALID);
        assert_eq!(u16::from_le_bytes([bytes[body + 8], bytes[body + 9]]), 0x11);

        assert!(
            encode_key_command(&mut bytes, 1, UmacCommand::DeleteKey, None, &default_group).is_ok()
        );
        assert_eq!(
            encode_key_command(&mut bytes, 1, UmacCommand::SetKey, None, &default_group,),
            Err(ProtocolError::InvalidValue(UmacCommand::SetKey as u32))
        );
    }

    #[test]
    fn command_status_is_parsed() {
        let mut payload = [0u8; UMAC_HEADER_LEN + 8];
        payload[8..12].copy_from_slice(&(UmacEvent::CommandStatus as u32).to_le_bytes());
        payload[UMAC_HEADER_LEN..UMAC_HEADER_LEN + 4]
            .copy_from_slice(&(UmacCommand::Associate as u32).to_le_bytes());
        payload[UMAC_HEADER_LEN + 4..].copy_from_slice(&7u32.to_le_bytes());
        let mut message = [0u8; HOST_HEADER_LEN + UMAC_HEADER_LEN + 8];
        let len =
            encode_host_message(&mut message, HostMessageType::Umac, false, &payload).unwrap();
        let parsed = super::super::protocol::parse_host_message(&message[..len]).unwrap();
        assert!(matches!(
            parse_control_event(parsed).unwrap(),
            ControlEvent::CommandStatus {
                command: 3,
                status: 7,
                ..
            }
        ));
    }

    #[test]
    fn every_control_event_variant_and_length_boundary_is_parsed() {
        let scan_done = event_payload(
            UmacEvent::ScanDone as u32,
            &[0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0],
        );
        assert!(matches!(
            parse_control_event(event_message(&scan_done)),
            Ok(ControlEvent::ScanDone {
                status: -1,
                scan_type: 2,
                ..
            })
        ));
        let short_scan_done = event_payload(UmacEvent::ScanDone as u32, &[0; 7]);
        assert_eq!(
            parse_control_event(event_message(&short_scan_done)),
            Err(ProtocolError::InvalidLength)
        );

        let mut mlme = vec![0; MLME_FIXED_BODY_LEN + 2];
        mlme[0..4].copy_from_slice(&0x11u32.to_le_bytes());
        mlme[4..8].copy_from_slice(&2412u32.to_le_bytes());
        mlme[8..12].copy_from_slice(&(-42i32).to_le_bytes());
        mlme[12..16].copy_from_slice(&0x22u32.to_le_bytes());
        mlme[16..24].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        mlme[24..28].copy_from_slice(&4i32.to_le_bytes());
        mlme[28..32].copy_from_slice(&[1, 2, 3, 4]);
        mlme[428..434].copy_from_slice(&[6, 5, 4, 3, 2, 1]);
        mlme[435..439].copy_from_slice(&2u32.to_le_bytes());
        mlme[439..441].copy_from_slice(&[0x30, 0]);
        for (event, expected) in [
            (UmacEvent::Authenticate, 0),
            (UmacEvent::Associate, 1),
            (UmacEvent::Deauthenticate, 2),
            (UmacEvent::Disassociate, 3),
        ] {
            let payload = event_payload(event as u32, &mlme);
            let parsed = parse_control_event(event_message(&payload)).unwrap();
            let value = match parsed {
                ControlEvent::Authentication(value) if expected == 0 => value,
                ControlEvent::Association(value) if expected == 1 => value,
                ControlEvent::Deauthentication(value) if expected == 2 => value,
                ControlEvent::Disassociation(value) if expected == 3 => value,
                other => panic!("unexpected MLME event: {other:?}"),
            };
            assert_eq!(value.frequency_mhz, 2412);
            assert_eq!(value.signal_dbm, -42);
            assert_eq!(value.frame, &[1, 2, 3, 4]);
            assert_eq!(value.bssid, [6, 5, 4, 3, 2, 1]);
            assert_eq!(value.request_information_elements, &[0x30, 0]);
        }

        let mut scan = vec![0; SCAN_RESULT_FIXED_BODY_LEN + 3];
        scan[0..4].copy_from_slice(&1u32.to_le_bytes());
        scan[8..12].copy_from_slice(&2437u32.to_le_bytes());
        scan[12..16].copy_from_slice(&2u32.to_le_bytes());
        scan[16..20].copy_from_slice(&9u32.to_le_bytes());
        scan[24..28].copy_from_slice(&(-3i32).to_le_bytes());
        scan[44..46].copy_from_slice(&100u16.to_le_bytes());
        scan[46..48].copy_from_slice(&0x1234u16.to_le_bytes());
        scan[48..52].copy_from_slice(&2u32.to_le_bytes());
        scan[52..56].copy_from_slice(&(-5500i32).to_le_bytes());
        scan[56..62].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        scan[62..66].copy_from_slice(&2u32.to_le_bytes());
        scan[66..70].copy_from_slice(&1u32.to_le_bytes());
        scan[70..73].copy_from_slice(&[0x30, 0, 0xdd]);
        let payload = event_payload(UmacEvent::ScanResult as u32, &scan);
        let ControlEvent::ScanResult(result) =
            parse_control_event(event_message(&payload)).unwrap()
        else {
            panic!("expected scan result")
        };
        assert_eq!(result.frequency_mhz, 2437);
        assert_eq!(result.signal, -55);
        assert_eq!(result.information_elements, &[0x30, 0]);
        assert_eq!(result.beacon_information_elements, &[0xdd]);
        assert_eq!(normalized_scan_signal(1, -44), -44);

        let interface = event_payload(
            UmacEvent::InterfaceFlagsStatus as u32,
            &(-7i32).to_le_bytes(),
        );
        assert!(matches!(
            parse_control_event(event_message(&interface)),
            Ok(ControlEvent::InterfaceState { status: -7, .. })
        ));
        let regulatory = event_payload(EVENT_REGULATORY_CHANGE, &[0, 0, 0, 0, 0, 0, 0, b'U', b'S']);
        assert!(matches!(
            parse_control_event(event_message(&regulatory)),
            Ok(ControlEvent::RegulatoryChange {
                country: [b'U', b'S'],
                ..
            })
        ));
        let other = event_payload(999, &[1, 2]);
        assert!(matches!(
            parse_control_event(event_message(&other)),
            Ok(ControlEvent::Other { body, .. }) if body == [1, 2]
        ));
        let connect = event_payload(UmacEvent::Connect as u32, &[3, 4]);
        assert!(matches!(
            parse_control_event(event_message(&connect)),
            Ok(ControlEvent::Other { body, .. }) if body == [3, 4]
        ));

        for (event, body) in [
            (UmacEvent::CommandStatus as u32, &[0; 7][..]),
            (UmacEvent::InterfaceFlagsStatus as u32, &[0; 3][..]),
            (EVENT_REGULATORY_CHANGE, &[0; 8][..]),
        ] {
            let payload = event_payload(event, body);
            assert_eq!(
                parse_control_event(event_message(&payload)),
                Err(ProtocolError::InvalidLength)
            );
        }
    }

    #[test]
    fn mlme_and_scan_variable_lengths_are_fail_closed() {
        let header = UmacHeader {
            port_id: 0,
            sequence: 0,
            command_event: 0,
            result: 0,
            valid_ids: 0,
            ifaceindex: 0,
            wiphy_index: 0,
            wdev_id: 0,
        };
        assert_eq!(
            parse_mlme(header, &[0; MLME_FIXED_BODY_LEN - 1]),
            Err(ProtocolError::InvalidLength)
        );
        for frame_len in [-1i32, 401] {
            let mut body = [0; MLME_FIXED_BODY_LEN];
            body[24..28].copy_from_slice(&frame_len.to_le_bytes());
            assert_eq!(parse_mlme(header, &body), Err(ProtocolError::InvalidLength));
        }
        let mut missing_request_ie = [0; MLME_FIXED_BODY_LEN];
        missing_request_ie[435..439].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            parse_mlme(header, &missing_request_ie),
            Err(ProtocolError::InvalidLength)
        );

        assert_eq!(
            parse_scan_result(header, &[0; SCAN_RESULT_FIXED_BODY_LEN - 1]),
            Err(ProtocolError::InvalidLength)
        );
        let mut missing_ies = [0; SCAN_RESULT_FIXED_BODY_LEN];
        missing_ies[62..66].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            parse_scan_result(header, &missing_ies),
            Err(ProtocolError::InvalidLength)
        );
        let mut missing_beacon = [0; SCAN_RESULT_FIXED_BODY_LEN];
        missing_beacon[66..70].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            parse_scan_result(header, &missing_beacon),
            Err(ProtocolError::InvalidLength)
        );
    }

    #[test]
    fn small_control_commands_and_station_authorization_are_exact() {
        let mut out = [0u8; MAX_STATION_MESSAGE_LEN];
        let body = HOST_HEADER_LEN + UMAC_HEADER_LEN;
        encode_interface_state(&mut out, 3, true, -2).unwrap();
        assert_eq!(read_i32(&out, body), 1);
        assert_eq!(out[body + 4], (-2i8) as u8);
        encode_interface_state(&mut out, 3, false, 2).unwrap();
        assert_eq!(read_i32(&out, body), 0);

        encode_power_save(&mut out, 3, PowerSaveState::Enabled).unwrap();
        assert_eq!(read_i32(&out, body), 1);
        encode_power_save_timeout(&mut out, 3, -10).unwrap();
        assert_eq!(read_i32(&out, body), -10);

        let peer = [1, 2, 3, 4, 5, 6];
        encode_station_authorized(&mut out, 3, peer, true).unwrap();
        assert_eq!(read_u32(&out, body), SET_STATION_FLAGS_VALID);
        assert_eq!(read_u32(&out, body + 264), STATION_FLAG_AUTHORIZED);
        assert_eq!(read_u32(&out, body + 268), STATION_FLAG_AUTHORIZED);
        assert_eq!(&out[body + 784..body + 790], &peer);
        encode_station_authorized(&mut out, 3, peer, false).unwrap();
        assert_eq!(read_u32(&out, body + 268), 0);

        assert_eq!(
            validated_station_message_len(0, 0),
            Err(ProtocolError::BufferTooSmall)
        );
        assert_eq!(
            validated_station_message_len(usize::MAX, usize::MAX),
            Err(ProtocolError::InvalidLength)
        );
        assert_eq!(
            validated_station_message_len(usize::MAX, MAX_STATION_MESSAGE_LEN),
            Err(ProtocolError::BufferTooSmall)
        );
        assert_eq!(
            encode_umac(&mut out, UmacCommand::SetPowerSave, Some(1), 1, |_| Ok(())),
            Err(ProtocolError::InvalidLength)
        );
    }

    #[test]
    fn world_regulatory_domain_is_accepted() {
        let mut out = [0u8; 128];
        assert!(encode_set_regulatory(&mut out, 0, *b"00", 0, false).is_ok());
        assert_eq!(read_u32(&out, HOST_HEADER_LEN + 16), 0);
        encode_set_regulatory(&mut out, 0, *b"US", 7, true).unwrap();
        let body = HOST_HEADER_LEN + UMAC_HEADER_LEN;
        assert_eq!(read_u32(&out, body), 0b111);
        assert_eq!(read_u32(&out, body + 4), 7);
        assert_eq!(&out[body + 8..body + 10], b"US");
        assert!(matches!(
            encode_set_regulatory(&mut out, 0, *b"0A", 0, false),
            Err(ProtocolError::InvalidValue(_))
        ));
        assert!(matches!(
            encode_set_regulatory(&mut out, 0, *b"A0", 0, false),
            Err(ProtocolError::InvalidValue(_))
        ));
    }
}
