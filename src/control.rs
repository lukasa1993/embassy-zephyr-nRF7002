//! Station control codecs and event parsing for the pinned Nordic UMAC ABI.
//!
//! The large authentication and association structures exceed the original
//! 1024-byte scratch limit. These codecs write directly into caller storage
//! and do not allocate.

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

const INDEX_IFACE_VALID: u32 = 1 << 1;

const AUTH_KEY_INFO_VALID: u32 = 1 << 0;
const AUTH_BSSID_VALID: u32 = 1 << 1;
const AUTH_FREQUENCY_VALID: u32 = 1 << 2;
const AUTH_SSID_VALID: u32 = 1 << 3;
const AUTH_IE_VALID: u32 = 1 << 4;
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
const KEY_FLAGS_VALID: u32 = 1 << 5;
const KEY_MAC_VALID: u32 = 1 << 0;

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
pub struct BssContext<'a> {
    pub scan_width: i32,
    pub signal_dbm: i32,
    pub from_beacon: bool,
    pub information_elements: &'a [u8],
    pub capability: u16,
    pub beacon_interval: u16,
    pub tsf: u64,
}

impl Default for BssContext<'_> {
    fn default() -> Self {
        Self {
            scan_width: 0,
            signal_dbm: 0,
            from_beacon: false,
            information_elements: &[],
            capability: 0,
            beacon_interval: 0,
            tsf: 0,
        }
    }
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
    ifaceindex: i32,
    request: &AuthenticationRequest<'_>,
) -> Result<usize, ProtocolError> {
    validate_ssid(request.ssid)?;
    validate_ie(request.information_elements)?;
    validate_ie(request.bss.information_elements)?;
    if request.sae_data.len() > MAX_SAE_LEN {
        return Err(ProtocolError::LimitExceeded);
    }
    if let Some(key) = request.key {
        validate_key(key)?;
    }

    encode_umac(
        out,
        UmacCommand::Authenticate,
        ifaceindex,
        AUTH_BODY_LEN,
        |writer| {
            let mut valid = AUTH_BSSID_VALID | AUTH_FREQUENCY_VALID | AUTH_SSID_VALID;
            if request.key.is_some() {
                valid |= AUTH_KEY_INFO_VALID;
            }
            if !request.information_elements.is_empty() {
                valid |= AUTH_IE_VALID;
            }
            if !request.sae_data.is_empty() {
                valid |= AUTH_SAE_VALID;
            }
            writer.u32(valid)?;
            writer.u32(request.frequency_mhz)?;
            writer.u16(if request.local_state_change {
                AUTH_LOCAL_STATE_CHANGE
            } else {
                0
            })?;
            writer.i32(request.auth_type as i32)?;
            write_key_info(writer, request.key)?;
            writer.ssid(request.ssid)?;
            writer.ie(request.information_elements)?;
            writer.i32(request.sae_data.len() as i32)?;
            writer.fixed(request.sae_data, MAX_SAE_LEN)?;
            writer.bytes(&request.bssid)?;
            writer.i32(request.bss.scan_width)?;
            writer.i32(request.bss.signal_dbm)?;
            writer.i32(if request.bss.from_beacon { 1 } else { 0 })?;
            writer.ie(request.bss.information_elements)?;
            writer.u16(request.bss.capability)?;
            writer.u16(request.bss.beacon_interval)?;
            writer.u64(request.bss.tsf)
        },
    )
}

/// Encodes `NRF_WIFI_UMAC_CMD_ASSOCIATE`.
pub fn encode_associate(
    out: &mut [u8],
    ifaceindex: i32,
    request: &AssociationRequest<'_>,
) -> Result<usize, ProtocolError> {
    validate_ssid(request.ssid)?;
    if let Some(security) = &request.security {
        validate_ie(security.rsn_information_element)?;
        if security.pairwise_ciphers.is_empty()
            || security.pairwise_ciphers.len() > MAX_PAIRWISE_CIPHERS
            || security.akm_suites.is_empty()
            || security.akm_suites.len() > MAX_AKM_SUITES
        {
            return Err(ProtocolError::LimitExceeded);
        }
    }

    encode_umac(
        out,
        UmacCommand::Associate,
        ifaceindex,
        ASSOC_BODY_LEN,
        |writer| {
            writer.u32(if request.previous_bssid.is_some() {
                ASSOC_PREVIOUS_BSSID_VALID
            } else {
                0
            })?;

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
            writer.u32(valid)?;
            writer.u32(request.frequency_mhz)?;
            writer.u32(0)?;
            writer.u32(if request.security.is_some() {
                WPA_VERSION_2
            } else {
                0
            })?;

            let pairwise = request
                .security
                .as_ref()
                .map(|value| value.pairwise_ciphers)
                .unwrap_or(&[]);
            writer.i32(pairwise.len() as i32)?;
            writer.fixed_u32(pairwise, MAX_PAIRWISE_CIPHERS)?;
            writer.u32(
                request
                    .security
                    .as_ref()
                    .map(|value| value.group_cipher)
                    .unwrap_or(0),
            )?;
            let akm = request
                .security
                .as_ref()
                .map(|value| value.akm_suites)
                .unwrap_or(&[]);
            writer.u32(akm.len() as u32)?;
            writer.fixed_u32(akm, MAX_AKM_SUITES)?;
            writer.i32(
                request
                    .security
                    .as_ref()
                    .map(|value| value.mfp as i32)
                    .unwrap_or(MfpMode::Disabled as i32),
            )?;
            writer.u32(0)?;
            writer.u16(request.background_scan_period_s)?;
            writer.bytes(&request.bssid)?;
            writer.bytes(&[0; 6])?;
            writer.ssid(request.ssid)?;
            writer.ie(request
                .security
                .as_ref()
                .map(|value| value.rsn_information_element)
                .unwrap_or(&[]))?;
            writer.u32(0)?;
            writer.u16(0)?;
            writer.zeros(4 * 256)?;
            writer.u16(EAPOL_ETHERTYPE)?;
            writer.u8(1)?;
            writer.u8(1)?;
            writer.bytes(&request.previous_bssid.unwrap_or([0; 6]))?;
            writer.u16(request.bss_max_idle_s)?;
            writer.bytes(&request.previous_bssid.unwrap_or([0; 6]))
        },
    )
}

/// Encodes `NRF_WIFI_UMAC_CMD_NEW_KEY` or `NRF_WIFI_UMAC_CMD_DEL_KEY`.
pub fn encode_key_command(
    out: &mut [u8],
    ifaceindex: i32,
    command: UmacCommand,
    peer: [u8; 6],
    key: &KeyConfig<'_>,
) -> Result<usize, ProtocolError> {
    if command != UmacCommand::NewKey && command != UmacCommand::DeleteKey {
        return Err(ProtocolError::InvalidValue(command as u32));
    }
    validate_key(key)?;
    encode_umac(out, command, ifaceindex, 4 + KEY_INFO_LEN + 6, |writer| {
        writer.u32(KEY_MAC_VALID)?;
        write_key_info(writer, Some(key))?;
        writer.bytes(&peer)
    })
}

/// Encodes `NRF_WIFI_UMAC_CMD_SET_KEY`.
pub fn encode_set_key(
    out: &mut [u8],
    ifaceindex: i32,
    key: &KeyConfig<'_>,
) -> Result<usize, ProtocolError> {
    validate_key(key)?;
    encode_umac(
        out,
        UmacCommand::SetKey,
        ifaceindex,
        KEY_INFO_LEN,
        |writer| write_key_info(writer, Some(key)),
    )
}

/// Encodes `NRF_WIFI_UMAC_CMD_SET_IFFLAGS`.
pub fn encode_interface_state(
    out: &mut [u8],
    ifaceindex: i32,
    up: bool,
    firmware_index: i8,
) -> Result<usize, ProtocolError> {
    encode_umac(
        out,
        UmacCommand::SetInterfaceFlags,
        ifaceindex,
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
    ifaceindex: i32,
    country: [u8; 2],
    user_hint_type: u32,
    force: bool,
) -> Result<usize, ProtocolError> {
    if !country.iter().all(|value| value.is_ascii_alphabetic()) {
        return Err(ProtocolError::InvalidValue(
            u16::from_be_bytes(country) as u32
        ));
    }
    encode_umac(
        out,
        UmacCommand::RequestSetRegulatory,
        ifaceindex,
        10,
        |writer| {
            let mut valid = 1 | (1 << 1);
            if force {
                valid |= 1 << 2;
            }
            writer.u32(valid)?;
            writer.u32(user_hint_type)?;
            writer.bytes(&country)
        },
    )
}

/// Encodes `NRF_WIFI_UMAC_CMD_SET_POWER_SAVE`.
pub fn encode_power_save(
    out: &mut [u8],
    ifaceindex: i32,
    state: PowerSaveState,
) -> Result<usize, ProtocolError> {
    encode_umac(out, UmacCommand::SetPowerSave, ifaceindex, 4, |writer| {
        writer.i32(state as i32)
    })
}

/// Encodes `NRF_WIFI_UMAC_CMD_SET_POWER_SAVE_TIMEOUT`.
pub fn encode_power_save_timeout(
    out: &mut [u8],
    ifaceindex: i32,
    timeout_ms: i32,
) -> Result<usize, ProtocolError> {
    encode_umac(
        out,
        UmacCommand::SetPowerSaveTimeout,
        ifaceindex,
        4,
        |writer| writer.i32(timeout_ms),
    )
}

/// Parses one UMAC control event.
pub fn parse_control_event(message: HostMessageRef<'_>) -> Result<ControlEvent<'_>, ProtocolError> {
    let (header, body) = parse_umac_event(message)?;
    match header.command_event {
        value if value == UmacEvent::ScanDone as u32 => {
            require_len(body, 8)?;
            Ok(ControlEvent::ScanDone {
                header,
                status: read_i32(body, 0),
                scan_type: read_u32(body, 4),
            })
        }
        value if value == UmacEvent::ScanResult as u32 => {
            Ok(ControlEvent::ScanResult(parse_scan_result(header, body)?))
        }
        value if value == UmacEvent::Authenticate as u32 => {
            Ok(ControlEvent::Authentication(parse_mlme(header, body)?))
        }
        value if value == UmacEvent::Associate as u32 => {
            Ok(ControlEvent::Association(parse_mlme(header, body)?))
        }
        value if value == UmacEvent::Deauthenticate as u32 => {
            Ok(ControlEvent::Deauthentication(parse_mlme(header, body)?))
        }
        value if value == UmacEvent::Disassociate as u32 => {
            Ok(ControlEvent::Disassociation(parse_mlme(header, body)?))
        }
        value if value == UmacEvent::CommandStatus as u32 => {
            require_len(body, 8)?;
            Ok(ControlEvent::CommandStatus {
                header,
                command: read_u32(body, 0),
                status: read_u32(body, 4),
            })
        }
        value if value == UmacEvent::InterfaceFlagsStatus as u32 => {
            require_len(body, 4)?;
            Ok(ControlEvent::InterfaceState {
                header,
                status: read_i32(body, 0),
            })
        }
        EVENT_REGULATORY_CHANGE => {
            require_len(body, 9)?;
            Ok(ControlEvent::RegulatoryChange {
                header,
                country: [body[7], body[8]],
            })
        }
        _ => Ok(ControlEvent::Other { header, body }),
    }
}

fn parse_mlme<'a>(header: UmacHeader, body: &'a [u8]) -> Result<MlmeEvent<'a>, ProtocolError> {
    require_len(body, MLME_FIXED_BODY_LEN)?;
    let frame_len = read_i32(body, 24);
    if frame_len < 0 || frame_len as usize > 400 {
        return Err(ProtocolError::InvalidLength);
    }
    let request_ie_len = read_u32(body, 435) as usize;
    let required = MLME_FIXED_BODY_LEN
        .checked_add(request_ie_len)
        .ok_or(ProtocolError::InvalidLength)?;
    require_len(body, required)?;
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
        frame: &body[28..28 + frame_len as usize],
        request_information_elements: &body[MLME_FIXED_BODY_LEN..required],
    })
}

fn parse_scan_result<'a>(
    header: UmacHeader,
    body: &'a [u8],
) -> Result<ScanResultEvent<'a>, ProtocolError> {
    require_len(body, SCAN_RESULT_FIXED_BODY_LEN)?;
    let ies_len = read_u32(body, 62) as usize;
    let beacon_len = read_u32(body, 66) as usize;
    let ies_end = SCAN_RESULT_FIXED_BODY_LEN
        .checked_add(ies_len)
        .ok_or(ProtocolError::InvalidLength)?;
    let beacon_end = ies_end
        .checked_add(beacon_len)
        .ok_or(ProtocolError::InvalidLength)?;
    require_len(body, beacon_end)?;
    let signal_type = read_u32(body, 48);
    let signal_raw = read_i32(body, 52);
    let signal = if signal_type == 2 {
        signal_raw / 100
    } else {
        signal_raw
    };
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

fn encode_umac<F>(
    out: &mut [u8],
    command: UmacCommand,
    ifaceindex: i32,
    body_len: usize,
    encode_body: F,
) -> Result<usize, ProtocolError>
where
    F: FnOnce(&mut Writer<'_>) -> Result<(), ProtocolError>,
{
    let total = HOST_HEADER_LEN
        .checked_add(UMAC_HEADER_LEN)
        .and_then(|value| value.checked_add(body_len))
        .ok_or(ProtocolError::InvalidLength)?;
    if total > out.len() || total > MAX_STATION_MESSAGE_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    let mut writer = Writer::new(&mut out[..total]);
    writer.u32(total as u32)?;
    writer.u32(0)?;
    writer.i32(HostMessageType::Umac as i32)?;
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(command as u32)?;
    writer.i32(0)?;
    writer.u32(INDEX_IFACE_VALID)?;
    writer.i32(ifaceindex)?;
    writer.i32(0)?;
    writer.u64(0)?;
    encode_body(&mut writer)?;
    if writer.len() != total {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(total)
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
    if key.key.len() > MAX_KEY_LEN || key.sequence.len() > MAX_KEY_SEQUENCE_LEN || key.key_index > 3
    {
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
    if key.flags != 0 {
        valid |= KEY_FLAGS_VALID;
    }
    writer.u32(valid)?;
    writer.u32(key.cipher_suite)?;
    writer.u16(key.flags)?;
    writer.i32(key.key_type as i32)?;
    writer.u32(key.key.len() as u32)?;
    writer.fixed(key.key, MAX_KEY_LEN)?;
    writer.i32(key.sequence.len() as i32)?;
    writer.fixed(key.sequence, MAX_KEY_SEQUENCE_LEN)?;
    writer.u8(key.key_index)
}

fn require_len(bytes: &[u8], len: usize) -> Result<(), ProtocolError> {
    if bytes.len() < len {
        Err(ProtocolError::InvalidLength)
    } else {
        Ok(())
    }
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

    fn zeros(&mut self, count: usize) -> Result<(), ProtocolError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(ProtocolError::BufferTooSmall)?;
        let target = self
            .bytes
            .get_mut(self.position..end)
            .ok_or(ProtocolError::BufferTooSmall)?;
        target.fill(0);
        self.position = end;
        Ok(())
    }

    fn fixed(&mut self, value: &[u8], width: usize) -> Result<(), ProtocolError> {
        if value.len() > width {
            return Err(ProtocolError::LimitExceeded);
        }
        self.bytes(value)?;
        self.zeros(width - value.len())
    }

    fn fixed_u32(&mut self, value: &[u32], count: usize) -> Result<(), ProtocolError> {
        if value.len() > count {
            return Err(ProtocolError::LimitExceeded);
        }
        for item in value {
            self.u32(*item)?;
        }
        self.zeros((count - value.len()) * 4)
    }

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

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
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
    use super::super::protocol::{HostMessageType, encode_host_message};
    use super::*;

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
    fn key_length_matches_the_packed_abi() {
        let key = KeyConfig::pairwise(RSN_CIPHER_CCMP_128, 0, &[0x55; 16]);
        let mut bytes = [0u8; MAX_STATION_MESSAGE_LEN];
        assert_eq!(
            encode_key_command(&mut bytes, 1, UmacCommand::NewKey, [1, 2, 3, 4, 5, 6], &key,)
                .unwrap(),
            KEY_MESSAGE_LEN
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
}
