//! Private declarations for the frozen Zephyr capability ABI.
//!
//! No declaration in this module is public. The safe API owns every enum and
//! structure visible to product code, while this module mirrors the fixed C
//! wire layout exactly.

#![cfg_attr(not(feature = "zephyr"), allow(dead_code))]

#[cfg(feature = "zephyr")]
use core::ffi::c_void;

pub(crate) const ABI_MAJOR: u16 = 2;
pub(crate) const ABI_MINOR: u16 = 0;
pub(crate) const ABI_VERSION: u32 = (ABI_MAJOR as u32) << 16 | ABI_MINOR as u32;

pub(crate) const MAC_LEN: usize = 6;
pub(crate) const COUNTRY_LEN: usize = 2;
pub(crate) const MAX_SSID_LEN: usize = 32;
pub(crate) const MAX_PASSPHRASE_LEN: usize = 63;
pub(crate) const MAX_SCAN_CHANNELS: usize = 16;
pub(crate) const MAX_REG_CHANNELS: usize = 42;
pub(crate) const ETH_HEADER_LEN: usize = 14;
pub(crate) const MAX_FRAME_LEN: usize = 1600;

pub(crate) const ROLE_STA: u8 = 0;
pub(crate) const ROLE_AP: u8 = 1;

pub(crate) const STATUS_DOWN: u32 = 0;
pub(crate) const STATUS_READY: u32 = 1;
pub(crate) const STATUS_CONNECTING: u32 = 2;
pub(crate) const STATUS_CONNECTED: u32 = 3;
pub(crate) const STATUS_DISCONNECTED: u32 = 4;
pub(crate) const STATUS_FAULTED: u32 = 5;

pub(crate) const EVENT_NONE: u32 = 0;
pub(crate) const EVENT_CONNECTED: u32 = 1;
pub(crate) const EVENT_ROAMED: u32 = 2;
pub(crate) const EVENT_DISCONNECTED: u32 = 3;
pub(crate) const EVENT_ADDRESS_CHANGED: u32 = 4;
pub(crate) const EVENT_EAPOL: u32 = 5;
pub(crate) const EVENT_INTERFACE_UP: u32 = 6;
pub(crate) const EVENT_INTERFACE_DOWN: u32 = 7;
pub(crate) const EVENT_AP_STARTED: u32 = 8;
pub(crate) const EVENT_AP_STOPPED: u32 = 9;
pub(crate) const EVENT_AP_CLIENT_JOINED: u32 = 10;
pub(crate) const EVENT_AP_CLIENT_LEFT: u32 = 11;
pub(crate) const EVENT_TWT: u32 = 12;
pub(crate) const EVENT_CONNECTION_FAILED: u32 = 13;

pub(crate) const SECURITY_OPEN: u8 = 0;
pub(crate) const SECURITY_WPA2_PSK: u8 = 1;
pub(crate) const SECURITY_WPA2_PSK_SHA256: u8 = 2;
pub(crate) const SECURITY_WPA3_SAE: u8 = 3;
pub(crate) const SECURITY_WPA3_SAE_H2E: u8 = 4;
pub(crate) const SECURITY_WPA3_SAE_AUTO: u8 = 5;
pub(crate) const SECURITY_WPA_PSK: u8 = 6;
pub(crate) const SECURITY_WPA_AUTO_PERSONAL: u8 = 7;
pub(crate) const SECURITY_OTHER: u8 = 255;

pub(crate) const MFP_DISABLE: u8 = 0;
pub(crate) const MFP_OPTIONAL: u8 = 1;
pub(crate) const MFP_REQUIRED: u8 = 2;

pub(crate) const BAND_2_4_GHZ: u8 = 0;
pub(crate) const BAND_5_GHZ: u8 = 1;
pub(crate) const BAND_ANY: u8 = 255;
pub(crate) const BAND_MASK_2_4_GHZ: u8 = 1;
pub(crate) const BAND_MASK_5_GHZ: u8 = 2;
pub(crate) const CHANNEL_ANY: u8 = 255;

pub(crate) const BANDWIDTH_20_MHZ: u8 = 1;
pub(crate) const BANDWIDTH_40_MHZ: u8 = 2;
pub(crate) const BANDWIDTH_80_MHZ: u8 = 3;
pub(crate) const BANDWIDTH_AUTO: u8 = 255;

pub(crate) const CAP_STA: u64 = 1 << 0;
pub(crate) const CAP_SOFTAP: u64 = 1 << 1;
pub(crate) const CAP_CONCURRENT_STA_AP: u64 = 1 << 2;
pub(crate) const CAP_SCAN: u64 = 1 << 3;
pub(crate) const CAP_BAND_2_4_GHZ: u64 = 1 << 4;
pub(crate) const CAP_BAND_5_GHZ: u64 = 1 << 5;
pub(crate) const CAP_REG_DOMAIN: u64 = 1 << 6;
pub(crate) const CAP_POWER_SAVE: u64 = 1 << 7;
pub(crate) const CAP_TWT: u64 = 1 << 8;
pub(crate) const CAP_RAW_L2: u64 = 1 << 9;
pub(crate) const CAP_WIFI_STATS: u64 = 1 << 10;
pub(crate) const CAP_AP_CLIENT_CONTROL: u64 = 1 << 11;
pub(crate) const CAP_RUNTIME_CREDENTIALS: u64 = 1 << 12;

pub(crate) const SCAN_PENDING: u32 = 0;
pub(crate) const SCAN_RESULT: u32 = 1;
pub(crate) const SCAN_COMPLETE: u32 = 2;

pub(crate) const REG_SUPPORTED: u8 = 1;
pub(crate) const REG_PASSIVE_ONLY: u8 = 2;
pub(crate) const REG_DFS: u8 = 4;

pub(crate) const RESULT_OK: i32 = 0;
pub(crate) const RESULT_EINVAL: i32 = -22;
pub(crate) const RESULT_ENOMEM: i32 = -12;
pub(crate) const RESULT_EBUSY: i32 = -16;
pub(crate) const RESULT_EIO: i32 = -5;
pub(crate) const RESULT_ENOTSUP: i32 = -95;
pub(crate) const RESULT_ETIMEDOUT: i32 = -110;
pub(crate) const RESULT_ENOTCONN: i32 = -107;
pub(crate) const RESULT_EAGAIN: i32 = -11;
pub(crate) const RESULT_EMSGSIZE: i32 = -90;
pub(crate) const RESULT_EBADF: i32 = -9;
pub(crate) const RESULT_EPROTO: i32 = -71;
pub(crate) const RESULT_ESTATE: i32 = -2000;
pub(crate) const RESULT_ENODEV: i32 = -19;
pub(crate) const RESULT_ENETDOWN: i32 = -100;
pub(crate) const RESULT_EPERM: i32 = -1;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CapabilitiesWire {
    pub(crate) abi_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) flags: u64,
    pub(crate) bands: u8,
    pub(crate) max_sta_associations: u8,
    pub(crate) max_ap_clients: u8,
    pub(crate) max_virtual_interfaces: u8,
    pub(crate) scan_queue_capacity: u16,
    pub(crate) reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct InterfaceWire {
    pub(crate) abi_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) mac: [u8; MAC_LEN],
    pub(crate) mtu: u16,
    pub(crate) reserved: u16,
    pub(crate) status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PollWire {
    pub(crate) event: u32,
    pub(crate) status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct StatusWire {
    pub(crate) abi_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) role: u8,
    pub(crate) enabled: u8,
    pub(crate) state: u8,
    pub(crate) band: u8,
    pub(crate) channel: u16,
    pub(crate) iface_mode: u8,
    pub(crate) link_mode: u8,
    pub(crate) security: u8,
    pub(crate) mfp: u8,
    pub(crate) rssi_dbm: i16,
    pub(crate) dtim_period: u8,
    pub(crate) twt_capable: u8,
    pub(crate) beacon_interval: u16,
    pub(crate) phy_rate_kbps: u32,
    pub(crate) ssid_len: u8,
    pub(crate) reserved0: [u8; 3],
    pub(crate) ssid: [u8; MAX_SSID_LEN],
    pub(crate) bssid: [u8; MAC_LEN],
    pub(crate) reserved1: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ConnectParamsWire {
    pub(crate) ssid: *const u8,
    pub(crate) ssid_len: u32,
    pub(crate) psk: *const u8,
    pub(crate) psk_len: u32,
    pub(crate) bssid: [u8; MAC_LEN],
    pub(crate) security: u8,
    pub(crate) mfp: u8,
    pub(crate) band: u8,
    pub(crate) channel: u8,
    pub(crate) bandwidth: u8,
    pub(crate) hidden_ssid: u8,
    pub(crate) bssid_set: u8,
    pub(crate) reserved: u8,
    pub(crate) timeout_ms: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ApParamsWire {
    pub(crate) connection: ConnectParamsWire,
    pub(crate) max_inactivity_s: u32,
    pub(crate) max_clients: u8,
    pub(crate) reserved: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BandChannelWire {
    pub(crate) band: u8,
    pub(crate) channel: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ScanParamsWire {
    pub(crate) ssid: *const u8,
    pub(crate) ssid_len: u32,
    pub(crate) channels: *const BandChannelWire,
    pub(crate) channel_count: u32,
    pub(crate) dwell_time_active_ms: u16,
    pub(crate) dwell_time_passive_ms: u16,
    pub(crate) max_results: u16,
    pub(crate) scan_type: u8,
    pub(crate) bands: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ScanResultWire {
    pub(crate) ssid_len: u8,
    pub(crate) band: u8,
    pub(crate) channel: u8,
    pub(crate) security: u8,
    pub(crate) mfp: u8,
    pub(crate) rssi_dbm: i8,
    pub(crate) bssid_len: u8,
    pub(crate) reserved0: u8,
    pub(crate) ssid: [u8; MAX_SSID_LEN],
    pub(crate) bssid: [u8; MAC_LEN],
    pub(crate) reserved1: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ScanPollWire {
    pub(crate) abi_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) kind: u32,
    pub(crate) status: i32,
    pub(crate) dropped_results: u32,
    pub(crate) reserved: u32,
    pub(crate) result: ScanResultWire,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct EventWire {
    pub(crate) abi_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) event: u32,
    pub(crate) status: i32,
    pub(crate) role: u8,
    pub(crate) peer_mac: [u8; MAC_LEN],
    pub(crate) peer_mac_set: u8,
    pub(crate) dropped_events: u32,
    pub(crate) value0: u32,
    pub(crate) value1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct RegChannelWire {
    pub(crate) center_frequency_mhz: u16,
    pub(crate) max_power_dbm: i8,
    pub(crate) flags: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PowerParamWire {
    pub(crate) parameter: u8,
    pub(crate) value8: u8,
    pub(crate) value16: u16,
    pub(crate) value32: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PowerConfigWire {
    pub(crate) abi_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) enabled: u8,
    pub(crate) wakeup_mode: u8,
    pub(crate) mode: u8,
    pub(crate) exit_strategy: u8,
    pub(crate) listen_interval: u16,
    pub(crate) reserved0: u16,
    pub(crate) timeout_ms: u32,
    pub(crate) twt_flow_count: u8,
    pub(crate) twt_flow_mask: u8,
    pub(crate) reserved1: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct TwtSetupWire {
    pub(crate) interval_us: u64,
    pub(crate) wake_interval_us: u32,
    pub(crate) wake_ahead_us: u32,
    pub(crate) flow_id: u8,
    pub(crate) negotiation_type: u8,
    pub(crate) setup_command: u8,
    pub(crate) dialog_token: u8,
    pub(crate) trigger: u8,
    pub(crate) implicit: u8,
    pub(crate) announce: u8,
    pub(crate) reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct StatsWire {
    pub(crate) abi_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) beacons_received: u64,
    pub(crate) beacons_missed: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_packets: u64,
    pub(crate) tx_packets: u64,
    pub(crate) rx_errors: u64,
    pub(crate) tx_errors: u64,
    pub(crate) overruns: u64,
}

#[cfg(feature = "zephyr")]
unsafe extern "C" {
    pub(crate) fn embassy_zephyr_nrf7002_l2_abi_version() -> u32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_control_init() -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_capabilities(
        capabilities: *mut CapabilitiesWire,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_set_enabled(role: u8, enabled: u8) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_status(role: u8, status: *mut StatusWire) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_event_poll(event: *mut EventWire) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_scan_start(
        role: u8,
        params: *const ScanParamsWire,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_scan_poll(result: *mut ScanPollWire) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_connect(
        role: u8,
        params: *const ConnectParamsWire,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_disconnect(role: u8) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_ap_start(params: *const ApParamsWire) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_ap_stop() -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_ap_disconnect_client(mac: *const u8) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_set_country(
        role: u8,
        country: *const u8,
        force: u8,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_get_reg_domain(
        role: u8,
        country: *mut u8,
        channels: *mut RegChannelWire,
        capacity: u32,
        count: *mut u32,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_set_power(params: *const PowerParamWire) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_get_power(config: *mut PowerConfigWire) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_twt_setup(params: *const TwtSetupWire) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_twt_teardown(flow_id: u8, all_flows: u8) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_get_stats(role: u8, stats: *mut StatsWire) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_wifi_reset_stats(role: u8) -> i32;

    pub(crate) fn embassy_zephyr_nrf7002_l2_open_role(role: u8, handle: *mut *mut c_void) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_l2_close(handle: *mut c_void) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_l2_interface(
        handle: *mut c_void,
        interface: *mut InterfaceWire,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_l2_connect_psk(
        handle: *mut c_void,
        params: *const ConnectParamsWire,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_l2_disconnect(handle: *mut c_void) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_l2_poll(
        handle: *mut c_void,
        timeout_ms: u32,
        result: *mut PollWire,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_l2_recv(
        handle: *mut c_void,
        buffer: *mut u8,
        capacity: usize,
        received: *mut usize,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_l2_send(
        handle: *mut c_void,
        buffer: *const u8,
        length: usize,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_console_open() -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_console_read(
        buffer: *mut u8,
        capacity: usize,
        received: *mut usize,
    ) -> i32;
    pub(crate) fn embassy_zephyr_nrf7002_random_fill(buffer: *mut u8, length: usize) -> i32;
}
