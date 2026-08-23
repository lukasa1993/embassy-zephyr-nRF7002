/*
 * Frozen capability boundary between Rust policy and the Zephyr/nRF70
 * mechanism layer.
 *
 * No Zephyr type crosses this header. Inputs are borrowed for one synchronous
 * call and outputs use fixed-width fields plus a size witness. Rust selects
 * every runtime parameter. Zephyr only executes the requested operation and
 * reports observations/events; supplicant reconnect and roaming remain the
 * deliberate exceptions.
 */

#ifndef EMBASSY_ZEPHYR_NRF7002_H_
#define EMBASSY_ZEPHYR_NRF7002_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EMBASSY_ZEPHYR_NRF7002_ABI_VERSION UINT32_C(0x00020000)
#define EMBASSY_ZEPHYR_NRF7002_MAC_LEN 6u
#define EMBASSY_ZEPHYR_NRF7002_COUNTRY_LEN 2u
#define EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN 32u
#define EMBASSY_ZEPHYR_NRF7002_MAX_PASSPHRASE_LEN 63u
#define EMBASSY_ZEPHYR_NRF7002_MAX_SCAN_CHANNELS 16u
#define EMBASSY_ZEPHYR_NRF7002_MAX_REG_CHANNELS 42u
#define EMBASSY_ZEPHYR_NRF7002_ETH_HEADER_LEN 14u
#define EMBASSY_ZEPHYR_NRF7002_MAX_FRAME_LEN 1600u

enum embassy_zephyr_nrf7002_role {
	EMBASSY_ZEPHYR_NRF7002_ROLE_STA = 0,
	EMBASSY_ZEPHYR_NRF7002_ROLE_AP = 1,
};

enum embassy_zephyr_nrf7002_status {
	EMBASSY_ZEPHYR_NRF7002_STATUS_DOWN = 0,
	EMBASSY_ZEPHYR_NRF7002_STATUS_READY = 1,
	EMBASSY_ZEPHYR_NRF7002_STATUS_CONNECTING = 2,
	EMBASSY_ZEPHYR_NRF7002_STATUS_CONNECTED = 3,
	EMBASSY_ZEPHYR_NRF7002_STATUS_DISCONNECTED = 4,
	EMBASSY_ZEPHYR_NRF7002_STATUS_FAULTED = 5,
};

enum embassy_zephyr_nrf7002_event {
	EMBASSY_ZEPHYR_NRF7002_EVENT_NONE = 0,
	EMBASSY_ZEPHYR_NRF7002_EVENT_CONNECTED = 1,
	EMBASSY_ZEPHYR_NRF7002_EVENT_ROAMED = 2,
	EMBASSY_ZEPHYR_NRF7002_EVENT_DISCONNECTED = 3,
	EMBASSY_ZEPHYR_NRF7002_EVENT_ADDRESS_CHANGED = 4,
	/* Reserved internally; never emitted over the Rust boundary. */
	EMBASSY_ZEPHYR_NRF7002_EVENT_EAPOL = 5,
	EMBASSY_ZEPHYR_NRF7002_EVENT_INTERFACE_UP = 6,
	EMBASSY_ZEPHYR_NRF7002_EVENT_INTERFACE_DOWN = 7,
	EMBASSY_ZEPHYR_NRF7002_EVENT_AP_STARTED = 8,
	EMBASSY_ZEPHYR_NRF7002_EVENT_AP_STOPPED = 9,
	EMBASSY_ZEPHYR_NRF7002_EVENT_AP_CLIENT_JOINED = 10,
	EMBASSY_ZEPHYR_NRF7002_EVENT_AP_CLIENT_LEFT = 11,
	EMBASSY_ZEPHYR_NRF7002_EVENT_TWT = 12,
	EMBASSY_ZEPHYR_NRF7002_EVENT_CONNECTION_FAILED = 13,
};

/* ABI-visible result values are negative errno-style values. */
#define EMBASSY_ZEPHYR_NRF7002_RESULT_OK 0
#define EMBASSY_ZEPHYR_NRF7002_RESULT_EINVAL (-22)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_ENOMEM (-12)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_EBUSY (-16)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_EIO (-5)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_ENOTSUP (-95)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_ETIMEDOUT (-110)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_ENOTCONN (-107)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_EAGAIN (-11)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_EMSGSIZE (-90)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_EBADF (-9)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_EPROTO (-71)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_ESTATE (-2000)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_ENODEV (-19)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_ENETDOWN (-100)
#define EMBASSY_ZEPHYR_NRF7002_RESULT_EPERM (-1)

enum embassy_zephyr_nrf7002_security {
	EMBASSY_ZEPHYR_NRF7002_SECURITY_OPEN = 0,
	EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA2_PSK = 1,
	EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA2_PSK_SHA256 = 2,
	EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA3_SAE = 3,
	EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA3_SAE_H2E = 4,
	EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA3_SAE_AUTO = 5,
	EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA_PSK = 6,
	EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA_AUTO_PERSONAL = 7,
	EMBASSY_ZEPHYR_NRF7002_SECURITY_OTHER = 255,
};

enum embassy_zephyr_nrf7002_mfp {
	EMBASSY_ZEPHYR_NRF7002_MFP_DISABLE = 0,
	EMBASSY_ZEPHYR_NRF7002_MFP_OPTIONAL = 1,
	EMBASSY_ZEPHYR_NRF7002_MFP_REQUIRED = 2,
};

#define EMBASSY_ZEPHYR_NRF7002_BAND_2_4_GHZ UINT8_C(0)
#define EMBASSY_ZEPHYR_NRF7002_BAND_5_GHZ UINT8_C(1)
#define EMBASSY_ZEPHYR_NRF7002_BAND_ANY UINT8_C(255)
#define EMBASSY_ZEPHYR_NRF7002_BAND_MASK_2_4_GHZ UINT8_C(1)
#define EMBASSY_ZEPHYR_NRF7002_BAND_MASK_5_GHZ UINT8_C(2)
#define EMBASSY_ZEPHYR_NRF7002_CHANNEL_ANY UINT8_C(255)

#define EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_20_MHZ UINT8_C(1)
#define EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_40_MHZ UINT8_C(2)
#define EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_80_MHZ UINT8_C(3)
#define EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_AUTO UINT8_C(255)

/* Capability bits returned by embassy_zephyr_nrf7002_capabilities_wire.flags. */
#define EMBASSY_ZEPHYR_NRF7002_CAP_STA (UINT64_C(1) << 0)
#define EMBASSY_ZEPHYR_NRF7002_CAP_SOFTAP (UINT64_C(1) << 1)
#define EMBASSY_ZEPHYR_NRF7002_CAP_CONCURRENT_STA_AP (UINT64_C(1) << 2)
#define EMBASSY_ZEPHYR_NRF7002_CAP_SCAN (UINT64_C(1) << 3)
#define EMBASSY_ZEPHYR_NRF7002_CAP_BAND_2_4_GHZ (UINT64_C(1) << 4)
#define EMBASSY_ZEPHYR_NRF7002_CAP_BAND_5_GHZ (UINT64_C(1) << 5)
#define EMBASSY_ZEPHYR_NRF7002_CAP_REG_DOMAIN (UINT64_C(1) << 6)
#define EMBASSY_ZEPHYR_NRF7002_CAP_POWER_SAVE (UINT64_C(1) << 7)
#define EMBASSY_ZEPHYR_NRF7002_CAP_TWT (UINT64_C(1) << 8)
#define EMBASSY_ZEPHYR_NRF7002_CAP_RAW_L2 (UINT64_C(1) << 9)
#define EMBASSY_ZEPHYR_NRF7002_CAP_WIFI_STATS (UINT64_C(1) << 10)
#define EMBASSY_ZEPHYR_NRF7002_CAP_AP_CLIENT_CONTROL (UINT64_C(1) << 11)
#define EMBASSY_ZEPHYR_NRF7002_CAP_RUNTIME_CREDENTIALS (UINT64_C(1) << 12)

struct embassy_zephyr_nrf7002_capabilities_wire {
	uint32_t abi_version;
	uint32_t struct_size;
	uint64_t flags;
	uint8_t bands;
	uint8_t max_sta_associations;
	uint8_t max_ap_clients;
	uint8_t max_virtual_interfaces;
	uint16_t scan_queue_capacity;
	uint16_t reserved;
};

struct embassy_zephyr_nrf7002_interface_wire {
	uint32_t abi_version;
	uint32_t struct_size;
	uint8_t mac[EMBASSY_ZEPHYR_NRF7002_MAC_LEN];
	uint16_t mtu;
	uint16_t reserved;
	uint32_t status;
};

struct embassy_zephyr_nrf7002_poll_wire {
	uint32_t event;
	uint32_t status;
};

struct embassy_zephyr_nrf7002_status_wire {
	uint32_t abi_version;
	uint32_t struct_size;
	uint8_t role;
	uint8_t enabled;
	uint8_t state;
	uint8_t band;
	uint16_t channel;
	uint8_t iface_mode;
	uint8_t link_mode;
	uint8_t security;
	uint8_t mfp;
	int16_t rssi_dbm;
	uint8_t dtim_period;
	uint8_t twt_capable;
	uint16_t beacon_interval;
	uint32_t phy_rate_kbps;
	uint8_t ssid_len;
	uint8_t reserved0[3];
	uint8_t ssid[EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN];
	uint8_t bssid[EMBASSY_ZEPHYR_NRF7002_MAC_LEN];
	uint8_t reserved1[2];
};

struct embassy_zephyr_nrf7002_connect_params {
	const uint8_t *ssid;
	uint32_t ssid_len;
	const uint8_t *psk;
	uint32_t psk_len;
	uint8_t bssid[EMBASSY_ZEPHYR_NRF7002_MAC_LEN];
	uint8_t security;
	uint8_t mfp;
	uint8_t band;
	uint8_t channel;
	uint8_t bandwidth;
	uint8_t hidden_ssid;
	uint8_t bssid_set;
	uint8_t reserved;
	uint32_t timeout_ms;
};

struct embassy_zephyr_nrf7002_ap_params {
	struct embassy_zephyr_nrf7002_connect_params connection;
	uint32_t max_inactivity_s;
	uint8_t max_clients;
	uint8_t reserved[3];
};

enum embassy_zephyr_nrf7002_scan_type {
	EMBASSY_ZEPHYR_NRF7002_SCAN_ACTIVE = 0,
	EMBASSY_ZEPHYR_NRF7002_SCAN_PASSIVE = 1,
};

struct embassy_zephyr_nrf7002_band_channel_wire {
	uint8_t band;
	uint8_t channel;
};

struct embassy_zephyr_nrf7002_scan_params {
	const uint8_t *ssid;
	uint32_t ssid_len;
	const struct embassy_zephyr_nrf7002_band_channel_wire *channels;
	uint32_t channel_count;
	uint16_t dwell_time_active_ms;
	uint16_t dwell_time_passive_ms;
	uint16_t max_results;
	uint8_t scan_type;
	uint8_t bands;
};

struct embassy_zephyr_nrf7002_scan_result_wire {
	uint8_t ssid_len;
	uint8_t band;
	uint8_t channel;
	uint8_t security;
	uint8_t mfp;
	int8_t rssi_dbm;
	uint8_t bssid_len;
	uint8_t reserved0;
	uint8_t ssid[EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN];
	uint8_t bssid[EMBASSY_ZEPHYR_NRF7002_MAC_LEN];
	uint8_t reserved1[2];
};

enum embassy_zephyr_nrf7002_scan_poll_kind {
	EMBASSY_ZEPHYR_NRF7002_SCAN_PENDING = 0,
	EMBASSY_ZEPHYR_NRF7002_SCAN_RESULT = 1,
	EMBASSY_ZEPHYR_NRF7002_SCAN_COMPLETE = 2,
};

struct embassy_zephyr_nrf7002_scan_poll_wire {
	uint32_t abi_version;
	uint32_t struct_size;
	uint32_t kind;
	int32_t status;
	uint32_t dropped_results;
	uint32_t reserved;
	struct embassy_zephyr_nrf7002_scan_result_wire result;
};

struct embassy_zephyr_nrf7002_event_wire {
	uint32_t abi_version;
	uint32_t struct_size;
	uint32_t event;
	int32_t status;
	uint8_t role;
	uint8_t peer_mac[EMBASSY_ZEPHYR_NRF7002_MAC_LEN];
	uint8_t peer_mac_set;
	uint32_t dropped_events;
	uint32_t value0;
	uint32_t value1;
};

struct embassy_zephyr_nrf7002_reg_channel_wire {
	uint16_t center_frequency_mhz;
	int8_t max_power_dbm;
	uint8_t flags;
};

#define EMBASSY_ZEPHYR_NRF7002_REG_SUPPORTED UINT8_C(1)
#define EMBASSY_ZEPHYR_NRF7002_REG_PASSIVE_ONLY UINT8_C(2)
#define EMBASSY_ZEPHYR_NRF7002_REG_DFS UINT8_C(4)

enum embassy_zephyr_nrf7002_power_parameter {
	EMBASSY_ZEPHYR_NRF7002_POWER_STATE = 0,
	EMBASSY_ZEPHYR_NRF7002_POWER_LISTEN_INTERVAL = 1,
	EMBASSY_ZEPHYR_NRF7002_POWER_WAKEUP_MODE = 2,
	EMBASSY_ZEPHYR_NRF7002_POWER_MODE = 3,
	EMBASSY_ZEPHYR_NRF7002_POWER_EXIT_STRATEGY = 4,
	EMBASSY_ZEPHYR_NRF7002_POWER_TIMEOUT = 5,
};

struct embassy_zephyr_nrf7002_power_param_wire {
	uint8_t parameter;
	uint8_t value8;
	uint16_t value16;
	uint32_t value32;
};

struct embassy_zephyr_nrf7002_power_config_wire {
	uint32_t abi_version;
	uint32_t struct_size;
	uint8_t enabled;
	uint8_t wakeup_mode;
	uint8_t mode;
	uint8_t exit_strategy;
	uint16_t listen_interval;
	uint16_t reserved0;
	uint32_t timeout_ms;
	uint8_t twt_flow_count;
	uint8_t twt_flow_mask;
	uint8_t reserved1[2];
};

struct embassy_zephyr_nrf7002_twt_setup_wire {
	uint64_t interval_us;
	uint32_t wake_interval_us;
	uint32_t wake_ahead_us;
	uint8_t flow_id;
	uint8_t negotiation_type;
	uint8_t setup_command;
	uint8_t dialog_token;
	uint8_t trigger;
	uint8_t implicit;
	uint8_t announce;
	uint8_t reserved;
};

struct embassy_zephyr_nrf7002_stats_wire {
	uint32_t abi_version;
	uint32_t struct_size;
	uint64_t beacons_received;
	uint64_t beacons_missed;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t rx_packets;
	uint64_t tx_packets;
	uint64_t rx_errors;
	uint64_t tx_errors;
	uint64_t overruns;
};

/* Version and capability/control lifetime. */
uint32_t embassy_zephyr_nrf7002_l2_abi_version(void);
int32_t embassy_zephyr_nrf7002_wifi_control_init(void);
int32_t embassy_zephyr_nrf7002_wifi_capabilities(
	struct embassy_zephyr_nrf7002_capabilities_wire *capabilities);
int32_t embassy_zephyr_nrf7002_wifi_set_enabled(uint8_t role, uint8_t enabled);
int32_t embassy_zephyr_nrf7002_wifi_status(uint8_t role,
	struct embassy_zephyr_nrf7002_status_wire *status);
int32_t embassy_zephyr_nrf7002_wifi_event_poll(struct embassy_zephyr_nrf7002_event_wire *event);

/* Rust-selected station and SoftAP operations. */
int32_t embassy_zephyr_nrf7002_wifi_scan_start(uint8_t role,
	const struct embassy_zephyr_nrf7002_scan_params *params);
int32_t embassy_zephyr_nrf7002_wifi_scan_poll(
	struct embassy_zephyr_nrf7002_scan_poll_wire *result);
int32_t embassy_zephyr_nrf7002_wifi_connect(uint8_t role,
	const struct embassy_zephyr_nrf7002_connect_params *params);
int32_t embassy_zephyr_nrf7002_wifi_disconnect(uint8_t role);
int32_t embassy_zephyr_nrf7002_wifi_ap_start(
	const struct embassy_zephyr_nrf7002_ap_params *params);
int32_t embassy_zephyr_nrf7002_wifi_ap_stop(void);
int32_t embassy_zephyr_nrf7002_wifi_ap_disconnect_client(
	const uint8_t mac[EMBASSY_ZEPHYR_NRF7002_MAC_LEN]);

/* Regulatory, power, TWT, and observations. */
int32_t embassy_zephyr_nrf7002_wifi_set_country(uint8_t role,
	const uint8_t country[EMBASSY_ZEPHYR_NRF7002_COUNTRY_LEN], uint8_t force);
int32_t embassy_zephyr_nrf7002_wifi_get_reg_domain(uint8_t role,
	uint8_t country[EMBASSY_ZEPHYR_NRF7002_COUNTRY_LEN],
	struct embassy_zephyr_nrf7002_reg_channel_wire *channels,
	uint32_t capacity, uint32_t *count);
int32_t embassy_zephyr_nrf7002_wifi_set_power(
	const struct embassy_zephyr_nrf7002_power_param_wire *params);
int32_t embassy_zephyr_nrf7002_wifi_get_power(
	struct embassy_zephyr_nrf7002_power_config_wire *config);
int32_t embassy_zephyr_nrf7002_wifi_twt_setup(
	const struct embassy_zephyr_nrf7002_twt_setup_wire *params);
int32_t embassy_zephyr_nrf7002_wifi_twt_teardown(uint8_t flow_id, uint8_t all_flows);
int32_t embassy_zephyr_nrf7002_wifi_get_stats(uint8_t role,
	struct embassy_zephyr_nrf7002_stats_wire *stats);
int32_t embassy_zephyr_nrf7002_wifi_reset_stats(uint8_t role);

/* Role-addressable raw Ethernet endpoints. */
int32_t embassy_zephyr_nrf7002_l2_init(struct embassy_zephyr_nrf7002_interface_wire *interface);
int32_t embassy_zephyr_nrf7002_l2_open(void **handle);
int32_t embassy_zephyr_nrf7002_l2_open_role(uint8_t role, void **handle);
int32_t embassy_zephyr_nrf7002_l2_close(void *handle);
int32_t embassy_zephyr_nrf7002_l2_interface(void *handle,
	struct embassy_zephyr_nrf7002_interface_wire *interface);
int32_t embassy_zephyr_nrf7002_l2_connect(void *handle, const uint8_t *ssid, size_t ssid_len);
int32_t embassy_zephyr_nrf7002_l2_connect_psk(void *handle,
	const struct embassy_zephyr_nrf7002_connect_params *params);
int32_t embassy_zephyr_nrf7002_l2_disconnect(void *handle);
int32_t embassy_zephyr_nrf7002_l2_poll(void *handle, uint32_t timeout_ms,
	struct embassy_zephyr_nrf7002_poll_wire *result);
int32_t embassy_zephyr_nrf7002_l2_recv(void *handle, uint8_t *buffer, size_t capacity,
	size_t *received);
int32_t embassy_zephyr_nrf7002_l2_send(void *handle, const uint8_t *buffer, size_t length);

/* Bounded platform services used by Rust application logic. */
int32_t embassy_zephyr_nrf7002_console_open(void);
int32_t embassy_zephyr_nrf7002_console_read(uint8_t *buffer, size_t capacity,
	size_t *received);
int32_t embassy_zephyr_nrf7002_random_fill(uint8_t *buffer, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* EMBASSY_ZEPHYR_NRF7002_H_ */
