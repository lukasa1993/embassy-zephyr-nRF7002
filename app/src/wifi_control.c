/*
 * Rust-owned Wi-Fi control plane.
 *
 * Every credential, role, band, channel, regulatory, AP, and power parameter
 * arrives through the frozen Rust ABI. Zephyr/nRF70 supplies the requested
 * mechanism and observations. Automatic supplicant reconnect and roaming are
 * the deliberate exceptions selected by the product architecture.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_stats.h>
#include <zephyr/net/wifi.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>

#include "embassy_zephyr_nrf7002.h"

#define CONTROL_EVENT_QUEUE_CAPACITY 16
#define SCAN_RESULT_QUEUE_CAPACITY 16

#if defined(CONFIG_WIFI_NM_WPA_SUPPLICANT_ROAMING)
#define WIFI_AUTOMATIC_ROAM_EVENT_MASK \
	(NET_EVENT_WIFI_SIGNAL_CHANGE | NET_EVENT_WIFI_NEIGHBOR_REP_COMP)
#else
#define WIFI_AUTOMATIC_ROAM_EVENT_MASK 0
#endif

#define WIFI_CONTROL_EVENT_MASK                                                   \
	(NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT |        \
	 NET_EVENT_WIFI_AP_ENABLE_RESULT | NET_EVENT_WIFI_AP_DISABLE_RESULT |      \
	 NET_EVENT_WIFI_AP_STA_CONNECTED | NET_EVENT_WIFI_AP_STA_DISCONNECTED |    \
	 NET_EVENT_WIFI_SCAN_RESULT | NET_EVENT_WIFI_SCAN_DONE | NET_EVENT_WIFI_TWT | \
	 WIFI_AUTOMATIC_ROAM_EVENT_MASK)

#define IFACE_CONTROL_EVENT_MASK (NET_EVENT_IF_ADMIN_UP | NET_EVENT_IF_ADMIN_DOWN)

K_MSGQ_DEFINE(control_event_queue,
	      sizeof(struct embassy_zephyr_nrf7002_event_wire),
	      CONTROL_EVENT_QUEUE_CAPACITY, 4);
K_MSGQ_DEFINE(scan_result_queue,
	      sizeof(struct embassy_zephyr_nrf7002_scan_result_wire),
	      SCAN_RESULT_QUEUE_CAPACITY, 4);

static struct net_mgmt_event_callback wifi_control_callback;
static struct net_mgmt_event_callback iface_control_callback;
static atomic_t control_initialized = ATOMIC_INIT(0);
static atomic_t scan_active = ATOMIC_INIT(0);
static atomic_t scan_done = ATOMIC_INIT(0);
static atomic_t scan_status = ATOMIC_INIT(0);
static atomic_t scan_dropped = ATOMIC_INIT(0);
static atomic_t control_event_dropped = ATOMIC_INIT(0);
static atomic_t scan_role = ATOMIC_INIT(EMBASSY_ZEPHYR_NRF7002_ROLE_STA);
static struct wifi_scan_params scan_params_storage;
static uint8_t scan_ssid_storage[EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN + 1];

static __noinline void secure_zero(void *memory, size_t length)
{
	volatile uint8_t *bytes = memory;

	while (length > 0U) {
		*bytes++ = 0U;
		length--;
	}
}

static struct net_if *iface_for_role(uint8_t role)
{
	switch (role) {
	case EMBASSY_ZEPHYR_NRF7002_ROLE_STA:
		return net_if_get_wifi_sta();
	case EMBASSY_ZEPHYR_NRF7002_ROLE_AP:
#if defined(CONFIG_NRF70_AP_MODE)
		return net_if_get_wifi_sap();
#else
		return NULL;
#endif
	default:
		return NULL;
	}
}

static int role_for_iface(struct net_if *iface, uint8_t *role)
{
	if (iface == NULL || role == NULL) {
		return -EINVAL;
	}
	if (iface == iface_for_role(EMBASSY_ZEPHYR_NRF7002_ROLE_STA)) {
		*role = EMBASSY_ZEPHYR_NRF7002_ROLE_STA;
		return 0;
	}
	if (iface == iface_for_role(EMBASSY_ZEPHYR_NRF7002_ROLE_AP)) {
		*role = EMBASSY_ZEPHYR_NRF7002_ROLE_AP;
		return 0;
	}
	return -ENODEV;
}

static int map_security(uint8_t security, enum wifi_security_type *out)
{
	if (out == NULL) {
		return -EINVAL;
	}

	switch (security) {
	case EMBASSY_ZEPHYR_NRF7002_SECURITY_OPEN:
		*out = WIFI_SECURITY_TYPE_NONE;
		return 0;
	case EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA2_PSK:
		*out = WIFI_SECURITY_TYPE_PSK;
		return 0;
	case EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA2_PSK_SHA256:
		*out = WIFI_SECURITY_TYPE_PSK_SHA256;
		return 0;
	case EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA3_SAE:
		*out = WIFI_SECURITY_TYPE_SAE;
		return 0;
	case EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA3_SAE_H2E:
		*out = WIFI_SECURITY_TYPE_SAE_H2E;
		return 0;
	case EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA3_SAE_AUTO:
		*out = WIFI_SECURITY_TYPE_SAE_AUTO;
		return 0;
	case EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA_PSK:
		*out = WIFI_SECURITY_TYPE_WPA_PSK;
		return 0;
	case EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA_AUTO_PERSONAL:
		*out = WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL;
		return 0;
	default:
		return -ENOTSUP;
	}
}

static uint8_t security_to_wire(enum wifi_security_type security)
{
	switch (security) {
	case WIFI_SECURITY_TYPE_NONE:
		return EMBASSY_ZEPHYR_NRF7002_SECURITY_OPEN;
	case WIFI_SECURITY_TYPE_PSK:
		return EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA2_PSK;
	case WIFI_SECURITY_TYPE_PSK_SHA256:
		return EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA2_PSK_SHA256;
	case WIFI_SECURITY_TYPE_SAE:
		return EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA3_SAE;
	case WIFI_SECURITY_TYPE_SAE_H2E:
		return EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA3_SAE_H2E;
	case WIFI_SECURITY_TYPE_SAE_AUTO:
		return EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA3_SAE_AUTO;
	case WIFI_SECURITY_TYPE_WPA_PSK:
		return EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA_PSK;
	case WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL:
		return EMBASSY_ZEPHYR_NRF7002_SECURITY_WPA_AUTO_PERSONAL;
	default:
		return EMBASSY_ZEPHYR_NRF7002_SECURITY_OTHER;
	}
}

static uint8_t band_to_wire(enum wifi_frequency_bands band)
{
	if (band == WIFI_FREQ_BAND_2_4_GHZ) {
		return EMBASSY_ZEPHYR_NRF7002_BAND_2_4_GHZ;
	}
	if (band == WIFI_FREQ_BAND_5_GHZ) {
		return EMBASSY_ZEPHYR_NRF7002_BAND_5_GHZ;
	}
	return EMBASSY_ZEPHYR_NRF7002_BAND_ANY;
}

static int validate_connection(
	const struct embassy_zephyr_nrf7002_connect_params *params)
{
	if (params == NULL || params->ssid == NULL || params->ssid_len == 0U ||
	    params->ssid_len > EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN) {
		return -EINVAL;
	}
	if (params->mfp > EMBASSY_ZEPHYR_NRF7002_MFP_REQUIRED ||
	    (params->band != EMBASSY_ZEPHYR_NRF7002_BAND_ANY &&
	     params->band != EMBASSY_ZEPHYR_NRF7002_BAND_2_4_GHZ &&
	     params->band != EMBASSY_ZEPHYR_NRF7002_BAND_5_GHZ) ||
	    (params->channel != EMBASSY_ZEPHYR_NRF7002_CHANNEL_ANY &&
	     (params->channel < WIFI_CHANNEL_MIN ||
	      params->channel > WIFI_CHANNEL_MAX)) ||
	    (params->bandwidth != EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_AUTO &&
	     (params->bandwidth < EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_20_MHZ ||
	      params->bandwidth > EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_80_MHZ)) ||
	    params->hidden_ssid > 2U || params->bssid_set > 1U) {
		return -EINVAL;
	}
	if (params->security == EMBASSY_ZEPHYR_NRF7002_SECURITY_OPEN) {
		return params->psk_len == 0U ? 0 : -EINVAL;
	}
	if (params->psk == NULL || params->psk_len < 8U ||
	    params->psk_len > EMBASSY_ZEPHYR_NRF7002_MAX_PASSPHRASE_LEN) {
		return -EINVAL;
	}
	return 0;
}

static int execute_connection(
	struct net_if *iface,
	const struct embassy_zephyr_nrf7002_connect_params *params,
	uint64_t request_id)
{
	struct wifi_connect_req_params request = { 0 };
	uint8_t ssid[EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN];
	uint8_t psk[EMBASSY_ZEPHYR_NRF7002_MAX_PASSPHRASE_LEN];
	uint64_t timeout_seconds;
	int ret;

	if (iface == NULL) {
		return -ENODEV;
	}
	ret = validate_connection(params);
	if (ret < 0) {
		return ret;
	}
	ret = map_security(params->security, &request.security);
	if (ret < 0) {
		return ret;
	}

	memcpy(ssid, params->ssid, params->ssid_len);
	request.ssid = ssid;
	request.ssid_length = (uint8_t)params->ssid_len;
	request.mfp = (enum wifi_mfp_options)params->mfp;
	request.band = params->band == EMBASSY_ZEPHYR_NRF7002_BAND_ANY
			       ? WIFI_FREQ_BAND_UNKNOWN
			       : (enum wifi_frequency_bands)params->band;
	request.channel = params->channel;
	request.bandwidth = params->bandwidth == EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_AUTO
				    ? WIFI_FREQ_BANDWIDTH_UNKNOWN
				    : (enum wifi_frequency_bandwidths)params->bandwidth;
	request.ignore_broadcast_ssid = params->hidden_ssid;
	if (params->bssid_set != 0U) {
		memcpy(request.bssid, params->bssid, WIFI_MAC_ADDR_LEN);
	}
	if (params->timeout_ms == 0U) {
		request.timeout = SYS_FOREVER_MS;
	} else {
		timeout_seconds = ((uint64_t)params->timeout_ms + 999U) / 1000U;
		request.timeout = timeout_seconds > (uint64_t)INT_MAX
					  ? INT_MAX : (int)timeout_seconds;
	}

	if (params->psk_len != 0U) {
		memcpy(psk, params->psk, params->psk_len);
		if (request.security == WIFI_SECURITY_TYPE_SAE ||
		    request.security == WIFI_SECURITY_TYPE_SAE_H2E ||
		    request.security == WIFI_SECURITY_TYPE_SAE_AUTO) {
			request.sae_password = psk;
			request.sae_password_length = (uint8_t)params->psk_len;
		} else {
			request.psk = psk;
			request.psk_length = (uint8_t)params->psk_len;
		}
	}

	if (request_id == NET_REQUEST_WIFI_CONNECT) {
		ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &request,
			       sizeof(request));
	} else if (request_id == NET_REQUEST_WIFI_AP_ENABLE) {
		ret = net_mgmt(NET_REQUEST_WIFI_AP_ENABLE, iface, &request,
			       sizeof(request));
	} else {
		ret = -EINVAL;
	}
	secure_zero(ssid, sizeof(ssid));
	secure_zero(psk, sizeof(psk));
	return ret < 0 ? ret : 0;
}

static void queue_control_event(uint32_t event, int32_t status, uint8_t role,
				const uint8_t *peer_mac,
				uint32_t value0, uint32_t value1)
{
	struct embassy_zephyr_nrf7002_event_wire out = {
		.abi_version = EMBASSY_ZEPHYR_NRF7002_ABI_VERSION,
		.struct_size = sizeof(out),
		.event = event,
		.status = status,
		.role = role,
		.value0 = value0,
		.value1 = value1,
	};

	if (peer_mac != NULL) {
		memcpy(out.peer_mac, peer_mac, EMBASSY_ZEPHYR_NRF7002_MAC_LEN);
		out.peer_mac_set = 1U;
	}
	if (k_msgq_put(&control_event_queue, &out, K_NO_WAIT) < 0) {
		atomic_inc(&control_event_dropped);
	}
}

static void handle_scan_event(struct net_mgmt_event_callback *callback,
			      uint64_t mgmt_event, struct net_if *iface)
{
	uint8_t role;

	if (role_for_iface(iface, &role) < 0 ||
	    role != (uint8_t)atomic_get(&scan_role)) {
		return;
	}

	if (mgmt_event == NET_EVENT_WIFI_SCAN_RESULT) {
		const struct wifi_scan_result *result = callback->info;
		struct embassy_zephyr_nrf7002_scan_result_wire out = { 0 };
		size_t ssid_len;

		if (result == NULL || callback->info_length < sizeof(*result)) {
			return;
		}
		ssid_len = MIN((size_t)result->ssid_length,
			       (size_t)EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN);
		out.ssid_len = (uint8_t)ssid_len;
		out.band = band_to_wire((enum wifi_frequency_bands)result->band);
		out.channel = result->channel;
		out.security = security_to_wire(result->security);
		out.mfp = result->mfp <= WIFI_MFP_REQUIRED
				  ? (uint8_t)result->mfp
				  : EMBASSY_ZEPHYR_NRF7002_MFP_DISABLE;
		out.rssi_dbm = result->rssi;
		out.bssid_len = MIN(result->mac_length,
				    EMBASSY_ZEPHYR_NRF7002_MAC_LEN);
		memcpy(out.ssid, result->ssid, ssid_len);
		memcpy(out.bssid, result->mac, out.bssid_len);
		if (k_msgq_put(&scan_result_queue, &out, K_NO_WAIT) < 0) {
			atomic_inc(&scan_dropped);
		}
	} else if (mgmt_event == NET_EVENT_WIFI_SCAN_DONE) {
		const struct wifi_status *status = callback->info;

		atomic_set(&scan_status,
			   status != NULL && callback->info_length >= sizeof(*status)
				   ? status->status : -EPROTO);
		atomic_set(&scan_active, 0);
		atomic_set(&scan_done, 1);
		secure_zero(scan_ssid_storage, sizeof(scan_ssid_storage));
	}
}

static void wifi_control_event_handler(
	struct net_mgmt_event_callback *callback, uint64_t mgmt_event,
	struct net_if *iface)
{
	const struct wifi_status *status = callback->info;
	const struct wifi_ap_sta_info *station = callback->info;
	const struct wifi_twt_params *twt = callback->info;
	uint8_t role;
	int32_t result = 0;

	if (mgmt_event == NET_EVENT_WIFI_SCAN_RESULT ||
	    mgmt_event == NET_EVENT_WIFI_SCAN_DONE) {
		handle_scan_event(callback, mgmt_event, iface);
		return;
	}
	if (role_for_iface(iface, &role) < 0) {
		return;
	}
	if (status != NULL && callback->info_length >= sizeof(*status)) {
		result = status->status;
	}

	switch (mgmt_event) {
#if defined(CONFIG_WIFI_NM_WPA_SUPPLICANT_ROAMING)
	case NET_EVENT_WIFI_SIGNAL_CHANGE:
		/* The product deliberately delegates reconnect/roaming policy to the
		 * pinned supplicant. This is the same stock event progression used by
		 * Zephyr's Wi-Fi shell, without exposing a Rust decision point.
		 */
		(void)net_mgmt(NET_REQUEST_WIFI_START_ROAMING, iface, NULL, 0);
		break;
	case NET_EVENT_WIFI_NEIGHBOR_REP_COMP:
		(void)net_mgmt(NET_REQUEST_WIFI_NEIGHBOR_REP_COMPLETE, iface,
			       NULL, 0);
		break;
#endif
	case NET_EVENT_WIFI_CONNECT_RESULT:
		queue_control_event(result == WIFI_STATUS_CONN_SUCCESS
					    ? EMBASSY_ZEPHYR_NRF7002_EVENT_CONNECTED
					    : EMBASSY_ZEPHYR_NRF7002_EVENT_CONNECTION_FAILED,
				    result, role, NULL, 0, 0);
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		queue_control_event(EMBASSY_ZEPHYR_NRF7002_EVENT_DISCONNECTED,
				    result, role, NULL, 0, 0);
		break;
	case NET_EVENT_WIFI_AP_ENABLE_RESULT:
		queue_control_event(EMBASSY_ZEPHYR_NRF7002_EVENT_AP_STARTED,
				    result, role, NULL, 0, 0);
		break;
	case NET_EVENT_WIFI_AP_DISABLE_RESULT:
		queue_control_event(EMBASSY_ZEPHYR_NRF7002_EVENT_AP_STOPPED,
				    result, role, NULL, 0, 0);
		break;
	case NET_EVENT_WIFI_AP_STA_CONNECTED:
		if (station != NULL && callback->info_length >= sizeof(*station)) {
			queue_control_event(
				EMBASSY_ZEPHYR_NRF7002_EVENT_AP_CLIENT_JOINED, 0, role,
				station->mac, station->link_mode, station->twt_capable);
		}
		break;
	case NET_EVENT_WIFI_AP_STA_DISCONNECTED:
		if (station != NULL && callback->info_length >= sizeof(*station)) {
			queue_control_event(
				EMBASSY_ZEPHYR_NRF7002_EVENT_AP_CLIENT_LEFT, 0, role,
				station->mac, station->link_mode, station->twt_capable);
		}
		break;
	case NET_EVENT_WIFI_TWT:
		if (twt != NULL && callback->info_length >= sizeof(*twt)) {
			queue_control_event(EMBASSY_ZEPHYR_NRF7002_EVENT_TWT,
				twt->fail_reason, role, NULL, twt->flow_id,
				twt->operation);
		}
		break;
	default:
		break;
	}
}

static void iface_control_event_handler(
	struct net_mgmt_event_callback *callback, uint64_t mgmt_event,
	struct net_if *iface)
{
	uint8_t role;

	ARG_UNUSED(callback);
	if (role_for_iface(iface, &role) < 0) {
		return;
	}
	if (mgmt_event == NET_EVENT_IF_ADMIN_UP) {
		queue_control_event(EMBASSY_ZEPHYR_NRF7002_EVENT_INTERFACE_UP,
				    0, role, NULL, 0, 0);
	} else if (mgmt_event == NET_EVENT_IF_ADMIN_DOWN) {
		queue_control_event(EMBASSY_ZEPHYR_NRF7002_EVENT_INTERFACE_DOWN,
				    0, role, NULL, 0, 0);
	}
}

int32_t embassy_zephyr_nrf7002_wifi_control_init(void)
{
	if (iface_for_role(EMBASSY_ZEPHYR_NRF7002_ROLE_STA) == NULL) {
		return -ENODEV;
	}
	if (!atomic_cas(&control_initialized, 0, 1)) {
		return 0;
	}

	k_msgq_purge(&control_event_queue);
	k_msgq_purge(&scan_result_queue);
	atomic_set(&control_event_dropped, 0);
	net_mgmt_init_event_callback(&wifi_control_callback,
				     wifi_control_event_handler,
				     WIFI_CONTROL_EVENT_MASK);
	net_mgmt_add_event_callback(&wifi_control_callback);
	net_mgmt_init_event_callback(&iface_control_callback,
				     iface_control_event_handler,
				     IFACE_CONTROL_EVENT_MASK);
	net_mgmt_add_event_callback(&iface_control_callback);
	return 0;
}

int32_t embassy_zephyr_nrf7002_wifi_capabilities(
	struct embassy_zephyr_nrf7002_capabilities_wire *capabilities)
{
	uint64_t flags = EMBASSY_ZEPHYR_NRF7002_CAP_SCAN |
			 EMBASSY_ZEPHYR_NRF7002_CAP_BAND_2_4_GHZ |
			 EMBASSY_ZEPHYR_NRF7002_CAP_REG_DOMAIN |
			 EMBASSY_ZEPHYR_NRF7002_CAP_RAW_L2 |
			 EMBASSY_ZEPHYR_NRF7002_CAP_RUNTIME_CREDENTIALS;

	if (capabilities == NULL) {
		return -EINVAL;
	}
	memset(capabilities, 0, sizeof(*capabilities));
	capabilities->abi_version = EMBASSY_ZEPHYR_NRF7002_ABI_VERSION;
	capabilities->struct_size = sizeof(*capabilities);
	capabilities->bands = EMBASSY_ZEPHYR_NRF7002_BAND_MASK_2_4_GHZ;
	capabilities->max_sta_associations = 1U;
	capabilities->max_ap_clients = 0U;
	capabilities->max_virtual_interfaces = 1U;
	capabilities->scan_queue_capacity = SCAN_RESULT_QUEUE_CAPACITY;
#if defined(CONFIG_NRF70_STA_MODE)
	flags |= EMBASSY_ZEPHYR_NRF7002_CAP_STA |
		 EMBASSY_ZEPHYR_NRF7002_CAP_POWER_SAVE |
		 EMBASSY_ZEPHYR_NRF7002_CAP_TWT;
#endif
#if defined(CONFIG_NRF70_AP_MODE)
	flags |= EMBASSY_ZEPHYR_NRF7002_CAP_SOFTAP |
		 EMBASSY_ZEPHYR_NRF7002_CAP_AP_CLIENT_CONTROL;
	capabilities->max_ap_clients = 1U;
#endif
#if defined(CONFIG_NRF70_ENABLE_DUAL_VIF)
	flags |= EMBASSY_ZEPHYR_NRF7002_CAP_CONCURRENT_STA_AP;
	capabilities->max_virtual_interfaces = 2U;
#endif
#if defined(CONFIG_WIFI_NRF7002) && !defined(CONFIG_NRF70_2_4G_ONLY)
	flags |= EMBASSY_ZEPHYR_NRF7002_CAP_BAND_5_GHZ;
	capabilities->bands |= EMBASSY_ZEPHYR_NRF7002_BAND_MASK_5_GHZ;
#endif
#if defined(CONFIG_NET_STATISTICS_WIFI)
	flags |= EMBASSY_ZEPHYR_NRF7002_CAP_WIFI_STATS;
#endif
	capabilities->flags = flags;
	return 0;
}

int32_t embassy_zephyr_nrf7002_wifi_set_enabled(uint8_t role, uint8_t enabled)
{
	struct net_if *iface = iface_for_role(role);
	int ret;

	if (iface == NULL || enabled > 1U) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	ret = enabled != 0U ? net_if_up(iface) : net_if_down(iface);
	if (ret == -EALREADY) {
		return 0;
	}
	return ret < 0 ? ret : 0;
}

int32_t embassy_zephyr_nrf7002_wifi_status(uint8_t role,
	struct embassy_zephyr_nrf7002_status_wire *out)
{
	struct net_if *iface = iface_for_role(role);
	struct wifi_iface_status status = { 0 };
	bool enabled;
	size_t ssid_len;
	int ret;

	if (iface == NULL || out == NULL) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	memset(out, 0, sizeof(*out));
	out->abi_version = EMBASSY_ZEPHYR_NRF7002_ABI_VERSION;
	out->struct_size = sizeof(*out);
	out->role = role;
	out->band = EMBASSY_ZEPHYR_NRF7002_BAND_ANY;
	out->security = EMBASSY_ZEPHYR_NRF7002_SECURITY_OTHER;
	enabled = net_if_is_admin_up(iface);
	out->enabled = enabled ? 1U : 0U;
	if (!enabled) {
		return 0;
	}

	ret = net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
		       sizeof(status));
	if (ret < 0) {
		return ret;
	}
	out->state = (uint8_t)status.state;
	out->band = band_to_wire(status.band);
	out->channel = status.channel;
	out->iface_mode = (uint8_t)status.iface_mode;
	out->link_mode = (uint8_t)status.link_mode;
	out->security = security_to_wire(status.security);
	out->mfp = status.mfp <= WIFI_MFP_REQUIRED
			   ? (uint8_t)status.mfp
			   : EMBASSY_ZEPHYR_NRF7002_MFP_DISABLE;
	out->rssi_dbm = status.rssi > INT16_MAX ? INT16_MAX :
			status.rssi < INT16_MIN ? INT16_MIN : (int16_t)status.rssi;
	out->dtim_period = status.dtim_period;
	out->twt_capable = status.twt_capable ? 1U : 0U;
	out->beacon_interval = status.beacon_interval;
	out->phy_rate_kbps = status.current_phy_tx_rate > 0.0f
				   ? (uint32_t)(status.current_phy_tx_rate * 1000.0f)
				   : 0U;
	ssid_len = MIN((size_t)status.ssid_len,
		       (size_t)EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN);
	out->ssid_len = (uint8_t)ssid_len;
	memcpy(out->ssid, status.ssid, ssid_len);
	memcpy(out->bssid, status.bssid, EMBASSY_ZEPHYR_NRF7002_MAC_LEN);
	return 0;
}

int32_t embassy_zephyr_nrf7002_wifi_event_poll(struct embassy_zephyr_nrf7002_event_wire *event)
{
	if (event == NULL) {
		return -EINVAL;
	}
	if (k_msgq_get(&control_event_queue, event, K_NO_WAIT) < 0) {
		return -EAGAIN;
	}
	event->dropped_events = (uint32_t)atomic_get(&control_event_dropped);
	return 0;
}

int32_t embassy_zephyr_nrf7002_wifi_scan_start(uint8_t role,
	const struct embassy_zephyr_nrf7002_scan_params *params)
{
	struct net_if *iface = iface_for_role(role);
	uint32_t index;
	int ret;

	if (iface == NULL || params == NULL ||
	    params->scan_type > EMBASSY_ZEPHYR_NRF7002_SCAN_PASSIVE ||
	    params->bands == 0U ||
	    (params->bands & ~(EMBASSY_ZEPHYR_NRF7002_BAND_MASK_2_4_GHZ |
			       EMBASSY_ZEPHYR_NRF7002_BAND_MASK_5_GHZ)) != 0U ||
	    params->ssid_len > EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN ||
	    (params->ssid_len != 0U && params->ssid == NULL) ||
	    params->channel_count > EMBASSY_ZEPHYR_NRF7002_MAX_SCAN_CHANNELS ||
	    params->channel_count > WIFI_MGMT_SCAN_CHAN_MAX_MANUAL ||
	    (params->channel_count != 0U && params->channels == NULL)) {
		return -EINVAL;
	}
	if (!net_if_is_admin_up(iface)) {
		return -ENETDOWN;
	}
	if (!atomic_cas(&scan_active, 0, 1)) {
		return -EBUSY;
	}

	k_msgq_purge(&scan_result_queue);
	atomic_set(&scan_done, 0);
	atomic_set(&scan_status, 0);
	atomic_set(&scan_dropped, 0);
	atomic_set(&scan_role, role);
	memset(&scan_params_storage, 0, sizeof(scan_params_storage));
	secure_zero(scan_ssid_storage, sizeof(scan_ssid_storage));
	scan_params_storage.scan_type = (enum wifi_scan_type)params->scan_type;
	scan_params_storage.bands = params->bands;
	scan_params_storage.dwell_time_active = params->dwell_time_active_ms;
	scan_params_storage.dwell_time_passive = params->dwell_time_passive_ms;
	scan_params_storage.max_bss_cnt = params->max_results;
	if (params->ssid_len != 0U) {
		memcpy(scan_ssid_storage, params->ssid, params->ssid_len);
		scan_ssid_storage[params->ssid_len] = 0U;
		scan_params_storage.ssids[0] = (const char *)scan_ssid_storage;
	}
	for (index = 0U; index < params->channel_count; index++) {
		if (params->channels[index].band >
		    EMBASSY_ZEPHYR_NRF7002_BAND_5_GHZ ||
		    params->channels[index].channel < WIFI_CHANNEL_MIN ||
		    params->channels[index].channel > WIFI_CHANNEL_MAX) {
			atomic_set(&scan_active, 0);
			return -EINVAL;
		}
		scan_params_storage.band_chan[index].band =
			params->channels[index].band;
		scan_params_storage.band_chan[index].channel =
			params->channels[index].channel;
	}

	ret = net_mgmt(NET_REQUEST_WIFI_SCAN, iface, &scan_params_storage,
		       sizeof(scan_params_storage));
	if (ret < 0) {
		atomic_set(&scan_status, ret);
		atomic_set(&scan_active, 0);
		atomic_set(&scan_done, 1);
		secure_zero(scan_ssid_storage, sizeof(scan_ssid_storage));
	}
	return ret < 0 ? ret : 0;
}

int32_t embassy_zephyr_nrf7002_wifi_scan_poll(
	struct embassy_zephyr_nrf7002_scan_poll_wire *result)
{
	if (result == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	result->abi_version = EMBASSY_ZEPHYR_NRF7002_ABI_VERSION;
	result->struct_size = sizeof(*result);
	result->dropped_results = (uint32_t)atomic_get(&scan_dropped);
	if (k_msgq_get(&scan_result_queue, &result->result, K_NO_WAIT) == 0) {
		result->kind = EMBASSY_ZEPHYR_NRF7002_SCAN_RESULT;
		return 0;
	}
	if (atomic_cas(&scan_done, 1, 0)) {
		result->kind = EMBASSY_ZEPHYR_NRF7002_SCAN_COMPLETE;
		result->status = (int32_t)atomic_get(&scan_status);
		return 0;
	}
	result->kind = EMBASSY_ZEPHYR_NRF7002_SCAN_PENDING;
	return 0;
}

int32_t embassy_zephyr_nrf7002_wifi_connect(uint8_t role,
	const struct embassy_zephyr_nrf7002_connect_params *params)
{
	if (role != EMBASSY_ZEPHYR_NRF7002_ROLE_STA) {
		return -ENOTSUP;
	}
	return execute_connection(iface_for_role(role), params,
				  NET_REQUEST_WIFI_CONNECT);
}

int32_t embassy_zephyr_nrf7002_wifi_disconnect(uint8_t role)
{
	struct net_if *iface = iface_for_role(role);

	if (iface == NULL) {
		return -ENODEV;
	}
	if (role == EMBASSY_ZEPHYR_NRF7002_ROLE_AP) {
		return net_mgmt(NET_REQUEST_WIFI_AP_DISABLE, iface, NULL, 0);
	}
	return net_mgmt(NET_REQUEST_WIFI_DISCONNECT, iface, NULL, 0);
}

int32_t embassy_zephyr_nrf7002_wifi_ap_start(
	const struct embassy_zephyr_nrf7002_ap_params *params)
{
	struct net_if *iface = iface_for_role(EMBASSY_ZEPHYR_NRF7002_ROLE_AP);
	struct wifi_ap_config_params ap_config = { 0 };
	int ret;

	if (iface == NULL || params == NULL) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	if (params->max_clients != 1U ||
	    params->connection.band == EMBASSY_ZEPHYR_NRF7002_BAND_ANY ||
	    params->connection.channel == EMBASSY_ZEPHYR_NRF7002_CHANNEL_ANY) {
		return -EINVAL;
	}
	if (params->max_inactivity_s != 0U) {
		ap_config.type = WIFI_AP_CONFIG_PARAM_MAX_INACTIVITY;
		ap_config.max_inactivity = params->max_inactivity_s;
		ret = net_mgmt(NET_REQUEST_WIFI_AP_CONFIG_PARAM, iface, &ap_config,
			       sizeof(ap_config));
		if (ret < 0 && ret != -ENOTSUP) {
			return ret;
		}
	}
	return execute_connection(iface, &params->connection,
				  NET_REQUEST_WIFI_AP_ENABLE);
}

int32_t embassy_zephyr_nrf7002_wifi_ap_stop(void)
{
	return embassy_zephyr_nrf7002_wifi_disconnect(EMBASSY_ZEPHYR_NRF7002_ROLE_AP);
}

int32_t embassy_zephyr_nrf7002_wifi_ap_disconnect_client(
	const uint8_t mac[EMBASSY_ZEPHYR_NRF7002_MAC_LEN])
{
	struct net_if *iface = iface_for_role(EMBASSY_ZEPHYR_NRF7002_ROLE_AP);

	if (iface == NULL || mac == NULL) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	return net_mgmt(NET_REQUEST_WIFI_AP_STA_DISCONNECT, iface,
			(void *)mac, EMBASSY_ZEPHYR_NRF7002_MAC_LEN);
}

int32_t embassy_zephyr_nrf7002_wifi_set_country(uint8_t role,
	const uint8_t country[EMBASSY_ZEPHYR_NRF7002_COUNTRY_LEN], uint8_t force)
{
	struct net_if *iface = iface_for_role(role);
	struct wifi_reg_domain domain = {
		.oper = WIFI_MGMT_SET,
		.force = force != 0U,
	};

	if (iface == NULL || country == NULL || force > 1U) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	memcpy(domain.country_code, country, WIFI_COUNTRY_CODE_LEN);
	return net_mgmt(NET_REQUEST_WIFI_REG_DOMAIN, iface, &domain,
			sizeof(domain));
}

int32_t embassy_zephyr_nrf7002_wifi_get_reg_domain(uint8_t role,
	uint8_t country[EMBASSY_ZEPHYR_NRF7002_COUNTRY_LEN],
	struct embassy_zephyr_nrf7002_reg_channel_wire *channels,
	uint32_t capacity, uint32_t *count)
{
	struct net_if *iface = iface_for_role(role);
	struct wifi_reg_chan_info native_channels[MAX_REG_CHAN_NUM] = { 0 };
	struct wifi_reg_domain domain = {
		.oper = WIFI_MGMT_GET,
		.num_channels = MAX_REG_CHAN_NUM,
		.chan_info = native_channels,
	};
	uint32_t index;
	uint32_t copied;
	int ret;

	if (iface == NULL || country == NULL || count == NULL ||
	    (capacity != 0U && channels == NULL)) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	ret = net_mgmt(NET_REQUEST_WIFI_REG_DOMAIN, iface, &domain,
		       sizeof(domain));
	if (ret < 0) {
		return ret;
	}
	memcpy(country, domain.country_code, WIFI_COUNTRY_CODE_LEN);
	*count = domain.num_channels;
	copied = MIN(capacity, domain.num_channels);
	for (index = 0U; index < copied; index++) {
		channels[index].center_frequency_mhz =
			native_channels[index].center_frequency;
		channels[index].max_power_dbm =
			(int8_t)native_channels[index].max_power;
		channels[index].flags =
			(native_channels[index].supported
				 ? EMBASSY_ZEPHYR_NRF7002_REG_SUPPORTED : 0U) |
			(native_channels[index].passive_only
				 ? EMBASSY_ZEPHYR_NRF7002_REG_PASSIVE_ONLY : 0U) |
			(native_channels[index].dfs
				 ? EMBASSY_ZEPHYR_NRF7002_REG_DFS : 0U);
	}
	return 0;
}

int32_t embassy_zephyr_nrf7002_wifi_set_power(
	const struct embassy_zephyr_nrf7002_power_param_wire *params)
{
	struct net_if *iface = iface_for_role(EMBASSY_ZEPHYR_NRF7002_ROLE_STA);
	struct wifi_ps_params power = { 0 };

	if (iface == NULL || params == NULL ||
	    params->parameter > EMBASSY_ZEPHYR_NRF7002_POWER_TIMEOUT) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	power.type = (enum wifi_ps_param_type)params->parameter;
	switch (params->parameter) {
	case EMBASSY_ZEPHYR_NRF7002_POWER_STATE:
		if (params->value8 > WIFI_PS_ENABLED) {
			return -EINVAL;
		}
		power.enabled = (enum wifi_ps)params->value8;
		break;
	case EMBASSY_ZEPHYR_NRF7002_POWER_LISTEN_INTERVAL:
		power.listen_interval = params->value16;
		break;
	case EMBASSY_ZEPHYR_NRF7002_POWER_WAKEUP_MODE:
		if (params->value8 > WIFI_PS_WAKEUP_MODE_LISTEN_INTERVAL) {
			return -EINVAL;
		}
		power.wakeup_mode = (enum wifi_ps_wakeup_mode)params->value8;
		break;
	case EMBASSY_ZEPHYR_NRF7002_POWER_MODE:
		if (params->value8 > WIFI_PS_MODE_WMM) {
			return -EINVAL;
		}
		power.mode = (enum wifi_ps_mode)params->value8;
		break;
	case EMBASSY_ZEPHYR_NRF7002_POWER_EXIT_STRATEGY:
		if (params->value8 > WIFI_PS_EXIT_EVERY_TIM) {
			return -EINVAL;
		}
		power.exit_strategy =
			(enum wifi_ps_exit_strategy)params->value8;
		break;
	case EMBASSY_ZEPHYR_NRF7002_POWER_TIMEOUT:
		power.timeout_ms = params->value32;
		break;
	default:
		return -EINVAL;
	}
	return net_mgmt(NET_REQUEST_WIFI_PS, iface, &power, sizeof(power));
}

int32_t embassy_zephyr_nrf7002_wifi_get_power(
	struct embassy_zephyr_nrf7002_power_config_wire *out)
{
	struct net_if *iface = iface_for_role(EMBASSY_ZEPHYR_NRF7002_ROLE_STA);
	struct wifi_ps_config config = { 0 };
	int index;
	int ret;

	if (iface == NULL || out == NULL) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	ret = net_mgmt(NET_REQUEST_WIFI_PS_CONFIG, iface, &config,
		       sizeof(config));
	if (ret < 0) {
		return ret;
	}
	memset(out, 0, sizeof(*out));
	out->abi_version = EMBASSY_ZEPHYR_NRF7002_ABI_VERSION;
	out->struct_size = sizeof(*out);
	out->enabled = (uint8_t)config.ps_params.enabled;
	out->wakeup_mode = (uint8_t)config.ps_params.wakeup_mode;
	out->mode = (uint8_t)config.ps_params.mode;
	out->exit_strategy = (uint8_t)config.ps_params.exit_strategy;
	out->listen_interval = config.ps_params.listen_interval;
	out->timeout_ms = config.ps_params.timeout_ms;
	out->twt_flow_count = config.num_twt_flows < 0
				      ? 0U : (uint8_t)config.num_twt_flows;
	for (index = 0; index < config.num_twt_flows &&
			index < WIFI_MAX_TWT_FLOWS; index++) {
		if (config.twt_flows[index].flow_id < 8U) {
			out->twt_flow_mask |= BIT(config.twt_flows[index].flow_id);
		}
	}
	return 0;
}

int32_t embassy_zephyr_nrf7002_wifi_twt_setup(
	const struct embassy_zephyr_nrf7002_twt_setup_wire *params)
{
	struct net_if *iface = iface_for_role(EMBASSY_ZEPHYR_NRF7002_ROLE_STA);
	struct wifi_twt_params twt = {
		.operation = WIFI_TWT_SETUP,
	};

	if (iface == NULL || params == NULL ||
	    params->flow_id >= WIFI_MAX_TWT_FLOWS ||
	    params->negotiation_type > WIFI_TWT_WAKE_TBTT ||
	    params->setup_command > WIFI_TWT_SETUP_CMD_DEMAND ||
	    params->trigger > 1U || params->implicit > 1U ||
	    params->announce > 1U || params->interval_us == 0U ||
	    params->wake_interval_us == 0U) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	twt.flow_id = params->flow_id;
	twt.negotiation_type =
		(enum wifi_twt_negotiation_type)params->negotiation_type;
	twt.setup_cmd = (enum wifi_twt_setup_cmd)params->setup_command;
	twt.dialog_token = params->dialog_token;
	twt.setup.trigger = params->trigger != 0U;
	twt.setup.implicit = params->implicit != 0U;
	twt.setup.announce = params->announce != 0U;
	twt.setup.twt_interval = params->interval_us;
	twt.setup.twt_wake_interval = params->wake_interval_us;
	twt.setup.twt_wake_ahead_duration = params->wake_ahead_us;
	return net_mgmt(NET_REQUEST_WIFI_TWT, iface, &twt, sizeof(twt));
}

int32_t embassy_zephyr_nrf7002_wifi_twt_teardown(uint8_t flow_id, uint8_t all_flows)
{
	struct net_if *iface = iface_for_role(EMBASSY_ZEPHYR_NRF7002_ROLE_STA);
	struct wifi_twt_params twt = {
		.operation = WIFI_TWT_TEARDOWN,
	};

	if (iface == NULL || all_flows > 1U ||
	    (all_flows == 0U && flow_id >= WIFI_MAX_TWT_FLOWS)) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	twt.flow_id = flow_id;
	twt.teardown.teardown_all = all_flows != 0U;
	return net_mgmt(NET_REQUEST_WIFI_TWT, iface, &twt, sizeof(twt));
}

int32_t embassy_zephyr_nrf7002_wifi_get_stats(uint8_t role,
	struct embassy_zephyr_nrf7002_stats_wire *out)
{
#if defined(CONFIG_NET_STATISTICS_WIFI)
	struct net_if *iface = iface_for_role(role);
	struct net_stats_wifi stats = { 0 };
	int ret;

	if (iface == NULL || out == NULL) {
		return iface == NULL ? -ENODEV : -EINVAL;
	}
	ret = net_mgmt(NET_REQUEST_STATS_GET_WIFI, iface, &stats,
		       sizeof(stats));
	if (ret < 0) {
		return ret;
	}
	memset(out, 0, sizeof(*out));
	out->abi_version = EMBASSY_ZEPHYR_NRF7002_ABI_VERSION;
	out->struct_size = sizeof(*out);
	out->beacons_received = stats.sta_mgmt.beacons_rx;
	out->beacons_missed = stats.sta_mgmt.beacons_miss;
	out->rx_bytes = stats.bytes.received;
	out->tx_bytes = stats.bytes.sent;
	out->rx_packets = stats.pkts.rx;
	out->tx_packets = stats.pkts.tx;
	out->rx_errors = stats.errors.rx;
	out->tx_errors = stats.errors.tx;
	out->overruns = stats.overrun_count;
	return 0;
#else
	ARG_UNUSED(role);
	ARG_UNUSED(out);
	return -ENOTSUP;
#endif
}

int32_t embassy_zephyr_nrf7002_wifi_reset_stats(uint8_t role)
{
#if defined(CONFIG_NET_STATISTICS_WIFI)
	struct net_if *iface = iface_for_role(role);

	if (iface == NULL) {
		return -ENODEV;
	}
	return net_mgmt(NET_REQUEST_STATS_RESET_WIFI, iface, NULL, 0);
#else
	ARG_UNUSED(role);
	return -ENOTSUP;
#endif
}
