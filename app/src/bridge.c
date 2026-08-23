/*
 * Small stock-Zephyr bridge for the Architecture B Stage 0 proof.
 *
 * Zephyr owns the Wi-Fi state machine and WPA supplicant.  The bridge exposes
 * one AF_PACKET/SOCK_RAW endpoint per compiled Wi-Fi role and never passes a
 * net_pkt, Zephyr object, or internal pointer across the C ABI. Calls are
 * serialized by each Rust endpoint owner; no hidden queue or allocator is
 * used here.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/console/console.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>

#include <net/wifi_ready.h>

#include "embassy_zephyr_nrf7002.h"

LOG_MODULE_REGISTER(embassy_zephyr_nrf7002_bridge, CONFIG_LOG_DEFAULT_LEVEL);

#define WIFI_EVENT_MASK \
	(NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT | \
	 NET_EVENT_WIFI_AP_ENABLE_RESULT | NET_EVENT_WIFI_AP_DISABLE_RESULT)

/* A clone/control packet can never make this loop unbounded. */
#define RX_DROP_BUDGET 8U

struct l2_endpoint {
	int fd;
	struct net_if *iface;
	bool active;
	uint8_t role;
	atomic_t pending_event;
	uint8_t ssid[EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN];
	uint8_t psk[EMBASSY_ZEPHYR_NRF7002_MAX_PASSPHRASE_LEN];
};

static struct l2_endpoint endpoints[] = {
	[EMBASSY_ZEPHYR_NRF7002_ROLE_STA] = {
		.fd = -1,
		.role = EMBASSY_ZEPHYR_NRF7002_ROLE_STA,
		.pending_event = ATOMIC_INIT(EMBASSY_ZEPHYR_NRF7002_EVENT_NONE),
	},
	[EMBASSY_ZEPHYR_NRF7002_ROLE_AP] = {
		.fd = -1,
		.role = EMBASSY_ZEPHYR_NRF7002_ROLE_AP,
		.pending_event = ATOMIC_INIT(EMBASSY_ZEPHYR_NRF7002_EVENT_NONE),
	},
};
static struct net_if *wifi_ifaces[ARRAY_SIZE(endpoints)];
static struct net_mgmt_event_callback wifi_event_callback;
static bool wifi_event_callback_registered;
static bool wifi_ready_callback_registered;
static atomic_t wifi_ready = ATOMIC_INIT(0);
static atomic_t console_opened = ATOMIC_INIT(0);

/*
 * Clear credential scratch storage through volatile byte stores.  The
 * bridge's SSID/PSK arrays are only a synchronous request hand-off; the
 * supplicant copies the request into its own reconnect state before
 * net_mgmt() returns.  Volatile stores keep this cleanup observable to the
 * compiler without depending on a potentially elided memset().
 */
static __noinline void secure_zero(void *memory, size_t length)
{
	volatile uint8_t *bytes = (volatile uint8_t *)memory;

	while (length > 0U) {
		*bytes++ = 0U;
		length--;
	}
}

static int32_t socket_errno(void)
{
	int error = errno;

	if (error <= 0) {
		error = EIO;
	}

	return -error;
}

static struct net_if *get_wifi_iface_role(uint8_t role)
{
	if (role >= ARRAY_SIZE(endpoints)) {
		return NULL;
	}
	if (wifi_ifaces[role] == NULL) {
		if (role == EMBASSY_ZEPHYR_NRF7002_ROLE_STA) {
			wifi_ifaces[role] = net_if_get_wifi_sta();
		} else {
#if defined(CONFIG_NRF70_AP_MODE)
			wifi_ifaces[role] = net_if_get_wifi_sap();
#endif
		}
	}
	return wifi_ifaces[role];
}

static struct net_if *get_wifi_iface(void)
{
	return get_wifi_iface_role(EMBASSY_ZEPHYR_NRF7002_ROLE_STA);
}

static struct l2_endpoint *endpoint_for_iface(struct net_if *iface)
{
	uint8_t role;

	for (role = 0U; role < ARRAY_SIZE(endpoints); role++) {
		if (iface == get_wifi_iface_role(role)) {
			return &endpoints[role];
		}
	}
	return NULL;
}

static void wifi_event_handler(struct net_mgmt_event_callback *callback,
				       uint64_t mgmt_event,
				       struct net_if *iface)
{
	struct l2_endpoint *endpoint = endpoint_for_iface(iface);

	if (endpoint == NULL) {
		return;
	}

	if (mgmt_event == NET_EVENT_WIFI_CONNECT_RESULT) {
		const struct wifi_status *status = callback->info;

		if (status != NULL && callback->info_length >= sizeof(*status) &&
		    status->conn_status == WIFI_STATUS_CONN_SUCCESS) {
			atomic_set(&endpoint->pending_event,
				   EMBASSY_ZEPHYR_NRF7002_EVENT_CONNECTED);
		} else {
			atomic_set(&endpoint->pending_event,
				   EMBASSY_ZEPHYR_NRF7002_EVENT_DISCONNECTED);
		}
	} else if (mgmt_event == NET_EVENT_WIFI_DISCONNECT_RESULT) {
		atomic_set(&endpoint->pending_event,
			   EMBASSY_ZEPHYR_NRF7002_EVENT_DISCONNECTED);
	} else if (mgmt_event == NET_EVENT_WIFI_AP_ENABLE_RESULT) {
		const struct wifi_status *status = callback->info;

		if (status != NULL && callback->info_length >= sizeof(*status) &&
		    status->ap_status == WIFI_STATUS_AP_SUCCESS) {
			atomic_set(&endpoint->pending_event,
				   EMBASSY_ZEPHYR_NRF7002_EVENT_CONNECTED);
		} else {
			atomic_set(&endpoint->pending_event,
				   EMBASSY_ZEPHYR_NRF7002_EVENT_DISCONNECTED);
		}
	} else if (mgmt_event == NET_EVENT_WIFI_AP_DISABLE_RESULT) {
		atomic_set(&endpoint->pending_event,
			   EMBASSY_ZEPHYR_NRF7002_EVENT_DISCONNECTED);
	}
}

static void wifi_ready_handler(bool ready)
{
	atomic_set(&wifi_ready, ready ? 1 : 0);
}

static int32_t register_wifi_events(void)
{
	wifi_ready_callback_t ready_callback = {
		.wifi_ready_cb = wifi_ready_handler,
	};
	int ret;

	if (get_wifi_iface() == NULL) {
		return -ENODEV;
	}

	if (!wifi_event_callback_registered) {
		net_mgmt_init_event_callback(&wifi_event_callback,
					     wifi_event_handler,
					     WIFI_EVENT_MASK);
		net_mgmt_add_event_callback(&wifi_event_callback);
		wifi_event_callback_registered = true;
	}

	if (!wifi_ready_callback_registered) {
		ret = register_wifi_ready_callback(ready_callback,
						 get_wifi_iface());
		if (ret < 0 && ret != -EALREADY) {
			return ret;
		}
		wifi_ready_callback_registered = true;
	}
	return 0;
}

static uint16_t read_be16(const uint8_t *data)
{
	return ((uint16_t)data[0] << 8) | data[1];
}

static bool is_eapol(const uint8_t *frame, size_t length)
{
	size_t offset = EMBASSY_ZEPHYR_NRF7002_ETH_HEADER_LEN - 2U;
	uint16_t ether_type;
	unsigned int tags = 0U;

	if (length < EMBASSY_ZEPHYR_NRF7002_ETH_HEADER_LEN) {
		return false;
	}

	ether_type = read_be16(&frame[offset]);
	while (tags < 8U &&
	       (ether_type == 0x8100U || ether_type == 0x88a8U ||
		ether_type == 0x9100U)) {
		if (length < offset + 6U) {
			return false;
		}
		offset += 4U;
		ether_type = read_be16(&frame[offset]);
		tags++;
	}

	return ether_type == ETH_P_EAPOL;
}

static uint32_t wire_status(struct net_if *iface)
{
	struct wifi_iface_status status = { 0 };
	int ret;

	if (iface == NULL) {
		return EMBASSY_ZEPHYR_NRF7002_STATUS_DOWN;
	}
	if (atomic_get(&wifi_ready) == 0) {
		return EMBASSY_ZEPHYR_NRF7002_STATUS_DOWN;
	}

	ret = net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
			       sizeof(status));
	if (ret < 0) {
		return EMBASSY_ZEPHYR_NRF7002_STATUS_DOWN;
	}

	switch (status.state) {
	case WIFI_STATE_COMPLETED:
		return EMBASSY_ZEPHYR_NRF7002_STATUS_CONNECTED;
	case WIFI_STATE_AUTHENTICATING:
	case WIFI_STATE_ASSOCIATING:
	case WIFI_STATE_ASSOCIATED:
	case WIFI_STATE_4WAY_HANDSHAKE:
	case WIFI_STATE_GROUP_HANDSHAKE:
	case WIFI_STATE_SCANNING:
		return EMBASSY_ZEPHYR_NRF7002_STATUS_CONNECTING;
	case WIFI_STATE_INACTIVE:
		return EMBASSY_ZEPHYR_NRF7002_STATUS_READY;
	case WIFI_STATE_DISCONNECTED:
		return EMBASSY_ZEPHYR_NRF7002_STATUS_DISCONNECTED;
	case WIFI_STATE_INTERFACE_DISABLED:
	case WIFI_STATE_UNKNOWN:
	default:
		return EMBASSY_ZEPHYR_NRF7002_STATUS_DOWN;
	}
}

static int32_t fill_interface(struct net_if *iface,
				      struct embassy_zephyr_nrf7002_interface_wire *out)
{
	struct net_linkaddr *link_addr;

	if (iface == NULL || out == NULL) {
		return -EINVAL;
	}

	link_addr = net_if_get_link_addr(iface);
	if (link_addr == NULL || link_addr->len < EMBASSY_ZEPHYR_NRF7002_MAC_LEN) {
		return -EIO;
	}

	memset(out, 0, sizeof(*out));
	out->abi_version = EMBASSY_ZEPHYR_NRF7002_ABI_VERSION;
	out->struct_size = sizeof(*out);
	memcpy(out->mac, link_addr->addr, EMBASSY_ZEPHYR_NRF7002_MAC_LEN);
	out->mtu = net_if_get_mtu(iface);
	out->status = wire_status(iface);
	return 0;
}

static struct l2_endpoint *endpoint_from_handle(void *handle)
{
	uint8_t role;

	for (role = 0U; role < ARRAY_SIZE(endpoints); role++) {
		if (handle == &endpoints[role] && endpoints[role].active &&
		    endpoints[role].fd >= 0) {
			return &endpoints[role];
		}
	}
	return NULL;
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

static int32_t connect_params(
	struct l2_endpoint *endpoint,
	const struct embassy_zephyr_nrf7002_connect_params *params)
{
	struct net_if *iface;
	struct wifi_connect_req_params request = { 0 };
	uint64_t timeout_seconds;
	int timeout;
	int ret;

	if (endpoint == NULL || params == NULL || params->ssid == NULL ||
		params->ssid_len == 0U ||
		params->ssid_len > EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN) {
		return -EINVAL;
	}
	iface = endpoint->iface;
	if (iface == NULL) {
		return -ENODEV;
	}

	ret = map_security(params->security, &request.security);
	if (ret < 0) {
		return ret;
	}
	if (params->mfp > EMBASSY_ZEPHYR_NRF7002_MFP_REQUIRED) {
		return -EINVAL;
	}
	if (params->band != EMBASSY_ZEPHYR_NRF7002_BAND_ANY &&
	    params->band > EMBASSY_ZEPHYR_NRF7002_BAND_5_GHZ) {
		return -EINVAL;
	}
	if (params->channel != EMBASSY_ZEPHYR_NRF7002_CHANNEL_ANY &&
	    params->channel != 0U &&
	    (params->channel < WIFI_CHANNEL_MIN ||
	     params->channel > WIFI_CHANNEL_MAX)) {
		return -EINVAL;
	}
	if (params->bandwidth != EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_AUTO &&
	    (params->bandwidth < EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_20_MHZ ||
	     params->bandwidth > EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_80_MHZ)) {
		return -EINVAL;
	}
	if (params->hidden_ssid > 2U || params->bssid_set > 1U) {
		return -EINVAL;
	}

	request.ssid = params->ssid;
	request.ssid_length = (uint8_t)params->ssid_len;
	request.mfp = (enum wifi_mfp_options)params->mfp;
	request.band = params->band == EMBASSY_ZEPHYR_NRF7002_BAND_ANY
			      ? WIFI_FREQ_BAND_UNKNOWN : params->band;
	request.channel = params->channel == 0U ||
			  params->channel == EMBASSY_ZEPHYR_NRF7002_CHANNEL_ANY
				 ? WIFI_CHANNEL_ANY : params->channel;
	request.bandwidth = params->bandwidth == EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_AUTO
				    ? WIFI_FREQ_BANDWIDTH_UNKNOWN
				    : (enum wifi_frequency_bandwidths)params->bandwidth;
	request.ignore_broadcast_ssid = params->hidden_ssid;
	if (params->bssid_set != 0U) {
		memcpy(request.bssid, params->bssid, WIFI_MAC_ADDR_LEN);
	}

	if (request.security == WIFI_SECURITY_TYPE_NONE) {
		if (params->psk_len != 0U) {
			return -EINVAL;
		}
	} else if (params->psk == NULL || params->psk_len < 8U ||
		   params->psk_len > EMBASSY_ZEPHYR_NRF7002_MAX_PASSPHRASE_LEN) {
		return -EINVAL;
	} else if (request.security == WIFI_SECURITY_TYPE_SAE ||
		   request.security == WIFI_SECURITY_TYPE_SAE_H2E ||
		   request.security == WIFI_SECURITY_TYPE_SAE_AUTO) {
		request.sae_password = params->psk;
		request.sae_password_length = (uint8_t)params->psk_len;
	} else {
		request.psk = endpoint->psk;
		request.psk_length = (uint8_t)params->psk_len;
	}

	secure_zero(endpoint->ssid, sizeof(endpoint->ssid));
	secure_zero(endpoint->psk, sizeof(endpoint->psk));
	memcpy(endpoint->ssid, params->ssid, params->ssid_len);
	request.ssid = endpoint->ssid;
	if (params->psk_len != 0U) {
		memcpy(endpoint->psk, params->psk, params->psk_len);
		if (request.security == WIFI_SECURITY_TYPE_SAE ||
		    request.security == WIFI_SECURITY_TYPE_SAE_H2E ||
		    request.security == WIFI_SECURITY_TYPE_SAE_AUTO) {
			request.sae_password = endpoint->psk;
		}
	}

	if (params->timeout_ms == 0U) {
		timeout = SYS_FOREVER_MS;
	} else {
		timeout_seconds = ((uint64_t)params->timeout_ms + 999U) / 1000U;
		timeout = timeout_seconds > (uint64_t)INT_MAX
				? INT_MAX : (int)timeout_seconds;
	}
	request.timeout = timeout;

	/*
	 * NCS hostap copies the request into WPA's internal credential state
	 * synchronously.  The request pointers are not used after this call, so
	 * erase the bridge scratch arrays on both success and failure.  WPA keeps
	 * its own copied credentials for reconnect; these arrays must not become a
	 * second long-lived credential store.
	 */
	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &request,
			       sizeof(request));
	secure_zero(endpoint->ssid, sizeof(endpoint->ssid));
	secure_zero(endpoint->psk, sizeof(endpoint->psk));
	return ret < 0 ? ret : 0;
}

uint32_t embassy_zephyr_nrf7002_l2_abi_version(void)
{
	return EMBASSY_ZEPHYR_NRF7002_ABI_VERSION;
}

int32_t embassy_zephyr_nrf7002_l2_init(struct embassy_zephyr_nrf7002_interface_wire *interface)
{
	struct net_if *iface;
	int32_t ret;

	if (interface == NULL) {
		return -EINVAL;
	}

	iface = get_wifi_iface();
	if (iface == NULL) {
		return -ENODEV;
	}
	ret = register_wifi_events();
	if (ret < 0) {
		return ret;
	}

	return fill_interface(iface, interface);
}

int32_t embassy_zephyr_nrf7002_l2_open(void **handle)
{
	return embassy_zephyr_nrf7002_l2_open_role(EMBASSY_ZEPHYR_NRF7002_ROLE_STA, handle);
}

int32_t embassy_zephyr_nrf7002_l2_open_role(uint8_t role, void **handle)
{
	struct sockaddr_ll address = { 0 };
	struct l2_endpoint *endpoint;
	struct net_if *iface;
	int ifindex;
	int fd;
	int ret;

	if (handle == NULL || role >= ARRAY_SIZE(endpoints)) {
		return -EINVAL;
	}
	*handle = NULL;
	endpoint = &endpoints[role];
	if (endpoint->active) {
		return -EBUSY;
	}

	iface = get_wifi_iface_role(role);
	if (iface == NULL) {
		return -ENODEV;
	}
	ret = register_wifi_events();
	if (ret < 0) {
		return ret;
	}
	/* Rust must explicitly enable the selected role through
	 * embassy_zephyr_nrf7002_wifi_set_enabled(). Opening an L2 transport never changes radio
	 * or interface policy. */
	if (!net_if_is_admin_up(iface)) {
		return -ENETDOWN;
	}
	if (atomic_get(&wifi_ready) == 0) {
		return -EAGAIN;
	}
	ifindex = net_if_get_by_iface(iface);
	if (ifindex <= 0) {
		return -ENODEV;
	}

	fd = zsock_socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		return socket_errno();
	}

	address.sll_family = AF_PACKET;
	address.sll_protocol = htons(ETH_P_ALL);
	address.sll_ifindex = ifindex;
	ret = zsock_bind(fd, (const struct sockaddr *)&address,
			 sizeof(address));
	if (ret < 0) {
		int32_t error = socket_errno();

		(void)zsock_close(fd);
		return error;
	}

	endpoint->fd = fd;
	endpoint->iface = iface;
	endpoint->active = true;
	atomic_set(&endpoint->pending_event, EMBASSY_ZEPHYR_NRF7002_EVENT_NONE);
	*handle = endpoint;
	return 0;
}

int32_t embassy_zephyr_nrf7002_l2_close(void *handle)
{
	struct l2_endpoint *endpoint = endpoint_from_handle(handle);
	int ret;

	if (endpoint == NULL) {
		return -EBADF;
	}

	endpoint->active = false;
	ret = zsock_close(endpoint->fd);
	endpoint->fd = -1;
	endpoint->iface = NULL;
	secure_zero(endpoint->ssid, sizeof(endpoint->ssid));
	secure_zero(endpoint->psk, sizeof(endpoint->psk));
	atomic_set(&endpoint->pending_event, EMBASSY_ZEPHYR_NRF7002_EVENT_NONE);
	return ret < 0 ? socket_errno() : 0;
}

int32_t embassy_zephyr_nrf7002_l2_interface(
	void *handle, struct embassy_zephyr_nrf7002_interface_wire *interface)
{
	struct l2_endpoint *endpoint = endpoint_from_handle(handle);

	if (endpoint == NULL || interface == NULL) {
		return -EINVAL;
	}

	return fill_interface(endpoint->iface, interface);
}

int32_t embassy_zephyr_nrf7002_l2_connect(void *handle, const uint8_t *ssid, size_t ssid_len)
{
	struct l2_endpoint *endpoint = endpoint_from_handle(handle);
	struct embassy_zephyr_nrf7002_connect_params params = {
		.ssid = ssid,
		.ssid_len = ssid_len,
		.security = EMBASSY_ZEPHYR_NRF7002_SECURITY_OPEN,
		.band = EMBASSY_ZEPHYR_NRF7002_BAND_ANY,
		.channel = EMBASSY_ZEPHYR_NRF7002_CHANNEL_ANY,
		.bandwidth = EMBASSY_ZEPHYR_NRF7002_BANDWIDTH_AUTO,
	};

	if (endpoint == NULL) {
		return -EBADF;
	}
	if (endpoint->role != EMBASSY_ZEPHYR_NRF7002_ROLE_STA) {
		return -ENOTSUP;
	}
	if (ssid == NULL || ssid_len == 0U ||
	    ssid_len > EMBASSY_ZEPHYR_NRF7002_MAX_SSID_LEN) {
		return -EINVAL;
	}

	/* The current Rust adapter carries only an SSID.  It therefore supports
	 * an open network here unless the application enables Zephyr's stock
	 * stored-credential request.  Secure networks use
	 * embassy_zephyr_nrf7002_l2_connect_psk() or that stored path; no credential is compiled
	 * in this source. */
#if defined(CONFIG_WIFI_CREDENTIALS_CONNECT_STORED)
	/* Zephyr resolves and copies the selected credential synchronously from
	 * its configured backend.  The SSID remains an input validation witness;
	 * selection policy belongs to that stock credentials subsystem. */
	return net_mgmt(NET_REQUEST_WIFI_CONNECT_STORED, endpoint->iface, NULL, 0);
#else
	return connect_params(endpoint, &params);
#endif
}

int32_t embassy_zephyr_nrf7002_l2_connect_psk(
	void *handle, const struct embassy_zephyr_nrf7002_connect_params *params)
{
	struct l2_endpoint *endpoint = endpoint_from_handle(handle);

	if (endpoint == NULL) {
		return -EBADF;
	}
	if (endpoint->role != EMBASSY_ZEPHYR_NRF7002_ROLE_STA) {
		return -ENOTSUP;
	}
	atomic_set(&endpoint->pending_event, EMBASSY_ZEPHYR_NRF7002_EVENT_NONE);

	return connect_params(endpoint, params);
}

int32_t embassy_zephyr_nrf7002_l2_disconnect(void *handle)
{
	struct l2_endpoint *endpoint = endpoint_from_handle(handle);
	int ret;

	if (endpoint == NULL) {
		return -EBADF;
	}

	if (endpoint->role == EMBASSY_ZEPHYR_NRF7002_ROLE_AP) {
		ret = net_mgmt(NET_REQUEST_WIFI_AP_DISABLE, endpoint->iface,
			       NULL, 0);
	} else {
		ret = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, endpoint->iface,
			       NULL, 0);
	}
	secure_zero(endpoint->ssid, sizeof(endpoint->ssid));
	secure_zero(endpoint->psk, sizeof(endpoint->psk));
	return ret < 0 ? ret : 0;
}

int32_t embassy_zephyr_nrf7002_l2_poll(void *handle, uint32_t timeout_ms,
			       struct embassy_zephyr_nrf7002_poll_wire *result)
{
	struct l2_endpoint *endpoint = endpoint_from_handle(handle);
	struct zsock_pollfd pollfd = { 0 };
	int timeout;
	int ret;
	int event;

	if (endpoint == NULL || result == NULL) {
		return -EINVAL;
	}

	result->event = EMBASSY_ZEPHYR_NRF7002_EVENT_NONE;
	result->status = wire_status(endpoint->iface);
	event = (int)atomic_get(&endpoint->pending_event);
	if (event != EMBASSY_ZEPHYR_NRF7002_EVENT_NONE) {
		atomic_set(&endpoint->pending_event,
			   EMBASSY_ZEPHYR_NRF7002_EVENT_NONE);
		result->event = (uint32_t)event;
		result->status = wire_status(endpoint->iface);
		return 0;
	}

	timeout = timeout_ms > (uint32_t)INT_MAX ? INT_MAX : (int)timeout_ms;
	pollfd.fd = endpoint->fd;
	pollfd.events = ZSOCK_POLLIN;
	ret = zsock_poll(&pollfd, 1, timeout);
	if (ret < 0) {
		return socket_errno();
	}
	if (ret == 0) {
		return -EAGAIN;
	}
	if (pollfd.revents & ZSOCK_POLLNVAL) {
		return -EBADF;
	}
	if (pollfd.revents & (ZSOCK_POLLERR | ZSOCK_POLLHUP)) {
		return -EIO;
	}

	result->status = wire_status(endpoint->iface);
	return 0;
}

int32_t embassy_zephyr_nrf7002_l2_recv(void *handle, uint8_t *buffer, size_t capacity,
			       size_t *received)
{
	struct l2_endpoint *endpoint = endpoint_from_handle(handle);
	unsigned int dropped = 0U;

	if (endpoint == NULL || buffer == NULL || received == NULL) {
		return -EINVAL;
	}
	if (capacity < EMBASSY_ZEPHYR_NRF7002_MAX_FRAME_LEN) {
		return -EMSGSIZE;
	}

	*received = 0U;
	while (dropped < RX_DROP_BUDGET) {
		ssize_t length;

		length = zsock_recvfrom(endpoint->fd, buffer, capacity,
					ZSOCK_MSG_DONTWAIT, NULL, NULL);
		if (length < 0) {
			return socket_errno();
		}
		if ((size_t)length < EMBASSY_ZEPHYR_NRF7002_ETH_HEADER_LEN ||
		    is_eapol(buffer, (size_t)length)) {
			/* AF_PACKET receives a bounded clone; dropping it here leaves
			 * Zephyr's original packet available to WPA/EAPOL handling. */
			dropped++;
			continue;
		}

		*received = (size_t)length;
		return 0;
	}

	return -EAGAIN;
}

int32_t embassy_zephyr_nrf7002_l2_send(void *handle, const uint8_t *buffer, size_t length)
{
	struct l2_endpoint *endpoint = endpoint_from_handle(handle);
	struct sockaddr_ll destination = { 0 };
	int ifindex;
	ssize_t sent;

	if (endpoint == NULL || buffer == NULL) {
		return -EINVAL;
	}
	if (length < EMBASSY_ZEPHYR_NRF7002_ETH_HEADER_LEN ||
	    length > EMBASSY_ZEPHYR_NRF7002_MAX_FRAME_LEN) {
		return -EMSGSIZE;
	}
	if (is_eapol(buffer, length)) {
		/* The controlled port belongs to WPA supplicant, not Rust. */
		return -EPERM;
	}

	ifindex = net_if_get_by_iface(endpoint->iface);
	if (ifindex <= 0) {
		return -ENODEV;
	}
	destination.sll_family = AF_PACKET;
	destination.sll_protocol = htons(ETH_P_ALL);
	destination.sll_ifindex = ifindex;
	destination.sll_halen = EMBASSY_ZEPHYR_NRF7002_MAC_LEN;
	memcpy(destination.sll_addr, buffer, EMBASSY_ZEPHYR_NRF7002_MAC_LEN);

	sent = zsock_sendto(endpoint->fd, buffer, length, ZSOCK_MSG_DONTWAIT,
				(const struct sockaddr *)&destination,
				sizeof(destination));
	if (sent < 0) {
		return socket_errno();
	}
	if ((size_t)sent != length) {
		return -EIO;
	}

	return 0;
}

int32_t embassy_zephyr_nrf7002_console_open(void)
{
	int ret;

	if (!atomic_cas(&console_opened, 0, 1)) {
		return -EBUSY;
	}

	ret = console_init();
	if (ret < 0) {
		atomic_set(&console_opened, 0);
		return ret;
	}
	console_set_rx_timeout(K_NO_WAIT);
	console_set_tx_timeout(K_NO_WAIT);
	return 0;
}

int32_t embassy_zephyr_nrf7002_console_read(uint8_t *buffer, size_t capacity,
			    size_t *received)
{
	ssize_t length;

	if (atomic_get(&console_opened) == 0) {
		return -EBADF;
	}
	if (buffer == NULL || received == NULL || capacity == 0U) {
		return -EINVAL;
	}

	*received = 0U;
	length = console_read(NULL, buffer, capacity);
	if (length < 0) {
		return (int32_t)length;
	}
	*received = (size_t)length;
	return 0;
}

int32_t embassy_zephyr_nrf7002_random_fill(uint8_t *buffer, size_t length)
{
	if (buffer == NULL && length != 0U) {
		return -EINVAL;
	}

	return sys_csrand_get(buffer, length);
}
