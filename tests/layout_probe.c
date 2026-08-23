#include <stddef.h>

#include "host_rpu_umac_if.h"

_Static_assert(NRF_WIFI_HOST_RPU_MSG_TYPE_SYSTEM == 0,
               "system message value changed");
_Static_assert(NRF_WIFI_HOST_RPU_MSG_TYPE_SUPPLICANT == 1,
               "supplicant message value changed");
_Static_assert(NRF_WIFI_HOST_RPU_MSG_TYPE_DATA == 2,
               "data message value changed");
_Static_assert(NRF_WIFI_HOST_RPU_MSG_TYPE_UMAC == 3,
               "UMAC message value changed");

_Static_assert(NRF_WIFI_UMAC_CMD_TRIGGER_SCAN == 0,
               "trigger-scan command value changed");
_Static_assert(NRF_WIFI_UMAC_CMD_GET_SCAN_RESULTS == 1,
               "get-scan-results command value changed");
_Static_assert(NRF_WIFI_UMAC_CMD_AUTHENTICATE == 2,
               "authenticate command value changed");
_Static_assert(NRF_WIFI_UMAC_CMD_ASSOCIATE == 3,
               "associate command value changed");
_Static_assert(NRF_WIFI_UMAC_CMD_DEAUTHENTICATE == 4,
               "deauthenticate command value changed");
_Static_assert(NRF_WIFI_UMAC_CMD_NEW_KEY == 6,
               "new-key command value changed");
_Static_assert(NRF_WIFI_UMAC_CMD_DEL_KEY == 7,
               "delete-key command value changed");
_Static_assert(NRF_WIFI_UMAC_CMD_SET_KEY == 8,
               "set-key command value changed");
_Static_assert(NRF_WIFI_UMAC_CMD_NEW_INTERFACE == 15,
               "new-interface command value changed");

_Static_assert(NRF_WIFI_UMAC_EVENT_TRIGGER_SCAN_START == 257,
               "scan-start event value changed");
_Static_assert(NRF_WIFI_UMAC_EVENT_SCAN_ABORTED == 258,
               "scan-aborted event value changed");
_Static_assert(NRF_WIFI_UMAC_EVENT_SCAN_DONE == 259,
               "scan-done event value changed");
_Static_assert(NRF_WIFI_UMAC_EVENT_SCAN_RESULT == 260,
               "scan-result event value changed");
_Static_assert(NRF_WIFI_UMAC_EVENT_DEAUTHENTICATE == 264,
               "deauthenticate event value changed");
_Static_assert(NRF_WIFI_UMAC_EVENT_DISCONNECT == 271,
               "disconnect event value changed");
_Static_assert(NRF_WIFI_UMAC_EVENT_NEW_INTERFACE == 281,
               "new-interface event value changed");
_Static_assert(NRF_WIFI_UMAC_EVENT_SCAN_DISPLAY_RESULT == 291,
               "scan-display event value changed");
_Static_assert(NRF_WIFI_UMAC_EVENT_CMD_STATUS == 292,
               "command-status event value changed");

_Static_assert(NRF_WIFI_CMD_TX_BUFF == 1,
               "TX command value changed");
_Static_assert(NRF_WIFI_CMD_TX_BUFF_DONE == 2,
               "TX-done event value changed");
_Static_assert(NRF_WIFI_CMD_RX_BUFF == 3,
               "RX event value changed");
_Static_assert(NRF_WIFI_CMD_CARRIER_ON == 4,
               "carrier-on event value changed");
_Static_assert(NRF_WIFI_CMD_CARRIER_OFF == 5,
               "carrier-off event value changed");

_Static_assert(MAX_NRF_WIFI_UMAC_CMD_SIZE == 400,
               "UMAC command fragment limit changed");
_Static_assert(TX_BUF_HEADROOM == 52,
               "TX buffer headroom changed");
_Static_assert(RPU_MEM_TX_CMD_BASE == 0xB00000B8,
               "TX command base changed");
_Static_assert(RPU_MEM_PKT_BASE == 0xB0005000,
               "packet RAM base changed");
_Static_assert(RPU_DATA_CMD_SIZE_MAX_TX == 148,
               "TX command slot size changed");

_Static_assert(sizeof(struct host_rpu_msg_hdr) == 8,
               "host_rpu_msg_hdr size changed");
_Static_assert(sizeof(struct host_rpu_msg) == 12,
               "host_rpu_msg size changed");
_Static_assert(sizeof(struct nrf_wifi_index_ids) == 20,
               "nrf_wifi_index_ids size changed");
_Static_assert(offsetof(struct nrf_wifi_index_ids, wdev_id) == 12,
               "nrf_wifi_index_ids.wdev_id offset changed");
_Static_assert(sizeof(struct nrf_wifi_umac_hdr) == 36,
               "nrf_wifi_umac_hdr size changed");
_Static_assert(offsetof(struct nrf_wifi_umac_hdr, ids) == 16,
               "nrf_wifi_umac_hdr.ids offset changed");
_Static_assert(sizeof(struct nrf_wifi_cmd_sys_init) == 366,
               "nrf_wifi_cmd_sys_init size changed");
_Static_assert(sizeof(struct nrf_wifi_scan_params) == 486,
               "nrf_wifi_scan_params size changed");
_Static_assert(offsetof(struct nrf_wifi_scan_params, center_frequency) == 486,
               "nrf_wifi_scan_params.center_frequency offset changed");
_Static_assert(sizeof(struct nrf_wifi_umac_scan_info) == 490,
               "nrf_wifi_umac_scan_info size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_cmd_scan) == 526,
               "nrf_wifi_umac_cmd_scan size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_add_vif_info) == 34,
               "nrf_wifi_umac_add_vif_info size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_cmd_add_vif) == 74,
               "nrf_wifi_umac_cmd_add_vif size changed");

_Static_assert(sizeof(struct nrf_wifi_umac_key_info) == 535,
               "nrf_wifi_umac_key_info size changed");
_Static_assert(offsetof(struct nrf_wifi_umac_key_info, key_idx) == 534,
               "nrf_wifi_umac_key_info.key_idx offset changed");
_Static_assert(sizeof(struct nrf_wifi_umac_auth_info) == 1672,
               "nrf_wifi_umac_auth_info size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_cmd_auth) == 1712,
               "nrf_wifi_umac_cmd_auth size changed");
_Static_assert(sizeof(struct nrf_wifi_connect_common_info) == 1563,
               "nrf_wifi_connect_common_info size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_cmd_assoc) == 1609,
               "nrf_wifi_umac_cmd_assoc size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_cmd_key) == 581,
               "nrf_wifi_umac_cmd_key size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_cmd_set_key) == 571,
               "nrf_wifi_umac_cmd_set_key size changed");
_Static_assert(sizeof(struct nrf_wifi_cmd_req_set_reg) == 46,
               "nrf_wifi_cmd_req_set_reg size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_cmd_chg_sta) == 829,
               "nrf_wifi_umac_cmd_chg_sta size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_cmd_chg_vif_state) == 41,
               "nrf_wifi_umac_cmd_chg_vif_state size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_cmd_set_power_save) == 40,
               "nrf_wifi_umac_cmd_set_power_save size changed");
_Static_assert(sizeof(struct nrf_wifi_umac_event_mlme) == 475,
               "nrf_wifi_umac_event_mlme size changed");
_Static_assert(offsetof(struct nrf_wifi_umac_event_mlme, req_ie) == 475,
               "nrf_wifi_umac_event_mlme.req_ie offset changed");
_Static_assert(sizeof(struct nrf_wifi_umac_event_new_scan_results) == 106,
               "nrf_wifi_umac_event_new_scan_results size changed");
_Static_assert(offsetof(struct nrf_wifi_umac_event_new_scan_results, ies) == 106,
               "nrf_wifi_umac_event_new_scan_results.ies offset changed");

_Static_assert(sizeof(struct nrf_wifi_umac_head) == 8,
               "nrf_wifi_umac_head size changed");
_Static_assert(sizeof(struct tx_mac_hdr_info) == 26,
               "tx_mac_hdr_info size changed");
_Static_assert(sizeof(struct nrf_wifi_tx_buff_info) == 6,
               "nrf_wifi_tx_buff_info size changed");
_Static_assert(offsetof(struct nrf_wifi_tx_buff, tx_buff_info) == 41,
               "nrf_wifi_tx_buff.tx_buff_info offset changed");
_Static_assert(sizeof(struct nrf_wifi_rx_buff_info) == 17,
               "nrf_wifi_rx_buff_info size changed");
_Static_assert(offsetof(struct nrf_wifi_rx_buff, rx_buff_info) == 20,
               "nrf_wifi_rx_buff.rx_buff_info offset changed");

int main(void) { return 0; }
