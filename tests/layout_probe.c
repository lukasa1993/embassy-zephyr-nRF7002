#include <stddef.h>

#include "host_rpu_umac_if.h"

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
