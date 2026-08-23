#include <stddef.h>
#include <stdio.h>

#include "host_rpu_umac_if.h"

#define SIZE(type) printf("sizeof(%s)=%zu\n", #type, sizeof(type))
#define OFFSET(type, field) \
    printf("offsetof(%s,%s)=%zu\n", #type, #field, offsetof(type, field))

int main(void)
{
    SIZE(struct nrf_wifi_key);
    SIZE(struct nrf_wifi_seq);
    SIZE(struct nrf_wifi_umac_key_info);
    SIZE(struct nrf_wifi_ssid);
    SIZE(struct nrf_wifi_ie);
    SIZE(struct nrf_wifi_sae);
    SIZE(struct nrf_wifi_umac_auth_info);
    SIZE(struct nrf_wifi_umac_cmd_auth);
    SIZE(struct nrf_wifi_ht_vht_capabilities);
    SIZE(struct nrf_wifi_connect_common_info);
    SIZE(struct nrf_wifi_umac_cmd_assoc);
    SIZE(struct nrf_wifi_umac_cmd_key);
    SIZE(struct nrf_wifi_umac_cmd_set_key);
    SIZE(struct nrf_wifi_umac_chg_vif_state_info);
    SIZE(struct nrf_wifi_umac_cmd_chg_vif_state);

    OFFSET(struct nrf_wifi_umac_cmd_auth, valid_fields);
    OFFSET(struct nrf_wifi_umac_cmd_auth, info);
    OFFSET(struct nrf_wifi_umac_auth_info, key_info);
    OFFSET(struct nrf_wifi_umac_auth_info, ssid);
    OFFSET(struct nrf_wifi_umac_auth_info, ie);
    OFFSET(struct nrf_wifi_umac_auth_info, sae);
    OFFSET(struct nrf_wifi_umac_auth_info, bssid);
    OFFSET(struct nrf_wifi_umac_auth_info, tsf);
    OFFSET(struct nrf_wifi_umac_cmd_assoc, valid_fields);
    OFFSET(struct nrf_wifi_umac_cmd_assoc, connect_common_info);
    OFFSET(struct nrf_wifi_umac_cmd_assoc, prev_bssid);
    OFFSET(struct nrf_wifi_connect_common_info, ssid);
    OFFSET(struct nrf_wifi_connect_common_info, wpa_ie);
    OFFSET(struct nrf_wifi_connect_common_info, ht_vht_capabilities);
    OFFSET(struct nrf_wifi_connect_common_info, prev_bssid);
    OFFSET(struct nrf_wifi_umac_cmd_key, key_info);
    OFFSET(struct nrf_wifi_umac_cmd_key, mac_addr);
    OFFSET(struct nrf_wifi_umac_cmd_chg_vif_state, info);

    return 0;
}
