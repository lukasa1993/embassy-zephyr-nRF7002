/*
 * Stock nRF Wi-Fi calls Zephyr's multicast monitor registration hook even
 * when both native IP families are disabled.  Zephyr declares that hook in
 * net_if.h but compiles its implementation out in a pure-L2 configuration.
 *
 * Keep the compatibility seam in this application (never in Nordic/Zephyr
 * sources).  With no native IPv4 or IPv6 addresses there are no multicast
 * memberships to monitor, so the exact no-IP behaviour is a no-op.
 */

#include <stdbool.h>

#include <zephyr/net/net_if.h>

#if !defined(CONFIG_NET_NATIVE_IPV4) && !defined(CONFIG_NET_NATIVE_IPV6)
void net_if_mcast_mon_register(struct net_if_mcast_monitor *mon,
			       struct net_if *iface,
			       net_if_mcast_callback_t cb)
{
	(void)mon;
	(void)iface;
	(void)cb;
}

void net_if_mcast_mon_unregister(struct net_if_mcast_monitor *mon)
{
	(void)mon;
}

void net_if_mcast_monitor(struct net_if *iface, const struct net_addr *addr,
			  bool is_joined)
{
	(void)iface;
	(void)addr;
	(void)is_joined;
}
#endif
