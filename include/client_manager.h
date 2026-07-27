#ifndef AIRPORTAL_CLIENT_MANAGER_H
#define AIRPORTAL_CLIENT_MANAGER_H

#include "airportal_types.h"

struct airportal_client_manager {
	struct airportal_client clients[AIRPORTAL_MAX_CLIENTS];
	bool used[AIRPORTAL_MAX_CLIENTS];
	size_t count;
};

void airportal_client_manager_init(struct airportal_client_manager *mgr);
struct airportal_client *
airportal_client_upsert(struct airportal_client_manager *mgr,
			const struct airportal_client_key *key,
			const char *ifname,
			const char *network,
			const char *ssid,
			const char *bssid);
struct airportal_client *
airportal_client_find(struct airportal_client_manager *mgr,
		      const struct airportal_client_key *key);
struct airportal_client *
airportal_client_find_by_mac_if_portal(struct airportal_client_manager *mgr,
				       const uint8_t mac[6],
				       const char *ifname,
				       uint32_t portal_id);
struct airportal_client *
airportal_client_find_by_ipv4_state(struct airportal_client_manager *mgr,
				    struct in_addr ipv4,
				    enum airportal_client_state state);
struct airportal_client *
airportal_client_find_unique_by_mac_state(struct airportal_client_manager *mgr,
					  const uint8_t mac[6],
					  enum airportal_client_state state);
void airportal_client_set_ipv4(struct airportal_client *client,
			       struct in_addr ipv4);
void airportal_client_mark_disconnected(struct airportal_client *client);
void airportal_client_remove(struct airportal_client_manager *mgr,
			     struct airportal_client *client);
size_t airportal_client_count_state(const struct airportal_client_manager *mgr,
				    enum airportal_client_state state);

#endif
