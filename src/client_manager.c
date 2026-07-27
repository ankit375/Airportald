#include "client_manager.h"

#include "log.h"

#include <net/if.h>
#include <stdio.h>
#include <string.h>

void airportal_client_manager_init(struct airportal_client_manager *mgr)
{
	memset(mgr, 0, sizeof(*mgr));
}

struct airportal_client *
airportal_client_find(struct airportal_client_manager *mgr,
		      const struct airportal_client_key *key)
{
	size_t i;

	for (i = 0; i < AIRPORTAL_MAX_CLIENTS; i++) {
		if (mgr->used[i] &&
		    airportal_client_key_equal(&mgr->clients[i].key, key))
			return &mgr->clients[i];
	}

	return NULL;
}

struct airportal_client *
airportal_client_find_by_mac_if_portal(struct airportal_client_manager *mgr,
				       const uint8_t mac[6],
				       const char *ifname,
				       uint32_t portal_id)
{
	size_t i;

	for (i = 0; i < AIRPORTAL_MAX_CLIENTS; i++) {
		struct airportal_client *client = &mgr->clients[i];

		if (!mgr->used[i])
			continue;
		if (memcmp(client->key.mac, mac, 6) == 0 &&
		    strcmp(client->ifname, ifname) == 0 &&
		    client->key.portal_id == portal_id)
			return client;
	}

	return NULL;
}

struct airportal_client *
airportal_client_find_by_ipv4_state(struct airportal_client_manager *mgr,
				    struct in_addr ipv4,
				    enum airportal_client_state state)
{
	size_t i;

	for (i = 0; i < AIRPORTAL_MAX_CLIENTS; i++) {
		struct airportal_client *client = &mgr->clients[i];

		if (!mgr->used[i] || client->state != state || !client->has_ipv4)
			continue;
		if (client->ipv4.s_addr == ipv4.s_addr)
			return client;
	}

	return NULL;
}

struct airportal_client *
airportal_client_find_unique_by_mac_state(struct airportal_client_manager *mgr,
					  const uint8_t mac[6],
					  enum airportal_client_state state)
{
	struct airportal_client *match = NULL;
	size_t i;

	for (i = 0; i < AIRPORTAL_MAX_CLIENTS; i++) {
		struct airportal_client *client = &mgr->clients[i];

		if (!mgr->used[i] || client->state != state ||
		    memcmp(client->key.mac, mac, 6) != 0)
			continue;
		if (match)
			return NULL;
		match = client;
	}

	return match;
}

void airportal_client_set_ipv4(struct airportal_client *client,
			       struct in_addr ipv4)
{
	if (!client)
		return;
	client->ipv4 = ipv4;
	client->has_ipv4 = true;
	client->last_seen_ms = airportal_monotonic_ms();
}

struct airportal_client *
airportal_client_upsert(struct airportal_client_manager *mgr,
			const struct airportal_client_key *key,
			const char *ifname,
			const char *network,
			const char *ssid,
			const char *bssid)
{
	struct airportal_client *client;
	uint64_t now = airportal_monotonic_ms();
	size_t i;

	client = airportal_client_find(mgr, key);
	if (client) {
		client->last_seen_ms = now;
		if (client->state == AIRPORTAL_CLIENT_DISCONNECTED) {
			client->state = AIRPORTAL_CLIENT_CAPTIVE;
			client->auth_generation++;
		}
		return client;
	}

	for (i = 0; i < AIRPORTAL_MAX_CLIENTS; i++) {
		if (mgr->used[i])
			continue;

		mgr->used[i] = true;
		mgr->count++;
		client = &mgr->clients[i];
		memset(client, 0, sizeof(*client));
		client->key = *key;
		snprintf(client->ifname, sizeof(client->ifname), "%s", ifname ? ifname : "");
		snprintf(client->network, sizeof(client->network), "%s", network ? network : "");
		snprintf(client->ssid, sizeof(client->ssid), "%s", ssid ? ssid : "");
		snprintf(client->bssid, sizeof(client->bssid), "%s", bssid ? bssid : "");
		client->state = AIRPORTAL_CLIENT_CAPTIVE;
		client->first_seen_ms = now;
		client->last_seen_ms = now;
		client->auth_generation = 1;
		return client;
	}

	ap_log_error("client_table_full max=%u", AIRPORTAL_MAX_CLIENTS);
	return NULL;
}

void airportal_client_mark_disconnected(struct airportal_client *client)
{
	if (!client)
		return;

	client->state = AIRPORTAL_CLIENT_DISCONNECTED;
	client->last_seen_ms = airportal_monotonic_ms();
	client->auth_generation++;
}

void airportal_client_remove(struct airportal_client_manager *mgr,
			     struct airportal_client *client)
{
	size_t index;

	if (!mgr || !client || client < mgr->clients ||
	    client >= mgr->clients + AIRPORTAL_MAX_CLIENTS)
		return;
	index = (size_t)(client - mgr->clients);
	if (!mgr->used[index])
		return;

	memset(client, 0, sizeof(*client));
	mgr->used[index] = false;
	if (mgr->count)
		mgr->count--;
}

size_t airportal_client_count_state(const struct airportal_client_manager *mgr,
				    enum airportal_client_state state)
{
	size_t i;
	size_t count = 0;

	for (i = 0; i < AIRPORTAL_MAX_CLIENTS; i++) {
		if (mgr->used[i] && mgr->clients[i].state == state)
			count++;
	}

	return count;
}
