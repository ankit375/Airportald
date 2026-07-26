#include "airportal_types.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

uint32_t airportal_client_key_hash(const struct airportal_client_key *key)
{
	uint32_t hash = 2166136261u;
	size_t i;

	for (i = 0; i < sizeof(key->mac); i++) {
		hash ^= key->mac[i];
		hash *= 16777619u;
	}

	hash ^= key->ifindex;
	hash *= 16777619u;
	hash ^= key->vlan_id;
	hash *= 16777619u;
	hash ^= key->portal_id;
	hash *= 16777619u;

	return hash;
}

bool airportal_client_key_equal(const struct airportal_client_key *a,
				const struct airportal_client_key *b)
{
	return memcmp(a->mac, b->mac, sizeof(a->mac)) == 0 &&
	       a->ifindex == b->ifindex &&
	       a->vlan_id == b->vlan_id &&
	       a->portal_id == b->portal_id;
}

const char *airportal_client_state_name(enum airportal_client_state state)
{
	switch (state) {
	case AIRPORTAL_CLIENT_NEW:
		return "new";
	case AIRPORTAL_CLIENT_CAPTIVE:
		return "captive";
	case AIRPORTAL_CLIENT_AUTH_PENDING:
		return "auth_pending";
	case AIRPORTAL_CLIENT_AUTHENTICATED:
		return "authenticated";
	case AIRPORTAL_CLIENT_SESSION_EXPIRED:
		return "session_expired";
	case AIRPORTAL_CLIENT_IDLE_EXPIRED:
		return "idle_expired";
	case AIRPORTAL_CLIENT_QUOTA_EXCEEDED:
		return "quota_exceeded";
	case AIRPORTAL_CLIENT_BLOCKED:
		return "blocked";
	case AIRPORTAL_CLIENT_DISCONNECTED:
		return "disconnected";
	default:
		return "unknown";
	}
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

bool airportal_parse_mac(const char *text, uint8_t mac[6])
{
	size_t i;

	if (!text || strlen(text) != 17)
		return false;

	for (i = 0; i < 6; i++) {
		int hi = hex_value(text[i * 3]);
		int lo = hex_value(text[i * 3 + 1]);

		if (hi < 0 || lo < 0)
			return false;
		if (i < 5 && text[i * 3 + 2] != ':')
			return false;
		mac[i] = (uint8_t)((hi << 4) | lo);
	}

	return true;
}

void airportal_format_mac(const uint8_t mac[6], char *buf, size_t len)
{
	if (!buf || len == 0)
		return;

	snprintf(buf, len, "%02X:%02X:%02X:%02X:%02X:%02X",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

uint64_t airportal_monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint64_t airportal_wall_time_sec(void)
{
	return (uint64_t)time(NULL);
}
