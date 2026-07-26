#ifndef AIRPORTAL_TYPES_H
#define AIRPORTAL_TYPES_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <net/if.h>

#define AIRPORTAL_VERSION "0.1.0"
#define AIRPORTAL_MAX_PORTALS 16
#define AIRPORTAL_MAX_BINDINGS 32
#define AIRPORTAL_MAX_RADIUS_PROFILES 8
#define AIRPORTAL_MAX_WALLED_GARDENS 64
#define AIRPORTAL_MAX_CLIENTS 512
#define AIRPORTAL_MAX_SESSIONS 512
#define AIRPORTAL_TOKEN_MAX 2048

enum airportal_client_state {
	AIRPORTAL_CLIENT_NEW = 0,
	AIRPORTAL_CLIENT_CAPTIVE,
	AIRPORTAL_CLIENT_AUTH_PENDING,
	AIRPORTAL_CLIENT_AUTHENTICATED,
	AIRPORTAL_CLIENT_SESSION_EXPIRED,
	AIRPORTAL_CLIENT_IDLE_EXPIRED,
	AIRPORTAL_CLIENT_QUOTA_EXCEEDED,
	AIRPORTAL_CLIENT_BLOCKED,
	AIRPORTAL_CLIENT_DISCONNECTED
};

struct airportal_client_key {
	uint8_t mac[6];
	uint32_t ifindex;
	uint16_t vlan_id;
	uint32_t portal_id;
};

struct airportal_client {
	struct airportal_client_key key;

	char ifname[IFNAMSIZ];
	char network[32];
	char ssid[33];
	char bssid[18];

	struct in_addr ipv4;
	bool has_ipv4;

	struct in6_addr ipv6;
	bool has_ipv6;

	enum airportal_client_state state;

	uint64_t first_seen_ms;
	uint64_t last_seen_ms;
	uint64_t authenticated_at_ms;

	char username[128];
	char session_id[96];
	char uam_challenge[33];

	uint64_t input_octets;
	uint64_t output_octets;

	uint32_t auth_generation;
	void *private_data;
};

struct airportal_session_policy {
	uint32_t session_timeout_sec;
	uint32_t idle_timeout_sec;
	uint64_t idle_activity_threshold_bytes;
	uint32_t accounting_interval_sec;

	uint64_t max_input_octets;
	uint64_t max_output_octets;
	uint64_t max_total_octets;

	uint64_t max_upload_bps;
	uint64_t max_download_bps;

	uint16_t assigned_vlan;
	bool has_assigned_vlan;

	bool allow_ipv4;
	bool allow_ipv6;

	char filter_id[128];
	char radius_class[256];
};

struct airportal_session {
	char session_id[96];
	struct airportal_client *client;
	struct airportal_session_policy policy;

	uint64_t started_at_ms;
	uint64_t last_activity_ms;
	uint64_t expires_at_ms;
	uint64_t idle_expires_at_ms;

	uint64_t input_octets;
	uint64_t output_octets;
	uint64_t last_activity_input_octets;
	uint64_t last_activity_output_octets;
	uint64_t input_octets_base;
	uint64_t output_octets_base;
	uint64_t last_accounting_input_octets;
	uint64_t last_accounting_output_octets;
	uint64_t last_accounting_update_ms;

	bool accounting_started;
	bool policy_installed;
	bool restored_after_restart;
};

struct airportal_metrics {
	uint64_t clients_seen;
	uint64_t sessions_started;
	uint64_t sessions_stopped;
	uint64_t auth_accepts;
	uint64_t auth_rejects;
	uint64_t radius_timeouts;
	uint64_t accounting_failures;
	uint64_t coa_requests;
	uint64_t disconnect_requests;
	uint64_t quota_disconnects;
	uint64_t idle_disconnects;
	uint64_t session_timeout_disconnects;
	uint64_t policy_install_failures;
	uint64_t http_redirects;
	uint64_t token_validation_failures;
};

struct airportal_token_claims {
	uint32_t version;
	char device_id[64];
	uint32_t portal_id;
	uint8_t client_mac[6];
	char client_ip[INET6_ADDRSTRLEN];
	char ifname[IFNAMSIZ];
	uint64_t issued_at;
	uint64_t expires_at;
	char nonce[65];
	uint32_t generation;
};

uint32_t airportal_client_key_hash(const struct airportal_client_key *key);
bool airportal_client_key_equal(const struct airportal_client_key *a,
				const struct airportal_client_key *b);
const char *airportal_client_state_name(enum airportal_client_state state);
bool airportal_parse_mac(const char *text, uint8_t mac[6]);
void airportal_format_mac(const uint8_t mac[6], char *buf, size_t len);
uint64_t airportal_monotonic_ms(void);
uint64_t airportal_wall_time_sec(void);

#endif
