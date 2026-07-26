#include "client_manager.h"
#include "config_manager.h"
#include "session_manager.h"
#include "token_manager.h"

#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_mac_and_key(void)
{
	struct airportal_client_key a;
	struct airportal_client_key b;
	uint8_t mac[6];
	char text[18];

	assert(airportal_parse_mac("AA:BB:CC:DD:EE:FF", mac));
	airportal_format_mac(mac, text, sizeof(text));
	assert(strcmp(text, "AA:BB:CC:DD:EE:FF") == 0);
	assert(!airportal_parse_mac("AA:BB:CC:DD:EE", mac));

	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	memcpy(a.mac, mac, sizeof(a.mac));
	memcpy(b.mac, mac, sizeof(b.mac));
	a.ifindex = b.ifindex = 7;
	a.portal_id = b.portal_id = 36;
	assert(airportal_client_key_equal(&a, &b));
	assert(airportal_client_key_hash(&a) == airportal_client_key_hash(&b));
	b.portal_id = 37;
	assert(!airportal_client_key_equal(&a, &b));
}

static void test_config_validation(void)
{
	struct airportal_config cfg;

	airportal_config_defaults(&cfg);
	snprintf(cfg.portals[0].name, sizeof(cfg.portals[0].name), "guest");
	cfg.portals[0].enabled = true;
	cfg.portals[0].portal_id = 36;
	snprintf(cfg.portals[0].auth_mode, sizeof(cfg.portals[0].auth_mode), "manual");
	snprintf(cfg.portals[0].portal_url, sizeof(cfg.portals[0].portal_url), "https://p.example/login");
	cfg.portals[0].default_session_timeout = 300;
	cfg.portals[0].default_idle_timeout = 60;
	cfg.portal_count = 1;
	snprintf(cfg.bindings[0].portal, sizeof(cfg.bindings[0].portal), "guest");
	snprintf(cfg.bindings[0].vif, sizeof(cfg.bindings[0].vif), "wlan1-1");
	cfg.binding_count = 1;
	assert(airportal_config_validate(&cfg) == 0);
	assert(airportal_config_find_binding(&cfg, "wlan1-1") != NULL);

	cfg.bindings[1] = cfg.bindings[0];
	cfg.binding_count = 2;
	assert(airportal_config_validate(&cfg) != 0);
}

static void test_client_session_timeout(void)
{
	struct airportal_client_manager clients;
	struct airportal_session_manager sessions;
	struct airportal_client_key key;
	struct airportal_client *client;
	struct airportal_session_policy policy;
	uint8_t mac[6];

	airportal_client_manager_init(&clients);
	airportal_session_manager_init(&sessions);
	assert(airportal_parse_mac("00:11:22:33:44:55", mac));
	memset(&key, 0, sizeof(key));
	memcpy(key.mac, mac, sizeof(key.mac));
	key.ifindex = 4;
	key.portal_id = 36;
	client = airportal_client_upsert(&clients, &key, "wlan1-1", "guest", "", "");
	assert(client != NULL);
	assert(client->state == AIRPORTAL_CLIENT_CAPTIVE);

	memset(&policy, 0, sizeof(policy));
	policy.session_timeout_sec = 1;
	policy.allow_ipv4 = true;
	assert(airportal_session_start(&sessions, client, "AP001", "test", &policy) != NULL);
	assert(client->state == AIRPORTAL_CLIENT_AUTHENTICATED);
	assert(airportal_session_expire_due(&sessions, airportal_monotonic_ms() + 2000) == 1);
	assert(client->state == AIRPORTAL_CLIENT_SESSION_EXPIRED);
	assert(sessions.count == 0);
}

static void test_session_restore(void)
{
	struct airportal_client_manager clients;
	struct airportal_session_manager sessions;
	struct airportal_client_key key;
	struct airportal_client *client;
	struct airportal_session *session;
	struct airportal_session_policy policy;

	airportal_client_manager_init(&clients);
	airportal_session_manager_init(&sessions);
	memset(&key, 0, sizeof(key));
	assert(airportal_parse_mac("00:11:22:33:44:66", key.mac));
	key.ifindex = 4;
	key.portal_id = 36;
	client = airportal_client_upsert(&clients, &key, "wlan1-1", "guest", "", "");
	assert(client != NULL);

	memset(&policy, 0, sizeof(policy));
	policy.session_timeout_sec = 300;
	policy.idle_timeout_sec = 60;
	policy.allow_ipv4 = true;
	session = airportal_session_restore(&sessions, client, "AP001-99",
					    "demo", &policy, 300000, 60000,
					    10, 20, 30, 40);
	assert(session != NULL);
	assert(strcmp(session->session_id, "AP001-99") == 0);
	assert(session->restored_after_restart);
	assert(client->state == AIRPORTAL_CLIENT_AUTHENTICATED);
	assert(strcmp(client->username, "demo") == 0);
	assert(sessions.count == 1);
}

static void test_session_octets_refresh_idle(void)
{
	struct airportal_client_manager clients;
	struct airportal_session_manager sessions;
	struct airportal_client_key key;
	struct airportal_client *client;
	struct airportal_session *session;
	struct airportal_session_policy policy;
	uint64_t first_idle_deadline;

	airportal_client_manager_init(&clients);
	airportal_session_manager_init(&sessions);
	memset(&key, 0, sizeof(key));
	assert(airportal_parse_mac("00:11:22:33:44:77", key.mac));
	key.ifindex = 4;
	key.portal_id = 36;
	client = airportal_client_upsert(&clients, &key, "wlan1-1", "guest", "", "");
	assert(client != NULL);

	memset(&policy, 0, sizeof(policy));
	policy.session_timeout_sec = 300;
	policy.idle_timeout_sec = 60;
	policy.allow_ipv4 = true;
	session = airportal_session_start(&sessions, client, "AP001", "demo",
					  &policy);
	assert(session != NULL);
	first_idle_deadline = session->idle_expires_at_ms;

	airportal_session_update_octets(session, 0, 0,
					session->started_at_ms + 10000);
	assert(session->idle_expires_at_ms == first_idle_deadline);

	airportal_session_update_octets(session, 1, 0,
					session->started_at_ms + 10000);
	assert(session->input_octets == 1);
	assert(session->idle_expires_at_ms ==
	       session->started_at_ms + 70000);
}

static void test_client_ip_lookup(void)
{
	struct airportal_client_manager clients;
	struct airportal_client_key key_a;
	struct airportal_client_key key_b;
	struct airportal_client *client_a;
	struct airportal_client *client_b;
	struct in_addr ip;

	airportal_client_manager_init(&clients);
	memset(&key_a, 0, sizeof(key_a));
	memset(&key_b, 0, sizeof(key_b));
	assert(airportal_parse_mac("00:11:22:33:44:55", key_a.mac));
	assert(airportal_parse_mac("00:11:22:33:44:55", key_b.mac));
	key_a.ifindex = 4;
	key_a.portal_id = 36;
	key_b.ifindex = 5;
	key_b.portal_id = 37;

	client_a = airportal_client_upsert(&clients, &key_a, "wlan1-1",
					   "guest", "", "");
	client_b = airportal_client_upsert(&clients, &key_b, "wlan1-2",
					   "guest2", "", "");
	assert(client_a != NULL);
	assert(client_b != NULL);
	assert(airportal_client_find_unique_by_mac_state(
		       &clients, key_a.mac, AIRPORTAL_CLIENT_CAPTIVE) == NULL);

	client_b->state = AIRPORTAL_CLIENT_AUTHENTICATED;
	assert(airportal_client_find_unique_by_mac_state(
		       &clients, key_a.mac, AIRPORTAL_CLIENT_CAPTIVE) == client_a);

	assert(inet_pton(AF_INET, "192.0.2.10", &ip) == 1);
	airportal_client_set_ipv4(client_a, ip);
	assert(client_a->has_ipv4);
	assert(airportal_client_find_by_ipv4_state(
		       &clients, ip, AIRPORTAL_CLIENT_CAPTIVE) == client_a);
	assert(airportal_client_find_by_ipv4_state(
		       &clients, ip, AIRPORTAL_CLIENT_AUTHENTICATED) == NULL);
}

static void test_token_replay(void)
{
	struct token_manager tokens;
	struct airportal_client client;
	struct airportal_portal_config portal;
	struct airportal_token_claims claims;
	char *token = NULL;
	uint8_t mac[6];

	assert(token_manager_init(&tokens, NULL) == 0);
	memset(&client, 0, sizeof(client));
	memset(&portal, 0, sizeof(portal));
	assert(airportal_parse_mac("AA:BB:CC:DD:EE:FF", mac));
	memcpy(client.key.mac, mac, sizeof(client.key.mac));
	client.key.portal_id = 36;
	client.auth_generation = 2;
	snprintf(client.ifname, sizeof(client.ifname), "wlan1-1");
	portal.portal_id = 36;
	snprintf(portal.portal_url, sizeof(portal.portal_url), "https://p.example/login");

	assert(token_create(&tokens, &client, &portal, &token) == 0);
	assert(token_validate(&tokens, token, &claims) == 0);
	assert(claims.portal_id == 36);
	assert(token_validate(&tokens, token, &claims) != 0);
	assert(token_validate(&tokens, "bad-token", &claims) != 0);
	free(token);
}

int main(void)
{
	test_mac_and_key();
	test_config_validation();
	test_client_session_timeout();
	test_session_restore();
	test_session_octets_refresh_idle();
	test_client_ip_lookup();
	test_token_replay();
	puts("ok");
	return 0;
}
