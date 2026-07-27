#include "hostapd_monitor.h"

#include "enforcement_manager.h"
#include "log.h"
#include "persistence.h"

#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef AIRPORTAL_OPENWRT
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#endif

struct hostapd_monitor_state {
	struct airportal_daemon *daemon;
	ev_timer poll_timer;
};

static void prune_disconnected_duplicates(struct airportal_daemon *daemon,
					  const uint8_t mac[6],
					  const char *ifname,
					  uint32_t portal_id)
{
	size_t i;

	for (i = 0; i < AIRPORTAL_MAX_CLIENTS; i++) {
		struct airportal_client *client = &daemon->clients.clients[i];
		char mac_buf[18];

		if (!daemon->clients.used[i] ||
		    client->state != AIRPORTAL_CLIENT_DISCONNECTED ||
		    client->key.portal_id != portal_id ||
		    memcmp(client->key.mac, mac, 6) != 0 ||
		    strcmp(client->ifname, ifname) == 0)
			continue;

		enforcement_remove(daemon, client);
		airportal_format_mac(client->key.mac, mac_buf, sizeof(mac_buf));
		ap_log_info("client_pruned_stale mac=%s old_ifname=%s new_ifname=%s portal_id=%u",
			    mac_buf, client->ifname, ifname, portal_id);
		airportal_client_remove(&daemon->clients, client);
	}
}

static int handle_connected(struct airportal_daemon *daemon,
			    const char *ifname,
			    const char *mac_text)
{
	const struct airportal_binding_config *binding;
	const struct airportal_portal_config *portal;
	struct airportal_client_key key;
	struct airportal_client *client;
	bool is_new;
	char mac_buf[18];

	binding = airportal_config_find_binding(&daemon->config, ifname);
	if (!binding)
		return -1;
	portal = airportal_config_find_portal_by_id(&daemon->config,
						    binding->portal_id);
	if (!portal || !portal->enabled)
		return -1;

	memset(&key, 0, sizeof(key));
	if (!airportal_parse_mac(mac_text, key.mac))
		return -1;
	key.ifindex = if_nametoindex(ifname);
	key.portal_id = portal->portal_id;
	prune_disconnected_duplicates(daemon, key.mac, ifname, key.portal_id);

	client = airportal_client_find(&daemon->clients, &key);
	is_new = !client || client->state == AIRPORTAL_CLIENT_DISCONNECTED;
	client = airportal_client_upsert(&daemon->clients, &key, ifname,
					 portal->network, "", "");
	if (!client)
		return -1;

	if (is_new) {
		int restored = persistence_try_restore_client(daemon, client);

		if (restored > 0) {
			airportal_format_mac(key.mac, mac_buf, sizeof(mac_buf));
			ap_log_info("client_restored mac=%s ifname=%s portal_id=%u",
				    mac_buf, ifname, key.portal_id);
			daemon->metrics.clients_seen++;
			return 0;
		}
		if (enforcement_install_captive(daemon, client) != 0) {
			daemon->metrics.policy_install_failures++;
			return -1;
		}

		airportal_format_mac(key.mac, mac_buf, sizeof(mac_buf));
		ap_log_info("client_connected mac=%s ifname=%s portal_id=%u",
			    mac_buf, ifname, key.portal_id);
		daemon->metrics.clients_seen++;
	}

	return 0;
}

static int handle_disconnected(struct airportal_daemon *daemon,
			       const char *ifname,
			       const char *mac_text)
{
	const struct airportal_binding_config *binding;
	struct airportal_client *client;
	uint8_t mac[6];

	binding = airportal_config_find_binding(&daemon->config, ifname);
	if (!binding || !airportal_parse_mac(mac_text, mac))
		return -1;

	client = airportal_client_find_by_mac_if_portal(&daemon->clients, mac,
						       ifname,
						       binding->portal_id);
	if (!client)
		return 0;
	airportal_disconnect_client(daemon, mac, ifname, binding->portal_id,
				    "lost_carrier");
	airportal_client_mark_disconnected(client);
	return 0;
}

int hostapd_monitor_handle_event(struct airportal_daemon *daemon,
				 const char *ifname,
				 const char *event)
{
	const char *mac;

	if (!daemon || !ifname || !event)
		return -1;

	mac = strstr(event, "AP-STA-CONNECTED ");
	if (mac)
		return handle_connected(daemon, ifname,
					mac + strlen("AP-STA-CONNECTED "));

	mac = strstr(event, "AP-STA-DISCONNECTED ");
	if (mac)
		return handle_disconnected(daemon, ifname,
					   mac + strlen("AP-STA-DISCONNECTED "));

	return 0;
}

#ifdef AIRPORTAL_OPENWRT
struct hostapd_poll_context {
	struct airportal_daemon *daemon;
	const char *ifname;
};

enum {
	GET_CLIENTS_CLIENTS,
	__GET_CLIENTS_MAX
};

static const struct blobmsg_policy get_clients_policy[__GET_CLIENTS_MAX] = {
	[GET_CLIENTS_CLIENTS] = { .name = "clients", .type = BLOBMSG_TYPE_TABLE },
};

static void update_client_octets(struct airportal_daemon *daemon,
				 const char *ifname, const char *mac_text,
				 uint64_t input_octets,
				 uint64_t output_octets)
{
	const struct airportal_binding_config *binding;
	struct airportal_client *client;
	struct airportal_session *session;
	uint8_t mac[6];

	binding = airportal_config_find_binding(&daemon->config, ifname);
	if (!binding || !airportal_parse_mac(mac_text, mac))
		return;

	client = airportal_client_find_by_mac_if_portal(&daemon->clients, mac,
						       ifname,
						       binding->portal_id);
	if (!client)
		return;
	client->input_octets = input_octets;
	client->output_octets = output_octets;

	session = airportal_session_find_by_client(&daemon->sessions, client);
	if (!session)
		return;
	airportal_session_update_octets(
		session,
		input_octets >= session->input_octets_base ?
		input_octets - session->input_octets_base : 0,
		output_octets >= session->output_octets_base ?
		output_octets - session->output_octets_base : 0,
		airportal_monotonic_ms());
}

static uint64_t blobmsg_get_uint64_any(struct blob_attr *attr)
{
	switch (blobmsg_type(attr)) {
	case BLOBMSG_TYPE_INT8:
		return blobmsg_get_u8(attr);
	case BLOBMSG_TYPE_INT16:
		return blobmsg_get_u16(attr);
	case BLOBMSG_TYPE_INT32:
		return blobmsg_get_u32(attr);
	case BLOBMSG_TYPE_INT64:
		return blobmsg_get_u64(attr);
	default:
		return 0;
	}
}

static bool parse_client_bytes(struct blob_attr *client,
			       uint64_t *rx, uint64_t *tx)
{
	struct blob_attr *cur;
	size_t rem;

	*rx = 0;
	*tx = 0;
	blobmsg_for_each_attr(cur, client, rem) {
		struct blob_attr *bytes_cur;
		size_t bytes_rem;

		if (strcmp(blobmsg_name(cur), "bytes") != 0 ||
		    blobmsg_type(cur) != BLOBMSG_TYPE_TABLE)
			continue;
		blobmsg_for_each_attr(bytes_cur, cur, bytes_rem) {
			if (strcmp(blobmsg_name(bytes_cur), "rx") == 0)
				*rx = blobmsg_get_uint64_any(bytes_cur);
			else if (strcmp(blobmsg_name(bytes_cur), "tx") == 0)
				*tx = blobmsg_get_uint64_any(bytes_cur);
		}
		return *rx != 0 || *tx != 0;
	}
	return false;
}

static void get_clients_cb(struct ubus_request *req, int type,
			   struct blob_attr *msg)
{
	struct hostapd_poll_context *ctx = (struct hostapd_poll_context *)req->priv;
	struct blob_attr *tb[__GET_CLIENTS_MAX];
	struct blob_attr *cur;
	size_t rem;

	(void)type;
	if (!msg || !ctx)
		return;

	blobmsg_parse(get_clients_policy, __GET_CLIENTS_MAX, tb,
		      blob_data(msg), blob_len(msg));
	if (!tb[GET_CLIENTS_CLIENTS])
		return;

	blobmsg_for_each_attr(cur, tb[GET_CLIENTS_CLIENTS], rem) {
		const char *mac = blobmsg_name(cur);
		uint64_t rx = 0;
		uint64_t tx = 0;

		if (mac && mac[0]) {
			handle_connected(ctx->daemon, ctx->ifname, mac);
			if (parse_client_bytes(cur, &rx, &tx))
				update_client_octets(ctx->daemon, ctx->ifname,
						     mac, rx, tx);
		}
	}
}

static void poll_hostapd_interface(struct airportal_daemon *daemon,
				   const char *ifname)
{
	struct hostapd_poll_context ctx = {
		.daemon = daemon,
		.ifname = ifname,
	};
	char object[96];
	uint32_t id;

	if (!daemon->ubus || !ifname || !ifname[0])
		return;

	snprintf(object, sizeof(object), "hostapd.%s", ifname);
	if (ubus_lookup_id(daemon->ubus, object, &id) != 0) {
		ap_log_debug("hostapd_object_unavailable object=%s", object);
		return;
	}

	ubus_invoke(daemon->ubus, id, "get_clients", NULL, get_clients_cb,
		    &ctx, 1000);
}

static void expire_stale_clients(struct airportal_daemon *daemon, uint64_t now)
{
	size_t i;

	for (i = 0; i < AIRPORTAL_MAX_CLIENTS; i++) {
		struct airportal_client *client = &daemon->clients.clients[i];
		char mac[18];

		if (!daemon->clients.used[i] ||
		    client->state == AIRPORTAL_CLIENT_DISCONNECTED ||
		    !airportal_config_find_binding(&daemon->config, client->ifname) ||
		    now - client->last_seen_ms <= 15000)
			continue;

		airportal_format_mac(client->key.mac, mac, sizeof(mac));
		handle_disconnected(daemon, client->ifname, mac);
	}
}

static void poll_timer_cb(EV_P_ ev_timer *w, int revents)
{
	struct hostapd_monitor_state *state =
		(struct hostapd_monitor_state *)w->data;
	size_t i;

	(void)loop;
	(void)revents;
	for (i = 0; i < state->daemon->config.binding_count; i++)
		poll_hostapd_interface(state->daemon,
				       state->daemon->config.bindings[i].vif);
	expire_stale_clients(state->daemon, airportal_monotonic_ms());
}
#endif

int hostapd_monitor_init(struct airportal_daemon *daemon)
{
#ifdef AIRPORTAL_OPENWRT
	struct hostapd_monitor_state *state;

	if (!daemon->ubus) {
		ap_log_warn("hostapd_monitor_unavailable reason=ubus_unavailable");
		return -1;
	}

	state = calloc(1, sizeof(*state));
	if (!state)
		return -1;
	state->daemon = daemon;
	ev_timer_init(&state->poll_timer, poll_timer_cb, 0.1, 2.0);
	state->poll_timer.data = state;
	ev_timer_start(daemon->loop, &state->poll_timer);
	daemon->hostapd_monitor = state;
	ap_log_info("hostapd_monitor_ready mode=ubus_poll interval_sec=2");
	return 0;
#else
	(void)daemon;
	ap_log_info("hostapd_monitor_ready mode=event_parser_only");
	return 0;
#endif
}

void hostapd_monitor_shutdown(struct airportal_daemon *daemon)
{
#ifdef AIRPORTAL_OPENWRT
	struct hostapd_monitor_state *state = daemon->hostapd_monitor;

	if (!state)
		return;
	ev_timer_stop(daemon->loop, &state->poll_timer);
	free(state);
	daemon->hostapd_monitor = NULL;
#else
	(void)daemon;
#endif
}

int hostapd_monitor_deauth_client(struct airportal_daemon *daemon,
				  const char *ifname,
				  const uint8_t mac[6],
				  const char *reason)
{
#ifdef AIRPORTAL_OPENWRT
	struct blob_buf req = { 0 };
	char object[96];
	char mac_text[18];
	uint32_t id;
	int rc;

	if (!daemon || !daemon->ubus || !ifname || !ifname[0] || !mac)
		return -1;

	snprintf(object, sizeof(object), "hostapd.%s", ifname);
	if (ubus_lookup_id(daemon->ubus, object, &id) != 0) {
		ap_log_warn("hostapd_deauth_failed reason=object_unavailable ifname=%s",
			    ifname);
		return -1;
	}

	airportal_format_mac(mac, mac_text, sizeof(mac_text));
	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "addr", mac_text);
	blobmsg_add_u32(&req, "reason", 5);
	blobmsg_add_u8(&req, "deauth", true);
	blobmsg_add_u32(&req, "ban_time", 1);

	rc = ubus_invoke(daemon->ubus, id, "del_client", req.head, NULL, NULL,
			 1000);
	blob_buf_free(&req);
	if (rc != 0) {
		ap_log_warn("hostapd_deauth_failed mac=%s ifname=%s ubus_rc=%d",
			    mac_text, ifname, rc);
		return -1;
	}

	ap_log_info("hostapd_deauth_sent mac=%s ifname=%s reason=%s",
		    mac_text, ifname, reason ? reason : "disconnect");
	return 0;
#else
	(void)daemon;
	(void)ifname;
	(void)mac;
	(void)reason;
	return 0;
#endif
}
