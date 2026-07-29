#include "ubus_api.h"

#include "log.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef AIRPORTAL_OPENWRT
#include <libubox/blobmsg_json.h>
#include <libubox/utils.h>
#include <libubus.h>

enum {
	AUTH_MAC,
	AUTH_IFNAME,
	AUTH_PORTAL_ID,
	AUTH_USERNAME,
	AUTH_SESSION_TIMEOUT,
	AUTH_IDLE_TIMEOUT,
	AUTH_IDLE_ACTIVITY_THRESHOLD_BYTES,
	AUTH_UPLOAD_BPS,
	AUTH_DOWNLOAD_BPS,
	AUTH_MAX_INPUT_OCTETS,
	AUTH_MAX_OUTPUT_OCTETS,
	AUTH_MAX_TOTAL_OCTETS,
	__AUTH_MAX
};

static const struct blobmsg_policy auth_policy[__AUTH_MAX] = {
	[AUTH_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
	[AUTH_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[AUTH_PORTAL_ID] = { .name = "portal_id", .type = BLOBMSG_TYPE_INT32 },
	[AUTH_USERNAME] = { .name = "username", .type = BLOBMSG_TYPE_STRING },
	[AUTH_SESSION_TIMEOUT] = { .name = "session_timeout", .type = BLOBMSG_TYPE_INT32 },
	[AUTH_IDLE_TIMEOUT] = { .name = "idle_timeout", .type = BLOBMSG_TYPE_INT32 },
	[AUTH_IDLE_ACTIVITY_THRESHOLD_BYTES] = { .name = "idle_activity_threshold_bytes", .type = BLOBMSG_TYPE_UNSPEC },
	[AUTH_UPLOAD_BPS] = { .name = "upload_bps", .type = BLOBMSG_TYPE_UNSPEC },
	[AUTH_DOWNLOAD_BPS] = { .name = "download_bps", .type = BLOBMSG_TYPE_UNSPEC },
	[AUTH_MAX_INPUT_OCTETS] = { .name = "max_input_octets", .type = BLOBMSG_TYPE_UNSPEC },
	[AUTH_MAX_OUTPUT_OCTETS] = { .name = "max_output_octets", .type = BLOBMSG_TYPE_UNSPEC },
	[AUTH_MAX_TOTAL_OCTETS] = { .name = "max_total_octets", .type = BLOBMSG_TYPE_UNSPEC },
};

enum {
	DISC_MAC,
	DISC_IFNAME,
	DISC_PORTAL_ID,
	DISC_REASON,
	__DISC_MAX
};

static const struct blobmsg_policy disc_policy[__DISC_MAX] = {
	[DISC_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
	[DISC_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[DISC_PORTAL_ID] = { .name = "portal_id", .type = BLOBMSG_TYPE_INT32 },
	[DISC_REASON] = { .name = "reason", .type = BLOBMSG_TYPE_STRING },
};

struct ubus_api_state {
	struct ubus_object obj;
	struct ubus_context *ctx;
	struct airportal_daemon *daemon;
	ev_io io;
};

static struct blob_buf b;

static uint64_t blobmsg_get_u64_any(struct blob_attr *attr)
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

static void ubus_ev_cb(EV_P_ ev_io *w, int revents)
{
	struct ubus_api_state *api = (struct ubus_api_state *)w->data;

	(void)loop;
	(void)revents;
	ubus_handle_event(api->ctx);
}

static int status_handler(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	struct ubus_api_state *api = container_of(obj, struct ubus_api_state, obj);
	struct airportal_daemon *daemon = api->daemon;
	uint64_t uptime = (airportal_monotonic_ms() - daemon->started_at_ms) / 1000u;

	(void)method;
	(void)msg;
	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "enabled", daemon->config.global.enabled);
	blobmsg_add_string(&b, "version", AIRPORTAL_VERSION);
	blobmsg_add_u32(&b, "uptime", (uint32_t)uptime);
	blobmsg_add_u32(&b, "clients", (uint32_t)daemon->clients.count);
	blobmsg_add_u32(&b, "authenticated_clients",
			(uint32_t)airportal_client_count_state(&daemon->clients,
							       AIRPORTAL_CLIENT_AUTHENTICATED));
	blobmsg_add_u32(&b, "captive_clients",
			(uint32_t)airportal_client_count_state(&daemon->clients,
							       AIRPORTAL_CLIENT_CAPTIVE));
	blobmsg_add_u32(&b, "active_sessions", (uint32_t)daemon->sessions.count);
	blobmsg_add_u8(&b, "radius_available", daemon->radius_available);
	blobmsg_add_u8(&b, "cloud_connected", false);
	blobmsg_add_u8(&b, "nft_ready", daemon->nft.ready);
	blobmsg_add_u8(&b, "tc_ready", daemon->tc.ready);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static void add_client_blob(struct airportal_client *client)
{
	void *c;
	char mac[18];
	char ip[INET_ADDRSTRLEN];

	airportal_format_mac(client->key.mac, mac, sizeof(mac));
	c = blobmsg_open_table(&b, NULL);
	blobmsg_add_string(&b, "mac", mac);
	blobmsg_add_string(&b, "ifname", client->ifname);
	blobmsg_add_u32(&b, "portal_id", client->key.portal_id);
	blobmsg_add_string(&b, "state", airportal_client_state_name(client->state));
	if (client->has_ipv4 && inet_ntop(AF_INET, &client->ipv4, ip, sizeof(ip)))
		blobmsg_add_string(&b, "ipv4", ip);
	blobmsg_add_string(&b, "username", client->username);
	blobmsg_add_string(&b, "session_id", client->session_id);
	blobmsg_add_u64(&b, "input_octets", client->input_octets);
	blobmsg_add_u64(&b, "output_octets", client->output_octets);
	blobmsg_close_table(&b, c);
}

static int clients_handler(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	struct ubus_api_state *api = container_of(obj, struct ubus_api_state, obj);
	size_t i;
	void *arr;

	(void)method;
	(void)msg;
	blob_buf_init(&b, 0);
	arr = blobmsg_open_array(&b, "clients");
	for (i = 0; i < AIRPORTAL_MAX_CLIENTS; i++) {
		if (api->daemon->clients.used[i])
			add_client_blob(&api->daemon->clients.clients[i]);
	}
	blobmsg_close_array(&b, arr);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static int sessions_handler(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg)
{
	struct ubus_api_state *api = container_of(obj, struct ubus_api_state, obj);
	size_t i;
	void *arr;

	(void)method;
	(void)msg;
	blob_buf_init(&b, 0);
	arr = blobmsg_open_array(&b, "sessions");
	for (i = 0; i < AIRPORTAL_MAX_SESSIONS; i++) {
		struct airportal_session *s = &api->daemon->sessions.sessions[i];
		void *entry;

		if (!api->daemon->sessions.used[i])
			continue;
		entry = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "session_id", s->session_id);
		blobmsg_add_u32(&b, "portal_id", s->client->key.portal_id);
		blobmsg_add_string(&b, "ifname", s->client->ifname);
		blobmsg_add_u64(&b, "expires_at_ms", s->expires_at_ms);
		blobmsg_add_u64(&b, "idle_expires_at_ms",
				s->idle_expires_at_ms);
		blobmsg_add_u64(&b, "last_activity_ms",
				s->last_activity_ms);
		blobmsg_add_u64(&b, "idle_activity_threshold_bytes",
				s->policy.idle_activity_threshold_bytes);
		blobmsg_add_u64(&b, "input_octets", s->input_octets);
		blobmsg_add_u64(&b, "output_octets", s->output_octets);
		blobmsg_add_u64(&b, "max_input_octets",
				s->policy.max_input_octets);
		blobmsg_add_u64(&b, "max_output_octets",
				s->policy.max_output_octets);
		blobmsg_add_u64(&b, "max_total_octets",
				s->policy.max_total_octets);
		blobmsg_add_u64(&b, "max_upload_bps",
				s->policy.max_upload_bps);
		blobmsg_add_u64(&b, "max_download_bps",
				s->policy.max_download_bps);
		blobmsg_add_u64(&b, "remaining_input_octets",
				airportal_session_remaining_input_octets(s));
		blobmsg_add_u64(&b, "remaining_output_octets",
				airportal_session_remaining_output_octets(s));
		blobmsg_add_u64(&b, "remaining_total_octets",
				airportal_session_remaining_total_octets(s));
		blobmsg_close_table(&b, entry);
	}
	blobmsg_close_array(&b, arr);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static int authorize_handler(struct ubus_context *ctx, struct ubus_object *obj,
			     struct ubus_request_data *req, const char *method,
			     struct blob_attr *msg)
{
	struct ubus_api_state *api = container_of(obj, struct ubus_api_state, obj);
	struct blob_attr *tb[__AUTH_MAX];
	struct airportal_session_policy policy;
	uint8_t mac[6];
	int rc;

	(void)method;
	blobmsg_parse(auth_policy, __AUTH_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[AUTH_MAC] || !tb[AUTH_IFNAME] || !tb[AUTH_PORTAL_ID] ||
	    !airportal_parse_mac(blobmsg_get_string(tb[AUTH_MAC]), mac))
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(&policy, 0, sizeof(policy));
	if (tb[AUTH_SESSION_TIMEOUT])
		policy.session_timeout_sec =
			blobmsg_get_u32(tb[AUTH_SESSION_TIMEOUT]);
	if (tb[AUTH_IDLE_TIMEOUT])
		policy.idle_timeout_sec =
			blobmsg_get_u32(tb[AUTH_IDLE_TIMEOUT]);
	if (tb[AUTH_IDLE_ACTIVITY_THRESHOLD_BYTES])
		policy.idle_activity_threshold_bytes =
			blobmsg_get_u64_any(tb[AUTH_IDLE_ACTIVITY_THRESHOLD_BYTES]);
	if (tb[AUTH_UPLOAD_BPS])
		policy.max_upload_bps = blobmsg_get_u64_any(tb[AUTH_UPLOAD_BPS]);
	if (tb[AUTH_DOWNLOAD_BPS])
		policy.max_download_bps =
			blobmsg_get_u64_any(tb[AUTH_DOWNLOAD_BPS]);
	if (tb[AUTH_MAX_INPUT_OCTETS])
		policy.max_input_octets =
			blobmsg_get_u64_any(tb[AUTH_MAX_INPUT_OCTETS]);
	if (tb[AUTH_MAX_OUTPUT_OCTETS])
		policy.max_output_octets =
			blobmsg_get_u64_any(tb[AUTH_MAX_OUTPUT_OCTETS]);
	if (tb[AUTH_MAX_TOTAL_OCTETS])
		policy.max_total_octets =
			blobmsg_get_u64_any(tb[AUTH_MAX_TOTAL_OCTETS]);

	rc = airportal_authorize_client(api->daemon, mac,
				       blobmsg_get_string(tb[AUTH_IFNAME]),
				       blobmsg_get_u32(tb[AUTH_PORTAL_ID]),
				       tb[AUTH_USERNAME] ?
				       blobmsg_get_string(tb[AUTH_USERNAME]) : "manual",
				       &policy);
	if (rc != 0)
		return UBUS_STATUS_NOT_FOUND;
	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "success", true);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static int disconnect_handler(struct ubus_context *ctx, struct ubus_object *obj,
			      struct ubus_request_data *req, const char *method,
			      struct blob_attr *msg)
{
	struct ubus_api_state *api = container_of(obj, struct ubus_api_state, obj);
	struct blob_attr *tb[__DISC_MAX];
	uint8_t mac[6];
	int rc;

	(void)method;
	blobmsg_parse(disc_policy, __DISC_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[DISC_MAC] || !tb[DISC_IFNAME] || !tb[DISC_PORTAL_ID] ||
	    !airportal_parse_mac(blobmsg_get_string(tb[DISC_MAC]), mac))
		return UBUS_STATUS_INVALID_ARGUMENT;
	rc = airportal_disconnect_client(api->daemon, mac,
					blobmsg_get_string(tb[DISC_IFNAME]),
					blobmsg_get_u32(tb[DISC_PORTAL_ID]),
					tb[DISC_REASON] ?
					blobmsg_get_string(tb[DISC_REASON]) :
					"admin_disconnect");
	if (rc != 0)
		return UBUS_STATUS_NOT_FOUND;
	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "success", true);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static int reload_handler(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	struct ubus_api_state *api = container_of(obj, struct ubus_api_state, obj);
	int rc;

	(void)method;
	(void)msg;
	rc = airportal_reload(api->daemon);
	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "success", rc == 0);
	ubus_send_reply(ctx, req, b.head);
	return rc == 0 ? 0 : UBUS_STATUS_UNKNOWN_ERROR;
}

static int portals_handler(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	struct ubus_api_state *api = container_of(obj, struct ubus_api_state, obj);
	size_t i;
	void *arr;

	(void)method;
	(void)msg;
	blob_buf_init(&b, 0);
	arr = blobmsg_open_array(&b, "portals");
	for (i = 0; i < api->daemon->config.portal_count; i++) {
		void *p = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "name", api->daemon->config.portals[i].name);
		blobmsg_add_u32(&b, "portal_id", api->daemon->config.portals[i].portal_id);
		blobmsg_add_u8(&b, "enabled", api->daemon->config.portals[i].enabled);
		blobmsg_add_string(&b, "network", api->daemon->config.portals[i].network);
		blobmsg_close_table(&b, p);
	}
	blobmsg_close_array(&b, arr);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static int statistics_handler(struct ubus_context *ctx, struct ubus_object *obj,
			      struct ubus_request_data *req, const char *method,
			      struct blob_attr *msg)
{
	struct ubus_api_state *api = container_of(obj, struct ubus_api_state, obj);
	struct airportal_metrics *m = &api->daemon->metrics;

	(void)method;
	(void)msg;
	blob_buf_init(&b, 0);
	blobmsg_add_u64(&b, "clients_seen", m->clients_seen);
	blobmsg_add_u64(&b, "sessions_started", m->sessions_started);
	blobmsg_add_u64(&b, "sessions_stopped", m->sessions_stopped);
	blobmsg_add_u64(&b, "auth_accepts", m->auth_accepts);
	blobmsg_add_u64(&b, "auth_rejects", m->auth_rejects);
	blobmsg_add_u64(&b, "radius_timeouts", m->radius_timeouts);
	blobmsg_add_u64(&b, "accounting_failures", m->accounting_failures);
	blobmsg_add_u64(&b, "coa_requests", m->coa_requests);
	blobmsg_add_u64(&b, "disconnect_requests", m->disconnect_requests);
	blobmsg_add_u64(&b, "quota_disconnects", m->quota_disconnects);
	blobmsg_add_u64(&b, "idle_disconnects", m->idle_disconnects);
	blobmsg_add_u64(&b, "session_timeout_disconnects", m->session_timeout_disconnects);
	blobmsg_add_u64(&b, "policy_install_failures", m->policy_install_failures);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static const struct ubus_method airportal_methods[] = {
	UBUS_METHOD_NOARG("status", status_handler),
	UBUS_METHOD_NOARG("clients", clients_handler),
	UBUS_METHOD_NOARG("sessions", sessions_handler),
	UBUS_METHOD("authorize", authorize_handler, auth_policy),
	UBUS_METHOD("disconnect", disconnect_handler, disc_policy),
	UBUS_METHOD_NOARG("reload", reload_handler),
	UBUS_METHOD_NOARG("portals", portals_handler),
	UBUS_METHOD_NOARG("statistics", statistics_handler),
};

static struct ubus_object_type airportal_object_type =
	UBUS_OBJECT_TYPE("airportal", airportal_methods);

int ubus_api_init(struct airportal_daemon *daemon)
{
	struct ubus_api_state *api = calloc(1, sizeof(*api));

	if (!api)
		return -1;
	api->daemon = daemon;
	api->ctx = ubus_connect(NULL);
	if (!api->ctx) {
		free(api);
		return -1;
	}
	api->obj.name = "airportal";
	api->obj.type = &airportal_object_type;
	api->obj.methods = airportal_methods;
	api->obj.n_methods = ARRAY_SIZE(airportal_methods);
	if (ubus_add_object(api->ctx, &api->obj) != 0) {
		ubus_free(api->ctx);
		free(api);
		return -1;
	}
	ev_io_init(&api->io, ubus_ev_cb, api->ctx->sock.fd, EV_READ);
	api->io.data = api;
	ev_io_start(daemon->loop, &api->io);
	daemon->ubus = api->ctx;
	daemon->ubus_api = api;
	return 0;
}

void ubus_api_shutdown(struct airportal_daemon *daemon)
{
	struct ubus_api_state *api = daemon->ubus_api;

	if (!api)
		return;
	ev_io_stop(daemon->loop, &api->io);
	ubus_remove_object(api->ctx, &api->obj);
	ubus_free(api->ctx);
	free(api);
	daemon->ubus_api = NULL;
	daemon->ubus = NULL;
}
#else
int ubus_api_init(struct airportal_daemon *daemon)
{
	(void)daemon;
	ap_log_warn("ubus_api_disabled build_without_openwrt");
	return -1;
}

void ubus_api_shutdown(struct airportal_daemon *daemon)
{
	(void)daemon;
}
#endif
