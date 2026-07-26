#ifndef AIRPORTAL_H
#define AIRPORTAL_H

#include <ev.h>

#include "airportal_types.h"
#include "client_manager.h"
#include "config_manager.h"
#include "nft_manager.h"
#include "session_manager.h"
#include "tc_manager.h"
#include "token_manager.h"

struct ubus_context;

struct airportal_daemon {
	struct ev_loop *loop;
	ev_signal sigint_watcher;
	ev_signal sigterm_watcher;
	ev_signal sighup_watcher;
	ev_timer timeout_watcher;

	uint64_t started_at_ms;
	bool shutting_down;

	struct airportal_config config;
	struct airportal_client_manager clients;
	struct airportal_session_manager sessions;
	struct nft_manager nft;
	struct tc_manager tc;
	struct token_manager tokens;
	struct airportal_metrics metrics;

	struct ubus_context *ubus;
	void *ubus_api;
	void *hostapd_monitor;
	void *portal_http;
	void *coa_server;
};

int airportal_reload(struct airportal_daemon *daemon);
int airportal_authorize_client(struct airportal_daemon *daemon,
			       const uint8_t mac[6],
			       const char *ifname,
			       uint32_t portal_id,
			       const char *username,
			       const struct airportal_session_policy *requested_policy);
int airportal_disconnect_client(struct airportal_daemon *daemon,
				const uint8_t mac[6],
				const char *ifname,
				uint32_t portal_id,
				const char *reason);

#endif
