#include "airportal.h"

#include "cloud_client.h"
#include "coa_server.h"
#include "enforcement_manager.h"
#include "hostapd_monitor.h"
#include "log.h"
#include "metrics.h"
#include "netlink_monitor.h"
#include "persistence.h"
#include "portal_http.h"
#include "radius_accounting.h"
#include "radius_client.h"
#include "ubus_api.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void stop_loop(struct airportal_daemon *daemon)
{
	if (daemon->shutting_down)
		return;

	daemon->shutting_down = true;
	ap_log_info("daemon_shutdown_start");
	ev_break(daemon->loop, EVBREAK_ALL);
}

static void signal_cb(EV_P_ ev_signal *w, int revents)
{
	struct airportal_daemon *daemon = (struct airportal_daemon *)w->data;

	(void)loop;
	(void)revents;
	if (w->signum == SIGHUP) {
		airportal_reload(daemon);
		return;
	}
	stop_loop(daemon);
}

static int return_client_to_captive(struct airportal_daemon *daemon,
				    struct airportal_client *client)
{
	enforcement_remove(daemon, client);
	client->state = AIRPORTAL_CLIENT_CAPTIVE;
	client->username[0] = '\0';
	ap_log_info("client_return_to_captive mac=%02X:%02X:%02X:%02X:%02X:%02X ifname=%s portal_id=%u",
		    client->key.mac[0], client->key.mac[1], client->key.mac[2],
		    client->key.mac[3], client->key.mac[4], client->key.mac[5],
		    client->ifname, client->key.portal_id);
	if (enforcement_install_captive(daemon, client) != 0) {
		daemon->metrics.policy_install_failures++;
		return -1;
	}
	return 0;
}

static void expire_due_sessions(struct airportal_daemon *daemon, uint64_t now_ms)
{
	size_t i;

	for (i = 0; i < AIRPORTAL_MAX_SESSIONS; i++) {
		struct airportal_session *session = &daemon->sessions.sessions[i];
		struct airportal_client *client;
		enum airportal_client_state final_state;
		const char *reason;

		if (!daemon->sessions.used[i])
			continue;
		if (airportal_session_quota_exceeded(session)) {
			final_state = AIRPORTAL_CLIENT_QUOTA_EXCEEDED;
			reason = "quota_exceeded";
			daemon->metrics.quota_disconnects++;
		} else if (session->expires_at_ms && now_ms >= session->expires_at_ms) {
			final_state = AIRPORTAL_CLIENT_SESSION_EXPIRED;
			reason = "session_timeout";
			daemon->metrics.session_timeout_disconnects++;
		} else if (session->idle_expires_at_ms &&
			   now_ms >= session->idle_expires_at_ms) {
			final_state = AIRPORTAL_CLIENT_IDLE_EXPIRED;
			reason = "idle_timeout";
			daemon->metrics.idle_disconnects++;
		} else {
			continue;
		}

		client = session->client;
		if (session->accounting_started &&
		    radius_accounting_stop(daemon, session, reason) != 0)
			daemon->metrics.accounting_failures++;
		airportal_session_stop(&daemon->sessions, session, final_state, reason);
		daemon->metrics.sessions_stopped++;
		if (client)
			return_client_to_captive(daemon, client);
	}
}

static void send_due_accounting_updates(struct airportal_daemon *daemon,
					uint64_t now_ms)
{
	size_t i;

	for (i = 0; i < AIRPORTAL_MAX_SESSIONS; i++) {
		struct airportal_session *session = &daemon->sessions.sessions[i];
		uint32_t interval = 0;

		if (!daemon->sessions.used[i] || !session->accounting_started)
			continue;
		interval = session->policy.accounting_interval_sec;
		if (!interval)
			continue;
		if (session->last_accounting_update_ms &&
		    now_ms < session->last_accounting_update_ms + (uint64_t)interval * 1000u)
			continue;
		if (!session->last_accounting_update_ms &&
		    now_ms < session->started_at_ms + (uint64_t)interval * 1000u)
			continue;

		if (radius_accounting_interim_update(daemon, session) != 0) {
			daemon->metrics.accounting_failures++;
			continue;
		}
		session->last_accounting_update_ms = now_ms;
		session->last_accounting_input_octets = session->input_octets;
		session->last_accounting_output_octets = session->output_octets;
	}
}

static void timeout_cb(EV_P_ ev_timer *w, int revents)
{
	struct airportal_daemon *daemon = (struct airportal_daemon *)w->data;
	uint64_t now_ms = airportal_monotonic_ms();

	(void)loop;
	(void)revents;
	expire_due_sessions(daemon, now_ms);
	send_due_accounting_updates(daemon, now_ms);
}

int airportal_reload(struct airportal_daemon *daemon)
{
	struct airportal_config new_config;

	if (airportal_config_load(&new_config, "airportal") != 0) {
		ap_log_error("config_reload_failed reason=%s",
			     new_config.validation_error[0] ?
			     new_config.validation_error : "load_error");
		return -1;
	}

	daemon->config = new_config;
	airportal_log_init(daemon->config.global.log_level);
	ap_log_info("config_reload_success portals=%zu bindings=%zu",
		    daemon->config.portal_count, daemon->config.binding_count);
	return 0;
}

int airportal_authorize_client(struct airportal_daemon *daemon,
			       const uint8_t mac[6],
			       const char *ifname,
			       uint32_t portal_id,
			       const char *username,
			       const struct airportal_session_policy *requested_policy)
{
	struct airportal_client *client;
	const struct airportal_portal_config *portal;
	struct airportal_session_policy policy;
	struct airportal_session *session;

	portal = airportal_config_find_portal_by_id(&daemon->config, portal_id);
	if (!portal || !portal->enabled)
		return -1;

	client = airportal_client_find_by_mac_if_portal(&daemon->clients, mac,
						       ifname, portal_id);
	if (!client || client->state == AIRPORTAL_CLIENT_DISCONNECTED)
		return -1;

	if (requested_policy)
		policy = *requested_policy;
	else
		memset(&policy, 0, sizeof(policy));
	if (!policy.session_timeout_sec)
		policy.session_timeout_sec = portal->default_session_timeout;
	if (!policy.idle_timeout_sec)
		policy.idle_timeout_sec = portal->default_idle_timeout;
	if (!policy.idle_activity_threshold_bytes)
		policy.idle_activity_threshold_bytes =
			portal->default_idle_activity_threshold_bytes;
	if (!policy.accounting_interval_sec)
		policy.accounting_interval_sec =
			daemon->config.global.default_accounting_interval;
	policy.allow_ipv4 = true;

	if (enforcement_authorize(daemon, client, &policy) != 0) {
		daemon->metrics.policy_install_failures++;
		return -1;
	}

	session = airportal_session_start(&daemon->sessions, client,
					  daemon->config.global.device_id,
					  username, &policy);
	if (!session)
		return -1;
	session->policy_installed = true;
	if (strcmp(portal->auth_mode, "radius") == 0) {
		if (radius_accounting_start(daemon, session) != 0)
			daemon->metrics.accounting_failures++;
		else {
			session->accounting_started = true;
			session->last_accounting_update_ms = airportal_monotonic_ms();
		}
	}
	daemon->metrics.auth_accepts++;
	daemon->metrics.sessions_started++;
	return 0;
}

int airportal_disconnect_client(struct airportal_daemon *daemon,
				const uint8_t mac[6],
				const char *ifname,
				uint32_t portal_id,
				const char *reason)
{
	struct airportal_client *client;
	struct airportal_session *session;

	client = airportal_client_find_by_mac_if_portal(&daemon->clients, mac,
						       ifname, portal_id);
	if (!client)
		return -1;

	session = airportal_session_find_by_client(&daemon->sessions, client);
	if (session) {
		if (session->accounting_started &&
		    radius_accounting_stop(daemon, session,
					   reason ? reason : "admin_disconnect") != 0)
			daemon->metrics.accounting_failures++;
		airportal_session_stop(&daemon->sessions, session,
				       AIRPORTAL_CLIENT_CAPTIVE,
				       reason ? reason : "admin_disconnect");
		daemon->metrics.sessions_stopped++;
	}
	if (return_client_to_captive(daemon, client) != 0)
		return -1;
	daemon->metrics.disconnect_requests++;
	return 0;
}

static int daemon_init(struct airportal_daemon *daemon)
{
	memset(daemon, 0, sizeof(*daemon));
	daemon->loop = EV_DEFAULT;
	daemon->started_at_ms = airportal_monotonic_ms();

	airportal_client_manager_init(&daemon->clients);
	airportal_session_manager_init(&daemon->sessions);
	metrics_init(&daemon->metrics);

	if (airportal_config_load(&daemon->config, "airportal") != 0) {
		ap_log_error("config_load_failed reason=%s",
			     daemon->config.validation_error[0] ?
			     daemon->config.validation_error : "load_error");
		return -1;
	}

	airportal_log_init(daemon->config.global.log_level);
	if (!daemon->config.global.enabled) {
		ap_log_warn("daemon_disabled_by_config");
		return -1;
	}

	if (token_manager_init(&daemon->tokens,
			       daemon->config.global.token_key_file) != 0) {
		ap_log_warn("token_key_unavailable using_runtime_key_only");
		if (token_manager_init(&daemon->tokens, NULL) != 0)
			return -1;
	}

	nft_manager_init(&daemon->nft, false);
	if (nft_manager_install_base_rules(&daemon->nft,
					   &daemon->config,
					   daemon->config.global.portal_http_port) != 0)
		return -1;
	if (tc_manager_init(&daemon->tc) != 0)
		return -1;

	persistence_init(daemon);
	cloud_client_init(daemon);
	radius_client_init(daemon);
	radius_accounting_init(daemon);
	coa_server_init(daemon);
	netlink_monitor_init(daemon);

	if (ubus_api_init(daemon) != 0)
		ap_log_warn("ubus_api_unavailable");
	if (hostapd_monitor_init(daemon) != 0)
		ap_log_warn("hostapd_monitor_unavailable");
	if (portal_http_init(daemon) != 0)
		ap_log_warn("portal_http_unavailable");

	ev_signal_init(&daemon->sigint_watcher, signal_cb, SIGINT);
	daemon->sigint_watcher.data = daemon;
	ev_signal_start(daemon->loop, &daemon->sigint_watcher);

	ev_signal_init(&daemon->sigterm_watcher, signal_cb, SIGTERM);
	daemon->sigterm_watcher.data = daemon;
	ev_signal_start(daemon->loop, &daemon->sigterm_watcher);

	ev_signal_init(&daemon->sighup_watcher, signal_cb, SIGHUP);
	daemon->sighup_watcher.data = daemon;
	ev_signal_start(daemon->loop, &daemon->sighup_watcher);

	ev_timer_init(&daemon->timeout_watcher, timeout_cb, 1.0, 1.0);
	daemon->timeout_watcher.data = daemon;
	ev_timer_start(daemon->loop, &daemon->timeout_watcher);
	return 0;
}

static void daemon_shutdown(struct airportal_daemon *daemon)
{
	ev_timer_stop(daemon->loop, &daemon->timeout_watcher);
	ev_signal_stop(daemon->loop, &daemon->sigint_watcher);
	ev_signal_stop(daemon->loop, &daemon->sigterm_watcher);
	ev_signal_stop(daemon->loop, &daemon->sighup_watcher);

	portal_http_shutdown(daemon);
	hostapd_monitor_shutdown(daemon);
	ubus_api_shutdown(daemon);
	netlink_monitor_shutdown(daemon);
	coa_server_shutdown(daemon);
	radius_accounting_shutdown(daemon);
	radius_client_shutdown(daemon);
	cloud_client_shutdown(daemon);
	persistence_checkpoint(daemon);
	persistence_shutdown(daemon);
	tc_manager_flush_managed_state(&daemon->tc);
	nft_manager_flush_managed_state(&daemon->nft);
}

int main(void)
{
	struct airportal_daemon daemon;

	if (daemon_init(&daemon) != 0)
		return EXIT_FAILURE;

	ap_log_info("daemon_started version=%s", AIRPORTAL_VERSION);
	ev_run(daemon.loop, 0);
	daemon_shutdown(&daemon);
	ap_log_info("daemon_stopped");
	return EXIT_SUCCESS;
}
