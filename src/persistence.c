#include "persistence.h"

#include "airportal.h"
#include "enforcement_manager.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct persisted_session {
	bool used;
	uint8_t mac[6];
	char ifname[IFNAMSIZ];
	uint32_t portal_id;
	char username[128];
	char session_id[96];
	struct airportal_session_policy policy;
	uint64_t expires_at_wall_sec;
	uint64_t idle_expires_at_wall_sec;
	uint64_t input_octets_base;
	uint64_t output_octets_base;
	uint64_t input_octets;
	uint64_t output_octets;
	bool accounting_started;
	bool policy_installed;
};

struct persistence_state {
	struct persisted_session entries[AIRPORTAL_MAX_SESSIONS];
	size_t count;
};

static void sanitize_field(char *dst, size_t dst_len, const char *src)
{
	size_t i;

	if (!dst || dst_len == 0)
		return;
	dst[0] = '\0';
	if (!src)
		return;
	for (i = 0; i + 1 < dst_len && src[i]; i++) {
		if (src[i] == '\t' || src[i] == '\n' || src[i] == '\r')
			dst[i] = '_';
		else
			dst[i] = src[i];
	}
	dst[i] = '\0';
}

static uint64_t deadline_to_wall(uint64_t deadline_ms)
{
	uint64_t now_ms;
	uint64_t now_wall;

	if (!deadline_ms)
		return 0;
	now_ms = airportal_monotonic_ms();
	now_wall = airportal_wall_time_sec();
	if (deadline_ms <= now_ms)
		return now_wall;
	return now_wall + (deadline_ms - now_ms + 999u) / 1000u;
}

static uint64_t remaining_ms_from_wall(uint64_t deadline_wall_sec,
				       uint64_t now_wall_sec)
{
	if (!deadline_wall_sec)
		return 0;
	if (deadline_wall_sec <= now_wall_sec)
		return UINT64_MAX;
	return (deadline_wall_sec - now_wall_sec) * 1000u;
}

static int ensure_parent_dir(const char *path)
{
	char dir[256];
	char *slash;

	if (!path || !path[0])
		return -1;
	snprintf(dir, sizeof(dir), "%s", path);
	slash = strrchr(dir, '/');
	if (!slash)
		return 0;
	if (slash == dir)
		return 0;
	*slash = '\0';
	if (mkdir(dir, 0700) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

int persistence_init(struct airportal_daemon *daemon)
{
	struct persistence_state *state;
	FILE *fp;
	char line[1024];
	const char *path;

	if (!daemon)
		return -1;
	state = calloc(1, sizeof(*state));
	if (!state)
		return -1;
	daemon->persistence = state;
	if (!daemon->config.global.session_restore)
		return 0;

	path = daemon->config.global.persistent_db;
	fp = fopen(path, "r");
	if (!fp) {
		ap_log_info("persistence_restore_empty path=%s", path);
		return 0;
	}

	while (fgets(line, sizeof(line), fp) &&
	       state->count < AIRPORTAL_MAX_SESSIONS) {
		struct persisted_session *entry = &state->entries[state->count];
		char mac_text[18];
		unsigned int portal_id;
		unsigned int allow_ipv4;
		unsigned int allow_ipv6;
		unsigned int has_assigned_vlan;
		unsigned int assigned_vlan;
		unsigned int accounting_started;
		unsigned int policy_installed;
		unsigned long long expires_at_wall_sec;
		unsigned long long idle_expires_at_wall_sec;
		unsigned long long input_octets_base;
		unsigned long long output_octets_base;
		unsigned long long input_octets;
		unsigned long long output_octets;
		unsigned long long max_input_octets;
		unsigned long long max_output_octets;
		unsigned long long max_total_octets;
		unsigned long long max_upload_bps;
		unsigned long long max_download_bps;
		unsigned long long idle_activity_threshold_bytes = 0;
		int parsed;
		int required_fields;

		memset(entry, 0, sizeof(*entry));
		if (strncmp(line, "v2\t", 3) == 0) {
			required_fields = 28;
			parsed = sscanf(line,
					"v2\t%17s\t%15s\t%u\t%127s\t%95s\t"
					"%u\t%u\t%u\t%llu\t%llu\t%llu\t%llu\t"
					"%llu\t%llu\t%llu\t%llu\t%llu\t%u\t%u\t%u\t"
					"%u\t%llu\t%llu\t%llu\t%u\t%u\t%127s\t%255s",
					mac_text, entry->ifname, &portal_id,
					entry->username, entry->session_id,
					&entry->policy.session_timeout_sec,
					&entry->policy.idle_timeout_sec,
					&entry->policy.accounting_interval_sec,
					&expires_at_wall_sec, &idle_expires_at_wall_sec,
					&input_octets_base, &output_octets_base,
					&input_octets, &output_octets,
					&max_input_octets, &max_output_octets,
					&max_total_octets,
					&allow_ipv4, &allow_ipv6, &has_assigned_vlan,
					&assigned_vlan, &max_upload_bps,
					&max_download_bps,
					&idle_activity_threshold_bytes,
					&accounting_started, &policy_installed,
					entry->policy.filter_id,
					entry->policy.radius_class);
		} else {
			required_fields = 27;
			parsed = sscanf(line,
					"v1\t%17s\t%15s\t%u\t%127s\t%95s\t"
					"%u\t%u\t%u\t%llu\t%llu\t%llu\t%llu\t"
					"%llu\t%llu\t%llu\t%llu\t%llu\t%u\t%u\t%u\t"
					"%u\t%llu\t%llu\t%u\t%u\t%127s\t%255s",
					mac_text, entry->ifname, &portal_id,
					entry->username, entry->session_id,
					&entry->policy.session_timeout_sec,
					&entry->policy.idle_timeout_sec,
					&entry->policy.accounting_interval_sec,
					&expires_at_wall_sec, &idle_expires_at_wall_sec,
					&input_octets_base, &output_octets_base,
					&input_octets, &output_octets,
					&max_input_octets, &max_output_octets,
					&max_total_octets,
					&allow_ipv4, &allow_ipv6, &has_assigned_vlan,
					&assigned_vlan, &max_upload_bps,
					&max_download_bps,
					&accounting_started, &policy_installed,
					entry->policy.filter_id,
					entry->policy.radius_class);
		}
		if (parsed < required_fields ||
		    !airportal_parse_mac(mac_text, entry->mac))
			continue;
		entry->portal_id = portal_id;
		entry->expires_at_wall_sec = expires_at_wall_sec;
		entry->idle_expires_at_wall_sec = idle_expires_at_wall_sec;
		entry->input_octets_base = input_octets_base;
		entry->output_octets_base = output_octets_base;
		entry->input_octets = input_octets;
		entry->output_octets = output_octets;
		entry->policy.max_input_octets = max_input_octets;
		entry->policy.max_output_octets = max_output_octets;
		entry->policy.max_total_octets = max_total_octets;
		entry->policy.idle_activity_threshold_bytes =
			idle_activity_threshold_bytes;
		entry->policy.allow_ipv4 = allow_ipv4 != 0;
		entry->policy.allow_ipv6 = allow_ipv6 != 0;
		entry->policy.has_assigned_vlan = has_assigned_vlan != 0;
		entry->policy.assigned_vlan = (uint16_t)assigned_vlan;
		entry->policy.max_upload_bps = max_upload_bps;
		entry->policy.max_download_bps = max_download_bps;
		entry->accounting_started = accounting_started != 0;
		entry->policy_installed = policy_installed != 0;
		entry->used = true;
		state->count++;
	}
	fclose(fp);
	ap_log_info("persistence_restore_loaded path=%s sessions=%zu",
		    path, state->count);
	return 0;
}

int persistence_checkpoint(struct airportal_daemon *daemon)
{
	FILE *fp;
	char tmp_path[256];
	const char *path;
	size_t i;
	size_t saved = 0;

	if (!daemon || !daemon->config.global.session_restore)
		return 0;
	path = daemon->config.global.persistent_db;
	if (ensure_parent_dir(path) != 0) {
		ap_log_warn("persistence_checkpoint_failed reason=mkdir path=%s",
			    path);
		return -1;
	}
	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
	fp = fopen(tmp_path, "w");
	if (!fp) {
		ap_log_warn("persistence_checkpoint_failed reason=open path=%s",
			    tmp_path);
		return -1;
	}

	for (i = 0; i < AIRPORTAL_MAX_SESSIONS; i++) {
		struct airportal_session *session = &daemon->sessions.sessions[i];
		struct airportal_client *client;
		char mac[18];
		char username[128];
		char filter_id[128];
		char radius_class[256];

		if (!daemon->sessions.used[i] || !session->client)
			continue;
		client = session->client;
		airportal_format_mac(client->key.mac, mac, sizeof(mac));
		sanitize_field(username, sizeof(username), client->username);
		sanitize_field(filter_id, sizeof(filter_id),
			       session->policy.filter_id[0] ?
			       session->policy.filter_id : "-");
		sanitize_field(radius_class, sizeof(radius_class),
			       session->policy.radius_class[0] ?
			       session->policy.radius_class : "-");
		fprintf(fp,
			"v2\t%s\t%s\t%u\t%s\t%s\t%u\t%u\t%u\t"
			"%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t"
			"%llu\t%llu\t%u\t%u\t%u\t%u\t%llu\t%llu\t%llu\t%u\t%u\t%s\t%s\n",
			mac, client->ifname, client->key.portal_id, username,
			session->session_id, session->policy.session_timeout_sec,
			session->policy.idle_timeout_sec,
			session->policy.accounting_interval_sec,
			(unsigned long long)deadline_to_wall(session->expires_at_ms),
			(unsigned long long)deadline_to_wall(session->idle_expires_at_ms),
			(unsigned long long)session->input_octets_base,
			(unsigned long long)session->output_octets_base,
			(unsigned long long)session->input_octets,
			(unsigned long long)session->output_octets,
			(unsigned long long)session->policy.max_input_octets,
			(unsigned long long)session->policy.max_output_octets,
			(unsigned long long)session->policy.max_total_octets,
			session->policy.allow_ipv4 ? 1u : 0u,
			session->policy.allow_ipv6 ? 1u : 0u,
			session->policy.has_assigned_vlan ? 1u : 0u,
			session->policy.assigned_vlan,
			(unsigned long long)session->policy.max_upload_bps,
			(unsigned long long)session->policy.max_download_bps,
			(unsigned long long)session->policy.idle_activity_threshold_bytes,
			session->accounting_started ? 1u : 0u,
			session->policy_installed ? 1u : 0u,
			filter_id, radius_class);
		saved++;
	}
	if (fclose(fp) != 0)
		return -1;
	if (rename(tmp_path, path) != 0) {
		unlink(tmp_path);
		ap_log_warn("persistence_checkpoint_failed reason=rename path=%s",
			    path);
		return -1;
	}
	ap_log_info("persistence_checkpoint_success path=%s sessions=%zu",
		    path, saved);
	return 0;
}

int persistence_try_restore_client(struct airportal_daemon *daemon,
				   struct airportal_client *client)
{
	struct persistence_state *state;
	uint64_t now_wall;
	size_t i;

	if (!daemon || !client || !daemon->persistence ||
	    !daemon->config.global.session_restore)
		return 0;
	state = (struct persistence_state *)daemon->persistence;
	now_wall = airportal_wall_time_sec();

	for (i = 0; i < AIRPORTAL_MAX_SESSIONS; i++) {
		struct persisted_session *entry = &state->entries[i];
		struct airportal_session *session;
		uint64_t remaining_session_ms;
		uint64_t remaining_idle_ms;

		if (!entry->used ||
		    memcmp(entry->mac, client->key.mac, sizeof(entry->mac)) != 0 ||
		    strcmp(entry->ifname, client->ifname) != 0 ||
		    entry->portal_id != client->key.portal_id)
			continue;

		remaining_session_ms = remaining_ms_from_wall(
			entry->expires_at_wall_sec, now_wall);
		remaining_idle_ms = remaining_ms_from_wall(
			entry->idle_expires_at_wall_sec, now_wall);
		if (remaining_session_ms == UINT64_MAX ||
		    remaining_idle_ms == UINT64_MAX) {
			entry->used = false;
			ap_log_info("persistence_restore_skip reason=expired ifname=%s portal_id=%u",
				    entry->ifname, entry->portal_id);
			return 0;
		}
		if (enforcement_authorize(daemon, client, &entry->policy) != 0) {
			daemon->metrics.policy_install_failures++;
			ap_log_warn("persistence_restore_failed reason=enforcement ifname=%s portal_id=%u",
				    entry->ifname, entry->portal_id);
			return -1;
		}
		session = airportal_session_restore(&daemon->sessions, client,
						    entry->session_id,
						    entry->username,
						    &entry->policy,
						    remaining_session_ms,
						    remaining_idle_ms,
						    entry->input_octets_base,
						    entry->output_octets_base,
						    entry->input_octets,
						    entry->output_octets);
		if (!session)
			return -1;
		session->accounting_started = entry->accounting_started;
		session->policy_installed = entry->policy_installed;
		session->last_accounting_update_ms = airportal_monotonic_ms();
		entry->used = false;
		ap_log_info("persistence_restore_success session_id=%s username=%s ifname=%s portal_id=%u",
			    session->session_id, client->username, client->ifname,
			    client->key.portal_id);
		return 1;
	}
	return 0;
}

void persistence_shutdown(struct airportal_daemon *daemon)
{
	free(daemon ? daemon->persistence : NULL);
	if (daemon)
		daemon->persistence = NULL;
}
