#include "session_manager.h"

#include "log.h"

#include <stdio.h>
#include <string.h>

void airportal_session_manager_init(struct airportal_session_manager *mgr)
{
	memset(mgr, 0, sizeof(*mgr));
	mgr->next_session_counter = 1;
}

struct airportal_session *
airportal_session_find_by_id(struct airportal_session_manager *mgr,
			     const char *session_id)
{
	size_t i;

	if (!session_id)
		return NULL;

	for (i = 0; i < AIRPORTAL_MAX_SESSIONS; i++) {
		if (mgr->used[i] &&
		    strcmp(mgr->sessions[i].session_id, session_id) == 0)
			return &mgr->sessions[i];
	}

	return NULL;
}

struct airportal_session *
airportal_session_find_by_client(struct airportal_session_manager *mgr,
				 const struct airportal_client *client)
{
	size_t i;

	for (i = 0; i < AIRPORTAL_MAX_SESSIONS; i++) {
		if (mgr->used[i] && mgr->sessions[i].client == client)
			return &mgr->sessions[i];
	}

	return NULL;
}

void airportal_session_update_octets(struct airportal_session *session,
				     uint64_t input_octets,
				     uint64_t output_octets,
				     uint64_t now_ms)
{
	bool active;
	uint64_t threshold;
	uint64_t input_delta;
	uint64_t output_delta;

	if (!session)
		return;
	threshold = session->policy.idle_activity_threshold_bytes;
	input_delta = input_octets >= session->last_activity_input_octets ?
		      input_octets - session->last_activity_input_octets : 0;
	output_delta = output_octets >= session->last_activity_output_octets ?
		       output_octets - session->last_activity_output_octets : 0;
	active = threshold ?
		 input_delta + output_delta >= threshold :
		 input_octets > session->input_octets ||
		 output_octets > session->output_octets;
	session->input_octets = input_octets;
	session->output_octets = output_octets;
	if (!active)
		return;
	session->last_activity_input_octets = input_octets;
	session->last_activity_output_octets = output_octets;
	session->last_activity_ms = now_ms;
	if (session->policy.idle_timeout_sec)
		session->idle_expires_at_ms =
			now_ms + (uint64_t)session->policy.idle_timeout_sec * 1000u;
}

static uint64_t remaining_octets(uint64_t used, uint64_t max)
{
	if (!max)
		return 0;
	if (used >= max)
		return 0;
	return max - used;
}

static bool total_octets_at_least(uint64_t input_octets,
				  uint64_t output_octets,
				  uint64_t limit)
{
	if (!limit)
		return false;
	if (input_octets >= limit || output_octets >= limit)
		return true;
	return input_octets >= limit - output_octets;
}

bool airportal_session_quota_exceeded(const struct airportal_session *session)
{
	if (!session)
		return false;
	if (session->policy.max_input_octets &&
	    session->input_octets >= session->policy.max_input_octets)
		return true;
	if (session->policy.max_output_octets &&
	    session->output_octets >= session->policy.max_output_octets)
		return true;
	return total_octets_at_least(session->input_octets,
				     session->output_octets,
				     session->policy.max_total_octets);
}

uint64_t airportal_session_remaining_input_octets(
	const struct airportal_session *session)
{
	if (!session)
		return 0;
	return remaining_octets(session->input_octets,
				session->policy.max_input_octets);
}

uint64_t airportal_session_remaining_output_octets(
	const struct airportal_session *session)
{
	if (!session)
		return 0;
	return remaining_octets(session->output_octets,
				session->policy.max_output_octets);
}

uint64_t airportal_session_remaining_total_octets(
	const struct airportal_session *session)
{
	uint64_t input_remaining;

	if (!session || !session->policy.max_total_octets)
		return 0;
	if (session->input_octets >= session->policy.max_total_octets ||
	    session->output_octets >= session->policy.max_total_octets)
		return 0;
	input_remaining = session->policy.max_total_octets -
			  session->input_octets;
	return session->output_octets >= input_remaining ?
	       0 : input_remaining - session->output_octets;
}

struct airportal_session *
airportal_session_start(struct airportal_session_manager *mgr,
			struct airportal_client *client,
			const char *device_id,
			const char *username,
			const struct airportal_session_policy *policy)
{
	struct airportal_session *existing;
	struct airportal_session *session;
	uint64_t now;
	size_t i;

	if (!client || !policy)
		return NULL;

	existing = airportal_session_find_by_client(mgr, client);
	if (existing)
		airportal_session_stop(mgr, existing, AIRPORTAL_CLIENT_CAPTIVE,
				       "replaced");

	for (i = 0; i < AIRPORTAL_MAX_SESSIONS; i++) {
		if (mgr->used[i])
			continue;

		now = airportal_monotonic_ms();
		mgr->used[i] = true;
		mgr->count++;
		session = &mgr->sessions[i];
		memset(session, 0, sizeof(*session));
		snprintf(session->session_id, sizeof(session->session_id),
			 "%s-%llu", device_id ? device_id : "ap",
			 (unsigned long long)mgr->next_session_counter++);
		session->client = client;
		session->policy = *policy;
		session->started_at_ms = now;
		session->last_activity_ms = now;
		session->input_octets_base = client->input_octets;
		session->output_octets_base = client->output_octets;
		if (policy->session_timeout_sec)
			session->expires_at_ms = now + (uint64_t)policy->session_timeout_sec * 1000u;
		if (policy->idle_timeout_sec)
			session->idle_expires_at_ms = now + (uint64_t)policy->idle_timeout_sec * 1000u;

		client->state = AIRPORTAL_CLIENT_AUTHENTICATED;
		client->authenticated_at_ms = now;
		snprintf(client->username, sizeof(client->username), "%s",
			 username ? username : "manual");
		snprintf(client->session_id, sizeof(client->session_id), "%s",
			 session->session_id);
		return session;
	}

	ap_log_error("session_table_full max=%u", AIRPORTAL_MAX_SESSIONS);
	return NULL;
}

struct airportal_session *
airportal_session_restore(struct airportal_session_manager *mgr,
			  struct airportal_client *client,
			  const char *session_id,
			  const char *username,
			  const struct airportal_session_policy *policy,
			  uint64_t remaining_session_ms,
			  uint64_t remaining_idle_ms,
			  uint64_t input_octets_base,
			  uint64_t output_octets_base,
			  uint64_t input_octets,
			  uint64_t output_octets)
{
	struct airportal_session *existing;
	struct airportal_session *session;
	uint64_t now;
	size_t i;

	if (!client || !session_id || !session_id[0] || !policy)
		return NULL;

	existing = airportal_session_find_by_client(mgr, client);
	if (existing)
		airportal_session_stop(mgr, existing, AIRPORTAL_CLIENT_CAPTIVE,
				       "restored_replaced");

	for (i = 0; i < AIRPORTAL_MAX_SESSIONS; i++) {
		if (mgr->used[i])
			continue;

		now = airportal_monotonic_ms();
		mgr->used[i] = true;
		mgr->count++;
		session = &mgr->sessions[i];
		memset(session, 0, sizeof(*session));
		snprintf(session->session_id, sizeof(session->session_id), "%s",
			 session_id);
		session->client = client;
		session->policy = *policy;
		session->started_at_ms = now;
		session->last_activity_ms = now;
		session->input_octets_base = input_octets_base;
		session->output_octets_base = output_octets_base;
		session->input_octets = input_octets;
		session->output_octets = output_octets;
		session->last_activity_input_octets = input_octets;
		session->last_activity_output_octets = output_octets;
		if (remaining_session_ms)
			session->expires_at_ms = now + remaining_session_ms;
		if (remaining_idle_ms)
			session->idle_expires_at_ms = now + remaining_idle_ms;
		session->restored_after_restart = true;

		client->state = AIRPORTAL_CLIENT_AUTHENTICATED;
		client->authenticated_at_ms = now;
		snprintf(client->username, sizeof(client->username), "%s",
			 username ? username : "restored");
		snprintf(client->session_id, sizeof(client->session_id), "%s",
			 session->session_id);
		return session;
	}

	ap_log_error("session_table_full max=%u", AIRPORTAL_MAX_SESSIONS);
	return NULL;
}

void airportal_session_stop(struct airportal_session_manager *mgr,
			    struct airportal_session *session,
			    enum airportal_client_state final_state,
			    const char *reason)
{
	size_t index;
	char mac[18];

	if (!mgr || !session)
		return;

	index = (size_t)(session - mgr->sessions);
	if (index >= AIRPORTAL_MAX_SESSIONS || !mgr->used[index])
		return;

	if (session->client) {
		airportal_format_mac(session->client->key.mac, mac, sizeof(mac));
		ap_log_info("session_stop session_id=%s mac=%s ifname=%s portal_id=%u reason=%s",
			    session->session_id, mac, session->client->ifname,
			    session->client->key.portal_id, reason ? reason : "unknown");
		session->client->state = final_state;
		session->client->session_id[0] = '\0';
	}

	memset(session, 0, sizeof(*session));
	mgr->used[index] = false;
	mgr->count--;
}

size_t airportal_session_expire_due(struct airportal_session_manager *mgr,
				    uint64_t now_ms)
{
	size_t i;
	size_t expired = 0;

	for (i = 0; i < AIRPORTAL_MAX_SESSIONS; i++) {
		struct airportal_session *session = &mgr->sessions[i];

		if (!mgr->used[i])
			continue;
		if (session->expires_at_ms && now_ms >= session->expires_at_ms) {
			airportal_session_stop(mgr, session,
					       AIRPORTAL_CLIENT_SESSION_EXPIRED,
					       "session_timeout");
			expired++;
			continue;
		}
		if (session->idle_expires_at_ms && now_ms >= session->idle_expires_at_ms) {
			airportal_session_stop(mgr, session,
					       AIRPORTAL_CLIENT_IDLE_EXPIRED,
					       "idle_timeout");
			expired++;
		}
	}

	return expired;
}
