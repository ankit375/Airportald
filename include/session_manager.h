#ifndef AIRPORTAL_SESSION_MANAGER_H
#define AIRPORTAL_SESSION_MANAGER_H

#include "airportal_types.h"

struct airportal_session_manager {
	struct airportal_session sessions[AIRPORTAL_MAX_SESSIONS];
	bool used[AIRPORTAL_MAX_SESSIONS];
	size_t count;
	uint64_t next_session_counter;
};

void airportal_session_manager_init(struct airportal_session_manager *mgr);
struct airportal_session *
airportal_session_start(struct airportal_session_manager *mgr,
			struct airportal_client *client,
			const char *device_id,
			const char *username,
			const struct airportal_session_policy *policy);
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
			  uint64_t output_octets);
struct airportal_session *
airportal_session_find_by_id(struct airportal_session_manager *mgr,
			     const char *session_id);
struct airportal_session *
airportal_session_find_by_client(struct airportal_session_manager *mgr,
				 const struct airportal_client *client);
void airportal_session_update_octets(struct airportal_session *session,
				     uint64_t input_octets,
				     uint64_t output_octets,
				     uint64_t now_ms);
void airportal_session_stop(struct airportal_session_manager *mgr,
			    struct airportal_session *session,
			    enum airportal_client_state final_state,
			    const char *reason);
size_t airportal_session_expire_due(struct airportal_session_manager *mgr,
				    uint64_t now_ms);

#endif
