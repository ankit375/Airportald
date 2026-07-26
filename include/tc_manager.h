#ifndef AIRPORTAL_TC_MANAGER_H
#define AIRPORTAL_TC_MANAGER_H

#include "airportal_types.h"

struct tc_client_policy {
	uint32_t mark;
	uint64_t upload_bps;
	uint64_t download_bps;
};

struct tc_manager {
	bool ready;
	bool native_available;
};

int tc_manager_init(struct tc_manager *mgr);
int tc_manager_apply_client(struct tc_manager *mgr,
			    const struct airportal_client *client,
			    const struct airportal_session_policy *policy);
int tc_manager_update_client(struct tc_manager *mgr,
			     const struct airportal_client *client,
			     const struct airportal_session_policy *policy);
int tc_manager_remove_client(struct tc_manager *mgr,
			     const struct airportal_client *client);
void tc_manager_flush_managed_state(struct tc_manager *mgr);

#endif
