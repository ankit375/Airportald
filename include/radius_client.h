#ifndef AIRPORTAL_RADIUS_CLIENT_H
#define AIRPORTAL_RADIUS_CLIENT_H

#include "airportal_types.h"
#include "config_manager.h"

struct airportal_daemon;

enum radius_auth_result {
	RADIUS_AUTH_ACCEPT = 0,
	RADIUS_AUTH_REJECT = 1,
	RADIUS_AUTH_TIMEOUT = 2,
	RADIUS_AUTH_ERROR = 3
};

int radius_client_init(struct airportal_daemon *daemon);
void radius_client_shutdown(struct airportal_daemon *daemon);
enum radius_auth_result
radius_client_authenticate(struct airportal_daemon *daemon,
			   const struct airportal_radius_config *radius,
			   const struct airportal_portal_config *portal,
			   const struct airportal_client *client,
			   const char *username,
			   const char *password,
			   struct airportal_session_policy *policy);

#endif
