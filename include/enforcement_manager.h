#ifndef AIRPORTAL_ENFORCEMENT_MANAGER_H
#define AIRPORTAL_ENFORCEMENT_MANAGER_H

#include "airportal.h"

int enforcement_install_captive(struct airportal_daemon *daemon,
				struct airportal_client *client);
int enforcement_authorize(struct airportal_daemon *daemon,
			  struct airportal_client *client,
			  const struct airportal_session_policy *policy);
int enforcement_remove(struct airportal_daemon *daemon,
		       struct airportal_client *client);

#endif
