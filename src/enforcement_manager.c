#include "enforcement_manager.h"

int enforcement_install_captive(struct airportal_daemon *daemon,
				struct airportal_client *client)
{
	return nft_manager_add_captive_client(&daemon->nft, client);
}

int enforcement_authorize(struct airportal_daemon *daemon,
			  struct airportal_client *client,
			  const struct airportal_session_policy *policy)
{
	if (nft_manager_authorize_client(&daemon->nft, client,
					 policy->session_timeout_sec) != 0)
		return -1;
	if (tc_manager_apply_client(&daemon->tc, client, policy) != 0)
		return -1;
	return 0;
}

int enforcement_remove(struct airportal_daemon *daemon,
		       struct airportal_client *client)
{
	tc_manager_remove_client(&daemon->tc, client);
	return nft_manager_remove_client(&daemon->nft, client);
}
