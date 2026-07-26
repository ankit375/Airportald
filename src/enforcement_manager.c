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
	bool has_bandwidth_limit;
	int tc_rc;

	if (nft_manager_authorize_client(&daemon->nft, client,
					 policy->session_timeout_sec) != 0)
		return -1;
	has_bandwidth_limit = policy->max_upload_bps ||
			      policy->max_download_bps;
	tc_rc = tc_manager_apply_client(&daemon->tc, client, policy);
	if (tc_rc != 0) {
		ap_log_warn("tc_policy_fallback_nft ifname=%s", client->ifname);
		if (nft_manager_apply_bandwidth_client(&daemon->nft, client,
						       policy) != 0)
			return -1;
	} else if (!has_bandwidth_limit) {
		if (nft_manager_apply_bandwidth_client(&daemon->nft, client,
						       policy) != 0)
			return -1;
	}
	return 0;
}

int enforcement_remove(struct airportal_daemon *daemon,
		       struct airportal_client *client)
{
	tc_manager_remove_client(&daemon->tc, client);
	return nft_manager_remove_client(&daemon->nft, client);
}
