#ifndef AIRPORTAL_NFT_MANAGER_H
#define AIRPORTAL_NFT_MANAGER_H

#include "config_manager.h"
#include "airportal_types.h"

struct nft_bandwidth_entry {
	bool used;
	struct airportal_client_key key;
	char ifname[IFNAMSIZ];
	uint64_t upload_bps;
	uint64_t download_bps;
};

struct nft_manager {
	bool ready;
	bool dry_run;
	uint16_t portal_port;
	struct nft_bandwidth_entry bandwidth[AIRPORTAL_MAX_CLIENTS];
};

int nft_manager_init(struct nft_manager *mgr, bool dry_run);
int nft_manager_install_base_rules(struct nft_manager *mgr,
				   const struct airportal_config *config,
				   uint16_t portal_port);
int nft_manager_refresh_walled_garden(struct nft_manager *mgr,
				      const struct airportal_config *config);
int nft_manager_add_captive_client(struct nft_manager *mgr,
				   const struct airportal_client *client);
int nft_manager_authorize_client(struct nft_manager *mgr,
				 const struct airportal_client *client,
				 uint32_t timeout_sec);
int nft_manager_apply_bandwidth_client(struct nft_manager *mgr,
				       const struct airportal_client *client,
				       const struct airportal_session_policy *policy);
int nft_manager_block_client(struct nft_manager *mgr,
			     const struct airportal_client *client);
int nft_manager_remove_client(struct nft_manager *mgr,
			      const struct airportal_client *client);
int nft_manager_flush_managed_state(struct nft_manager *mgr);

#endif
