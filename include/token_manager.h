#ifndef AIRPORTAL_TOKEN_MANAGER_H
#define AIRPORTAL_TOKEN_MANAGER_H

#include "airportal_types.h"
#include "config_manager.h"

struct token_manager {
	uint8_t key[32];
	bool has_key;
	char nonces[64][65];
	size_t nonce_next;
};

int token_manager_init(struct token_manager *mgr, const char *key_file);
int token_create(struct token_manager *mgr,
		 const struct airportal_client *client,
		 const struct airportal_portal_config *portal,
		 char **out_token);
int token_validate(struct token_manager *mgr,
		   const char *token,
		   struct airportal_token_claims *claims);

#endif
