#ifndef AIRPORTAL_CONFIG_MANAGER_H
#define AIRPORTAL_CONFIG_MANAGER_H

#include "airportal_types.h"
#include "log.h"

struct airportal_global_config {
	bool enabled;
	enum airportal_log_level log_level;
	char state_dir[128];
	char persistent_db[128];
	bool session_restore;
	bool cloud_managed;
	uint32_t default_accounting_interval;
	uint32_t default_session_timeout;
	uint32_t default_idle_timeout;
	uint64_t default_idle_activity_threshold_bytes;
	bool fail_open;
	uint16_t portal_http_port;
	char portal_http_host[64];
	uint16_t coa_port;
	char device_id[64];
	char token_key_file[128];
};

struct airportal_portal_config {
	char name[32];
	bool enabled;
	uint32_t portal_id;
	char auth_mode[24];
	char portal_url[256];
	char uam_secret[128];
	char network[32];
	char radius_profile[32];
	uint32_t default_session_timeout;
	uint32_t default_idle_timeout;
	uint64_t default_idle_activity_threshold_bytes;
	bool client_isolation;
	bool allow_dns;
	bool allow_dhcp;
	bool allow_captive_detection;
};

struct airportal_binding_config {
	char portal[32];
	char vif[IFNAMSIZ];
	uint32_t portal_id;
};

struct airportal_radius_config {
	char name[32];
	char transport[16];
	char auth_server[64];
	uint16_t auth_port;
	char acct_server[64];
	uint16_t acct_port;
	char coa_bind[64];
	char coa_source[64];
	uint16_t coa_port;
	char secret_file[128];
	char nas_identifier[64];
	char radsec_ca_cert[128];
	char radsec_client_cert[128];
	char radsec_client_key[128];
	char radsec_crl_file[128];
	char radsec_server_name[128];
	bool radsec_verify_host;
	uint32_t retry_count;
	uint32_t timeout_ms;
};

struct airportal_walled_garden_config {
	char name[32];
	char portal[32];
	char type[16];
	char value[256];
};

struct airportal_config {
	struct airportal_global_config global;
	struct airportal_portal_config portals[AIRPORTAL_MAX_PORTALS];
	size_t portal_count;
	struct airportal_binding_config bindings[AIRPORTAL_MAX_BINDINGS];
	size_t binding_count;
	struct airportal_radius_config radius[AIRPORTAL_MAX_RADIUS_PROFILES];
	size_t radius_count;
	struct airportal_walled_garden_config walled_gardens[AIRPORTAL_MAX_WALLED_GARDENS];
	size_t walled_garden_count;
	char validation_error[256];
};

int airportal_config_load(struct airportal_config *cfg, const char *package);
void airportal_config_defaults(struct airportal_config *cfg);
const struct airportal_portal_config *
airportal_config_find_portal_by_id(const struct airportal_config *cfg,
				   uint32_t portal_id);
const struct airportal_portal_config *
airportal_config_find_portal_by_name(const struct airportal_config *cfg,
				     const char *name);
const struct airportal_radius_config *
airportal_config_find_radius_by_name(const struct airportal_config *cfg,
				     const char *name);
const struct airportal_binding_config *
airportal_config_find_binding(const struct airportal_config *cfg,
			      const char *ifname);
int airportal_config_validate(struct airportal_config *cfg);

#endif
