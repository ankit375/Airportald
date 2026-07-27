#include "config_manager.h"

#include "log.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef AIRPORTAL_OPENWRT
#include <uci.h>
#endif

static void set_error(struct airportal_config *cfg, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void set_error(struct airportal_config *cfg, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(cfg->validation_error, sizeof(cfg->validation_error), fmt, ap);
	va_end(ap);
}

void airportal_config_defaults(struct airportal_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->global.enabled = true;
	cfg->global.log_level = AIRPORTAL_LOG_INFO;
	snprintf(cfg->global.state_dir, sizeof(cfg->global.state_dir), "/tmp/airportal");
	snprintf(cfg->global.persistent_db, sizeof(cfg->global.persistent_db),
		 "/etc/airportal/sessions.db");
	cfg->global.session_restore = true;
	cfg->global.cloud_managed = true;
	cfg->global.default_accounting_interval = 300;
	cfg->global.default_session_timeout = 3600;
	cfg->global.default_idle_timeout = 600;
	cfg->global.default_idle_activity_threshold_bytes = 65536;
	cfg->global.portal_http_port = 8088;
	cfg->global.portal_http_host[0] = '\0';
	cfg->global.coa_port = 3799;
	snprintf(cfg->global.device_id, sizeof(cfg->global.device_id), "ap");
	snprintf(cfg->global.token_key_file, sizeof(cfg->global.token_key_file),
		 "/etc/airportal/token.key");
}

const struct airportal_portal_config *
airportal_config_find_portal_by_id(const struct airportal_config *cfg,
				   uint32_t portal_id)
{
	size_t i;

	for (i = 0; i < cfg->portal_count; i++) {
		if (cfg->portals[i].portal_id == portal_id)
			return &cfg->portals[i];
	}

	return NULL;
}

const struct airportal_portal_config *
airportal_config_find_portal_by_name(const struct airportal_config *cfg,
				     const char *name)
{
	size_t i;

	if (!name)
		return NULL;
	for (i = 0; i < cfg->portal_count; i++) {
		if (strcmp(cfg->portals[i].name, name) == 0)
			return &cfg->portals[i];
	}

	return NULL;
}

const struct airportal_radius_config *
airportal_config_find_radius_by_name(const struct airportal_config *cfg,
				     const char *name)
{
	size_t i;

	if (!name)
		return NULL;
	for (i = 0; i < cfg->radius_count; i++) {
		if (strcmp(cfg->radius[i].name, name) == 0)
			return &cfg->radius[i];
	}

	return NULL;
}

const struct airportal_binding_config *
airportal_config_find_binding(const struct airportal_config *cfg,
			      const char *ifname)
{
	size_t i;

	if (!ifname || !ifname[0])
		return NULL;
	for (i = 0; i < cfg->binding_count; i++) {
		if (strcmp(cfg->bindings[i].vif, ifname) == 0)
			return &cfg->bindings[i];
	}

	return NULL;
}

static bool valid_port(uint16_t port)
{
	return port > 0;
}

static bool valid_timeout(uint32_t value)
{
	return value == 0 || (value >= 30 && value <= 86400);
}

int airportal_config_validate(struct airportal_config *cfg)
{
	size_t i;
	size_t j;

	cfg->validation_error[0] = '\0';

	if (!valid_port(cfg->global.portal_http_port) ||
	    !valid_port(cfg->global.coa_port)) {
		set_error(cfg, "invalid global port");
		return -1;
	}
	if (!valid_timeout(cfg->global.default_session_timeout) ||
	    !valid_timeout(cfg->global.default_idle_timeout)) {
		set_error(cfg, "invalid global timeout");
		return -1;
	}

	for (i = 0; i < cfg->portal_count; i++) {
		const struct airportal_portal_config *portal = &cfg->portals[i];

		if (!portal->enabled)
			continue;
		if (portal->portal_id == 0) {
			set_error(cfg, "portal %s has invalid portal_id", portal->name);
			return -1;
		}
		for (j = i + 1; j < cfg->portal_count; j++) {
			if (cfg->portals[j].portal_id == portal->portal_id) {
				set_error(cfg, "duplicate portal_id %u", portal->portal_id);
				return -1;
			}
		}
		if (!portal->portal_url[0]) {
			set_error(cfg, "portal %s missing portal_url", portal->name);
			return -1;
		}
		if (strcmp(portal->auth_mode, "manual") != 0 &&
		    strcmp(portal->auth_mode, "radius") != 0 &&
		    strcmp(portal->auth_mode, "cloud_callback") != 0 &&
		    strcmp(portal->auth_mode, "click_through") != 0) {
			set_error(cfg, "portal %s has unsupported auth_mode", portal->name);
			return -1;
		}
		if (strcmp(portal->auth_mode, "radius") == 0 &&
		    !portal->radius_profile[0]) {
			set_error(cfg, "portal %s missing radius_profile", portal->name);
			return -1;
		}
		if (!valid_timeout(portal->default_session_timeout) ||
		    !valid_timeout(portal->default_idle_timeout)) {
			set_error(cfg, "portal %s has invalid timeout", portal->name);
			return -1;
		}
	}

	for (i = 0; i < cfg->binding_count; i++) {
		const struct airportal_binding_config *binding = &cfg->bindings[i];

		if (!binding->vif[0]) {
			set_error(cfg, "binding missing vif");
			return -1;
		}
		if (!airportal_config_find_portal_by_name(cfg, binding->portal)) {
			set_error(cfg, "binding references unknown portal %s", binding->portal);
			return -1;
		}
		for (j = i + 1; j < cfg->binding_count; j++) {
			if (strcmp(binding->vif, cfg->bindings[j].vif) == 0) {
				set_error(cfg, "duplicate interface binding %s", binding->vif);
				return -1;
			}
		}
	}

	for (i = 0; i < cfg->radius_count; i++) {
		const struct airportal_radius_config *radius = &cfg->radius[i];
		bool referenced = false;

		if (!valid_port(radius->auth_port) || !valid_port(radius->acct_port) ||
		    !valid_port(radius->coa_port)) {
			set_error(cfg, "radius profile %s has invalid port", radius->name);
			return -1;
		}
		for (j = 0; j < cfg->portal_count; j++) {
			if (cfg->portals[j].enabled &&
			    strcmp(cfg->portals[j].auth_mode, "radius") == 0 &&
			    strcmp(cfg->portals[j].radius_profile, radius->name) == 0)
				referenced = true;
		}
		if (referenced && radius->secret_file[0] &&
		    access(radius->secret_file, R_OK) != 0) {
			set_error(cfg, "radius profile %s secret_file unreadable", radius->name);
			return -1;
		}
	}

	for (i = 0; i < cfg->binding_count; i++) {
		const struct airportal_portal_config *portal =
			airportal_config_find_portal_by_name(cfg, cfg->bindings[i].portal);

		cfg->bindings[i].portal_id = portal ? portal->portal_id : 0;
	}

	return 0;
}

#ifdef AIRPORTAL_OPENWRT
static const char *uci_lookup_string(struct uci_context *ctx,
				     struct uci_section *s,
				     const char *name)
{
	const char *value = uci_lookup_option_string(ctx, s, name);

	return value ? value : "";
}

static bool uci_lookup_bool(struct uci_context *ctx, struct uci_section *s,
			    const char *name, bool def)
{
	const char *value = uci_lookup_option_string(ctx, s, name);

	if (!value || !value[0])
		return def;
	return strcmp(value, "1") == 0 || strcmp(value, "true") == 0 ||
	       strcmp(value, "yes") == 0 || strcmp(value, "on") == 0;
}

static uint32_t uci_lookup_u32(struct uci_context *ctx, struct uci_section *s,
			       const char *name, uint32_t def)
{
	const char *value = uci_lookup_option_string(ctx, s, name);
	char *end = NULL;
	unsigned long parsed;

	if (!value || !value[0])
		return def;
	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno || !end || *end)
		return def;
	return (uint32_t)parsed;
}

int airportal_config_load(struct airportal_config *cfg, const char *package)
{
	struct uci_context *ctx;
	struct uci_package *pkg = NULL;
	struct uci_element *e;
	int rc = -1;

	airportal_config_defaults(cfg);
	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, package ? package : "airportal", &pkg) != UCI_OK)
		goto out;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, "global") == 0) {
			cfg->global.enabled = uci_lookup_bool(ctx, s, "enabled", true);
			cfg->global.log_level =
				airportal_log_level_from_string(uci_lookup_string(ctx, s,
										  "log_level"));
			snprintf(cfg->global.state_dir, sizeof(cfg->global.state_dir), "%s",
				 uci_lookup_string(ctx, s, "state_dir"));
			snprintf(cfg->global.persistent_db, sizeof(cfg->global.persistent_db), "%s",
				 uci_lookup_string(ctx, s, "persistent_db"));
			cfg->global.session_restore = uci_lookup_bool(ctx, s, "session_restore",
								      true);
			cfg->global.cloud_managed = uci_lookup_bool(ctx, s, "cloud_managed",
								    true);
			cfg->global.default_accounting_interval =
				uci_lookup_u32(ctx, s, "default_accounting_interval", 300);
			cfg->global.default_session_timeout =
				uci_lookup_u32(ctx, s, "default_session_timeout", 3600);
			cfg->global.default_idle_timeout =
				uci_lookup_u32(ctx, s, "default_idle_timeout", 600);
			cfg->global.default_idle_activity_threshold_bytes =
				uci_lookup_u32(ctx, s,
					       "default_idle_activity_threshold_bytes",
					       65536);
			cfg->global.fail_open = uci_lookup_bool(ctx, s, "fail_open", false);
			cfg->global.portal_http_port =
				(uint16_t)uci_lookup_u32(ctx, s, "portal_http_port", 8088);
			snprintf(cfg->global.portal_http_host,
				 sizeof(cfg->global.portal_http_host), "%s",
				 uci_lookup_string(ctx, s, "portal_http_host"));
			cfg->global.coa_port =
				(uint16_t)uci_lookup_u32(ctx, s, "coa_port", 3799);
			snprintf(cfg->global.device_id, sizeof(cfg->global.device_id), "%s",
				 uci_lookup_string(ctx, s, "device_id"));
			snprintf(cfg->global.token_key_file, sizeof(cfg->global.token_key_file),
				 "%s", uci_lookup_string(ctx, s, "token_key_file"));
		} else if (strcmp(s->type, "portal") == 0 &&
			   cfg->portal_count < AIRPORTAL_MAX_PORTALS) {
			struct airportal_portal_config *portal =
				&cfg->portals[cfg->portal_count++];

			snprintf(portal->name, sizeof(portal->name), "%s", s->e.name);
			portal->enabled = uci_lookup_bool(ctx, s, "enabled", true);
			portal->portal_id = uci_lookup_u32(ctx, s, "portal_id", 0);
			snprintf(portal->auth_mode, sizeof(portal->auth_mode), "%s",
				 uci_lookup_string(ctx, s, "auth_mode"));
			snprintf(portal->portal_url, sizeof(portal->portal_url), "%s",
				 uci_lookup_string(ctx, s, "portal_url"));
			snprintf(portal->uam_secret, sizeof(portal->uam_secret), "%s",
				 uci_lookup_string(ctx, s, "uam_secret"));
			snprintf(portal->network, sizeof(portal->network), "%s",
				 uci_lookup_string(ctx, s, "network"));
			snprintf(portal->radius_profile, sizeof(portal->radius_profile), "%s",
				 uci_lookup_string(ctx, s, "radius_profile"));
			portal->default_session_timeout =
				uci_lookup_u32(ctx, s, "default_session_timeout",
					       cfg->global.default_session_timeout);
			portal->default_idle_timeout =
				uci_lookup_u32(ctx, s, "default_idle_timeout",
					       cfg->global.default_idle_timeout);
			portal->default_idle_activity_threshold_bytes =
				uci_lookup_u32(ctx, s,
					       "default_idle_activity_threshold_bytes",
					       cfg->global.default_idle_activity_threshold_bytes);
			portal->client_isolation = uci_lookup_bool(ctx, s, "client_isolation",
								   true);
			portal->allow_dns = uci_lookup_bool(ctx, s, "allow_dns", true);
			portal->allow_dhcp = uci_lookup_bool(ctx, s, "allow_dhcp", true);
			portal->allow_captive_detection =
				uci_lookup_bool(ctx, s, "allow_captive_detection", true);
		} else if (strcmp(s->type, "binding") == 0 &&
			   cfg->binding_count < AIRPORTAL_MAX_BINDINGS) {
			struct airportal_binding_config *binding =
				&cfg->bindings[cfg->binding_count++];

			snprintf(binding->portal, sizeof(binding->portal), "%s",
				 uci_lookup_string(ctx, s, "portal"));
			snprintf(binding->vif, sizeof(binding->vif), "%s",
				 uci_lookup_string(ctx, s, "vif"));
		} else if (strcmp(s->type, "radius") == 0 &&
			   cfg->radius_count < AIRPORTAL_MAX_RADIUS_PROFILES) {
			struct airportal_radius_config *radius =
				&cfg->radius[cfg->radius_count++];

			snprintf(radius->name, sizeof(radius->name), "%s", s->e.name);
			snprintf(radius->auth_server, sizeof(radius->auth_server), "%s",
				 uci_lookup_string(ctx, s, "auth_server"));
			radius->auth_port = (uint16_t)uci_lookup_u32(ctx, s, "auth_port",
								     1812);
			snprintf(radius->acct_server, sizeof(radius->acct_server), "%s",
				 uci_lookup_string(ctx, s, "acct_server"));
			radius->acct_port = (uint16_t)uci_lookup_u32(ctx, s, "acct_port",
								     1813);
			snprintf(radius->coa_bind, sizeof(radius->coa_bind), "%s",
				 uci_lookup_string(ctx, s, "coa_bind"));
			snprintf(radius->coa_source, sizeof(radius->coa_source), "%s",
				 uci_lookup_string(ctx, s, "coa_source"));
			radius->coa_port = (uint16_t)uci_lookup_u32(ctx, s, "coa_port",
								    3799);
			snprintf(radius->secret_file, sizeof(radius->secret_file), "%s",
				 uci_lookup_string(ctx, s, "secret_file"));
			snprintf(radius->nas_identifier, sizeof(radius->nas_identifier), "%s",
				 uci_lookup_string(ctx, s, "nas_identifier"));
			radius->retry_count = uci_lookup_u32(ctx, s, "retry_count", 3);
			radius->timeout_ms = uci_lookup_u32(ctx, s, "timeout_ms", 3000);
		} else if (strcmp(s->type, "walled_garden") == 0 &&
			   cfg->walled_garden_count < AIRPORTAL_MAX_WALLED_GARDENS) {
			struct airportal_walled_garden_config *wg =
				&cfg->walled_gardens[cfg->walled_garden_count++];

			snprintf(wg->name, sizeof(wg->name), "%s", s->e.name);
			snprintf(wg->portal, sizeof(wg->portal), "%s",
				 uci_lookup_string(ctx, s, "portal"));
			snprintf(wg->type, sizeof(wg->type), "%s",
				 uci_lookup_string(ctx, s, "type"));
			snprintf(wg->value, sizeof(wg->value), "%s",
				 uci_lookup_string(ctx, s, "value"));
		}
	}

	rc = airportal_config_validate(cfg);
out:
	if (pkg)
		uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return rc;
}
#else
int airportal_config_load(struct airportal_config *cfg, const char *package)
{
	(void)package;
	airportal_config_defaults(cfg);

	snprintf(cfg->portals[0].name, sizeof(cfg->portals[0].name), "guest");
	cfg->portals[0].enabled = true;
	cfg->portals[0].portal_id = 36;
	snprintf(cfg->portals[0].auth_mode, sizeof(cfg->portals[0].auth_mode), "manual");
	snprintf(cfg->portals[0].portal_url, sizeof(cfg->portals[0].portal_url),
		 "https://captive-portal.example.com/login");
	cfg->portals[0].uam_secret[0] = '\0';
	snprintf(cfg->portals[0].network, sizeof(cfg->portals[0].network), "guest");
	cfg->portals[0].default_session_timeout = 3600;
	cfg->portals[0].default_idle_timeout = 600;
	cfg->portals[0].default_idle_activity_threshold_bytes = 65536;
	cfg->portals[0].allow_dns = true;
	cfg->portals[0].allow_dhcp = true;
	cfg->portals[0].allow_captive_detection = true;
	cfg->portal_count = 1;

	snprintf(cfg->bindings[0].portal, sizeof(cfg->bindings[0].portal), "guest");
	snprintf(cfg->bindings[0].vif, sizeof(cfg->bindings[0].vif), "wlan1-1");
	cfg->binding_count = 1;

	return airportal_config_validate(cfg);
}
#endif
