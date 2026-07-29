#ifndef AIRPORTAL_RADIUS_TRANSPORT_H
#define AIRPORTAL_RADIUS_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config_manager.h"

bool radius_transport_is_radsec(const struct airportal_radius_config *radius);
int radius_transport_exchange(const struct airportal_radius_config *radius,
			      const char *host, uint16_t port,
			      const uint8_t *request, size_t request_len,
			      uint8_t *response, size_t response_len,
			      size_t *actual_response_len);

#endif
