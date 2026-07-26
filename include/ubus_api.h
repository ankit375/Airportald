#ifndef AIRPORTAL_UBUS_API_H
#define AIRPORTAL_UBUS_API_H

#include "airportal.h"

int ubus_api_init(struct airportal_daemon *daemon);
void ubus_api_shutdown(struct airportal_daemon *daemon);

#endif
