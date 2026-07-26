#ifndef AIRPORTAL_PORTAL_HTTP_H
#define AIRPORTAL_PORTAL_HTTP_H

#include "airportal.h"

int portal_http_init(struct airportal_daemon *daemon);
void portal_http_shutdown(struct airportal_daemon *daemon);

#endif
