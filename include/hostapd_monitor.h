#ifndef AIRPORTAL_HOSTAPD_MONITOR_H
#define AIRPORTAL_HOSTAPD_MONITOR_H

#include "airportal.h"

int hostapd_monitor_init(struct airportal_daemon *daemon);
void hostapd_monitor_shutdown(struct airportal_daemon *daemon);
int hostapd_monitor_handle_event(struct airportal_daemon *daemon,
				 const char *ifname,
				 const char *event);

#endif
