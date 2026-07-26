#ifndef AIRPORTAL_NETLINK_MONITOR_H
#define AIRPORTAL_NETLINK_MONITOR_H

struct airportal_daemon;

int netlink_monitor_init(struct airportal_daemon *daemon);
void netlink_monitor_shutdown(struct airportal_daemon *daemon);

#endif
