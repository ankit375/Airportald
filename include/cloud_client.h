#ifndef AIRPORTAL_CLOUD_CLIENT_H
#define AIRPORTAL_CLOUD_CLIENT_H

struct airportal_daemon;

int cloud_client_init(struct airportal_daemon *daemon);
void cloud_client_shutdown(struct airportal_daemon *daemon);

#endif
