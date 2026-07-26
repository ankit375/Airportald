#ifndef AIRPORTAL_PERSISTENCE_H
#define AIRPORTAL_PERSISTENCE_H

struct airportal_daemon;
struct airportal_client;

int persistence_init(struct airportal_daemon *daemon);
int persistence_checkpoint(struct airportal_daemon *daemon);
int persistence_try_restore_client(struct airportal_daemon *daemon,
				   struct airportal_client *client);
void persistence_shutdown(struct airportal_daemon *daemon);

#endif
