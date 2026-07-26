#ifndef AIRPORTAL_PERSISTENCE_H
#define AIRPORTAL_PERSISTENCE_H

struct airportal_daemon;

int persistence_init(struct airportal_daemon *daemon);
int persistence_checkpoint(struct airportal_daemon *daemon);
void persistence_shutdown(struct airportal_daemon *daemon);

#endif
