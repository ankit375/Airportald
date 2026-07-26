#ifndef AIRPORTAL_RADIUS_ACCOUNTING_H
#define AIRPORTAL_RADIUS_ACCOUNTING_H

struct airportal_session;
struct airportal_daemon;

int radius_accounting_init(struct airportal_daemon *daemon);
void radius_accounting_shutdown(struct airportal_daemon *daemon);
int radius_accounting_start(struct airportal_daemon *daemon,
			    const struct airportal_session *session);
int radius_accounting_interim_update(struct airportal_daemon *daemon,
				     const struct airportal_session *session);
int radius_accounting_stop(struct airportal_daemon *daemon,
			   const struct airportal_session *session,
			   const char *reason);

#endif
