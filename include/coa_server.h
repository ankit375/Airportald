#ifndef AIRPORTAL_COA_SERVER_H
#define AIRPORTAL_COA_SERVER_H

struct airportal_daemon;

int coa_server_init(struct airportal_daemon *daemon);
void coa_server_shutdown(struct airportal_daemon *daemon);

#endif
