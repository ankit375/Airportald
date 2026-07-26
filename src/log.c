#include "log.h"

#include <stdio.h>
#include <string.h>
#include <syslog.h>

static enum airportal_log_level current_level = AIRPORTAL_LOG_INFO;

void airportal_log_init(enum airportal_log_level level)
{
	current_level = level;
	openlog("airportal", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

enum airportal_log_level airportal_log_level_from_string(const char *level)
{
	if (!level)
		return AIRPORTAL_LOG_INFO;
	if (strcmp(level, "error") == 0)
		return AIRPORTAL_LOG_ERROR;
	if (strcmp(level, "warn") == 0)
		return AIRPORTAL_LOG_WARN;
	if (strcmp(level, "info") == 0)
		return AIRPORTAL_LOG_INFO;
	if (strcmp(level, "debug") == 0)
		return AIRPORTAL_LOG_DEBUG;
	if (strcmp(level, "trace") == 0)
		return AIRPORTAL_LOG_TRACE;
	return AIRPORTAL_LOG_INFO;
}

static int syslog_priority(enum airportal_log_level level)
{
	switch (level) {
	case AIRPORTAL_LOG_ERROR:
		return LOG_ERR;
	case AIRPORTAL_LOG_WARN:
		return LOG_WARNING;
	case AIRPORTAL_LOG_INFO:
		return LOG_INFO;
	case AIRPORTAL_LOG_DEBUG:
	case AIRPORTAL_LOG_TRACE:
	default:
		return LOG_DEBUG;
	}
}

void airportal_log(enum airportal_log_level level, const char *fmt, ...)
{
	va_list ap;

	if (level > current_level)
		return;

	va_start(ap, fmt);
	vsyslog(syslog_priority(level), fmt, ap);
	va_end(ap);
}
