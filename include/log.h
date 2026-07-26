#ifndef AIRPORTAL_LOG_H
#define AIRPORTAL_LOG_H

#include <stdarg.h>

enum airportal_log_level {
	AIRPORTAL_LOG_ERROR = 0,
	AIRPORTAL_LOG_WARN,
	AIRPORTAL_LOG_INFO,
	AIRPORTAL_LOG_DEBUG,
	AIRPORTAL_LOG_TRACE
};

void airportal_log_init(enum airportal_log_level level);
enum airportal_log_level airportal_log_level_from_string(const char *level);
void airportal_log(enum airportal_log_level level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#define ap_log_error(...) airportal_log(AIRPORTAL_LOG_ERROR, __VA_ARGS__)
#define ap_log_warn(...) airportal_log(AIRPORTAL_LOG_WARN, __VA_ARGS__)
#define ap_log_info(...) airportal_log(AIRPORTAL_LOG_INFO, __VA_ARGS__)
#define ap_log_debug(...) airportal_log(AIRPORTAL_LOG_DEBUG, __VA_ARGS__)
#define ap_log_trace(...) airportal_log(AIRPORTAL_LOG_TRACE, __VA_ARGS__)

#endif
