#include "metrics.h"

#include <string.h>

void metrics_init(struct airportal_metrics *metrics)
{
	memset(metrics, 0, sizeof(*metrics));
}
