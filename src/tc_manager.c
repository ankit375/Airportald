#include "tc_manager.h"

#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int run_tc(char *const argv[], bool quiet)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		if (quiet) {
			int nullfd = open("/dev/null", O_WRONLY);

			if (nullfd >= 0) {
				dup2(nullfd, STDOUT_FILENO);
				dup2(nullfd, STDERR_FILENO);
				close(nullfd);
			}
		}
		execvp(argv[0], argv);
		_exit(127);
	}

	do {
		if (waitpid(pid, &status, 0) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		break;
	} while (true);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

static void probe_module(const char *module)
{
	char *const argv[] = { "modprobe", (char *)module, NULL };

	run_tc(argv, true);
}

static uint32_t client_priority(const struct airportal_client *client)
{
	return 1000u + (airportal_client_key_hash(&client->key) % 30000u);
}

static void format_rate(uint64_t bps, char *buf, size_t len)
{
	uint64_t kbit = (bps + 999u) / 1000u;

	if (kbit == 0)
		kbit = 1;
	snprintf(buf, len, "%llukbit", (unsigned long long)kbit);
}

static void format_burst(uint64_t bps, char *buf, size_t len)
{
	uint64_t burst = bps / 80u;

	if (burst < 1024u)
		burst = 1024u;
	if (burst > 65536u)
		burst = 65536u;
	snprintf(buf, len, "%llub", (unsigned long long)burst);
}

static int ensure_clsact(const struct airportal_client *client)
{
	char *const argv[] = {
		"tc", "qdisc", "replace", "dev", (char *)client->ifname,
		"clsact", NULL
	};

	return run_tc(argv, true);
}

static void remove_filter(const struct airportal_client *client,
			  const char *direction, uint32_t pref)
{
	char pref_buf[16];
	char *const argv[] = {
		"tc", "filter", "delete", "dev", (char *)client->ifname,
		(char *)direction, "pref", pref_buf, NULL
	};

	snprintf(pref_buf, sizeof(pref_buf), "%u", pref);
	run_tc(argv, true);
}

static int apply_filter(const struct airportal_client *client,
			const char *direction, const char *mac_key,
			uint64_t bps, uint32_t pref)
{
	char mac[18];
	char pref_buf[16];
	char rate[32];
	char burst[32];
	char *const argv[] = {
		"tc", "filter", "replace", "dev", (char *)client->ifname,
		(char *)direction, "protocol", "all", "pref", pref_buf,
		"flower", (char *)mac_key, mac, "action", "police",
		"rate", rate, "burst", burst, "conform-exceed", "drop", NULL
	};

	airportal_format_mac(client->key.mac, mac, sizeof(mac));
	snprintf(pref_buf, sizeof(pref_buf), "%u", pref);
	format_rate(bps, rate, sizeof(rate));
	format_burst(bps, burst, sizeof(burst));
	return run_tc(argv, false);
}

int tc_manager_init(struct tc_manager *mgr)
{
	char *const argv[] = { "tc", "-V", NULL };

	if (!mgr)
		return -1;
	memset(mgr, 0, sizeof(*mgr));
	mgr->ready = true;
	mgr->native_available = run_tc(argv, true) == 0;
	if (mgr->native_available) {
		probe_module("sch_ingress");
		probe_module("sch_clsact");
		probe_module("cls_flower");
		probe_module("act_police");
	}
	ap_log_info("tc_manager_ready phase=%s",
		    mgr->native_available ? "native" : "unavailable");
	return 0;
}

int tc_manager_apply_client(struct tc_manager *mgr,
			    const struct airportal_client *client,
			    const struct airportal_session_policy *policy)
{
	uint32_t pref;
	int rc = 0;

	if (!mgr || !mgr->ready || !client || !policy)
		return -1;
	if (!mgr->native_available) {
		ap_log_warn("tc_policy_skipped reason=tc_unavailable ifname=%s",
			    client->ifname);
		return policy->max_upload_bps || policy->max_download_bps ? -1 : 0;
	}

	pref = client_priority(client);
	if (ensure_clsact(client) != 0) {
		ap_log_warn("tc_policy_skipped reason=clsact_unavailable ifname=%s",
			    client->ifname);
		return policy->max_upload_bps || policy->max_download_bps ? -1 : 0;
	}

	remove_filter(client, "ingress", pref);
	remove_filter(client, "egress", pref);
	if (!policy->max_upload_bps && !policy->max_download_bps)
		return 0;

	if (policy->max_upload_bps &&
	    apply_filter(client, "ingress", "src_mac",
			 policy->max_upload_bps, pref) != 0)
		rc = -1;
	if (policy->max_download_bps &&
	    apply_filter(client, "egress", "dst_mac",
			 policy->max_download_bps, pref) != 0)
		rc = -1;

	if (rc == 0)
		ap_log_info("tc_policy_apply mac=%02X:%02X:%02X:%02X:%02X:%02X ifname=%s pref=%u upload_bps=%llu download_bps=%llu",
			    client->key.mac[0], client->key.mac[1],
			    client->key.mac[2], client->key.mac[3],
			    client->key.mac[4], client->key.mac[5],
			    client->ifname, pref,
			    (unsigned long long)policy->max_upload_bps,
			    (unsigned long long)policy->max_download_bps);
	else
		ap_log_warn("tc_policy_apply_failed ifname=%s pref=%u",
			    client->ifname, pref);
	return rc;
}

int tc_manager_update_client(struct tc_manager *mgr,
			     const struct airportal_client *client,
			     const struct airportal_session_policy *policy)
{
	return tc_manager_apply_client(mgr, client, policy);
}

int tc_manager_remove_client(struct tc_manager *mgr,
			     const struct airportal_client *client)
{
	uint32_t pref;

	if (!mgr || !mgr->ready || !client)
		return -1;
	if (!mgr->native_available)
		return 0;
	pref = client_priority(client);
	remove_filter(client, "ingress", pref);
	remove_filter(client, "egress", pref);
	ap_log_info("tc_policy_remove mac=%02X:%02X:%02X:%02X:%02X:%02X ifname=%s pref=%u",
		    client->key.mac[0], client->key.mac[1], client->key.mac[2],
		    client->key.mac[3], client->key.mac[4], client->key.mac[5],
		    client->ifname, pref);
	return 0;
}

void tc_manager_flush_managed_state(struct tc_manager *mgr)
{
	if (!mgr)
		return;
	mgr->ready = false;
}
