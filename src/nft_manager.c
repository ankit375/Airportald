#include "nft_manager.h"

#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define AIRPORTAL_NFT_TABLE "airportal"
#define AIRPORTAL_NFT_BRIDGE_TABLE "airportal_broute"

static void log_client_action(const char *action,
			      const struct airportal_client *client)
{
	char mac[18];

	airportal_format_mac(client->key.mac, mac, sizeof(mac));
	ap_log_info("nft_%s mac=%s ifname=%s ifindex=%u vlan_id=%u portal_id=%u",
		    action, mac, client->ifname, client->key.ifindex,
		    client->key.vlan_id, client->key.portal_id);
}

static int run_nft_argv(char *const argv[], const char *input, bool quiet)
{
	int pipefd[2] = { -1, -1 };
	pid_t pid;
	int status;

	if (input && pipe(pipefd) != 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		if (pipefd[0] >= 0)
			close(pipefd[0]);
		if (pipefd[1] >= 0)
			close(pipefd[1]);
		return -1;
	}

	if (pid == 0) {
		if (quiet) {
			int nullfd = open("/dev/null", O_WRONLY);

			if (nullfd >= 0) {
				dup2(nullfd, STDERR_FILENO);
				close(nullfd);
			}
		}
		if (input) {
			close(pipefd[1]);
			if (dup2(pipefd[0], STDIN_FILENO) < 0)
				_exit(127);
			close(pipefd[0]);
		}
		execvp(argv[0], argv);
		_exit(127);
	}

	if (input) {
		size_t remaining = strlen(input);
		const char *p = input;

		close(pipefd[0]);
		while (remaining > 0) {
			ssize_t n = write(pipefd[1], p, remaining);

			if (n < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			p += n;
			remaining -= (size_t)n;
		}
		close(pipefd[1]);
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

static int run_nft_script(const char *script)
{
	char *const argv[] = { "nft", "-f", "-", NULL };

	return run_nft_argv(argv, script, false);
}

static int run_nft_script_quiet(const char *script)
{
	char *const argv[] = { "nft", "-f", "-", NULL };

	return run_nft_argv(argv, script, true);
}

static void enable_bridge_netfilter(void)
{
	static const char *paths[] = {
		"/proc/sys/net/bridge/bridge-nf-call-iptables",
		"/proc/sys/net/bridge/bridge-nf-call-ip6tables",
	};
	size_t i;

	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		int fd = open(paths[i], O_WRONLY | O_CLOEXEC);

		if (fd < 0)
			continue;
		if (write(fd, "1\n", 2) < 0)
			ap_log_warn("bridge_netfilter_enable_failed path=%s", paths[i]);
		close(fd);
	}
}

static void nft_delete_managed_tables(void)
{
	char *const inet_argv[] = {
		"nft", "delete", "table", "inet", AIRPORTAL_NFT_TABLE, NULL
	};
	char *const bridge_argv[] = {
		"nft", "delete", "table", "bridge", AIRPORTAL_NFT_BRIDGE_TABLE, NULL
	};

	run_nft_argv(inet_argv, NULL, true);
	run_nft_argv(bridge_argv, NULL, true);
}

static int nft_set_client_element(const char *op,
				  const struct airportal_client *client,
				  bool quiet)
{
	char mac[18];
	char script[256];

	airportal_format_mac(client->key.mac, mac, sizeof(mac));
	snprintf(script, sizeof(script),
		 "%s element inet " AIRPORTAL_NFT_TABLE " captive_macs { %s }\n",
		 op, mac);
	if (quiet)
		return run_nft_script_quiet(script);
	return run_nft_script(script);
}

static void build_walled_ipv4_elements(const struct airportal_config *config,
				       char *buf, size_t buf_len)
{
	struct in_addr addr;
	size_t used = 0;
	size_t i;
	bool first = true;

	if (!buf || buf_len == 0)
		return;
	buf[0] = '\0';
	if (!config)
		return;

	for (i = 0; i < config->walled_garden_count; i++) {
		const struct airportal_walled_garden_config *wg =
			&config->walled_gardens[i];
		int n;

		if (strcmp(wg->type, "ip") != 0 ||
		    inet_pton(AF_INET, wg->value, &addr) != 1)
			continue;
		n = snprintf(buf + used, buf_len - used, "%s%s",
			     first ? "" : ", ", wg->value);
		if (n < 0)
			return;
		if ((size_t)n >= buf_len - used) {
			buf[buf_len - 1] = '\0';
			return;
		}
		used += (size_t)n;
		first = false;
	}
}

int nft_manager_init(struct nft_manager *mgr, bool dry_run)
{
	mgr->ready = false;
	mgr->dry_run = dry_run;
	mgr->portal_port = 0;
	return 0;
}

int nft_manager_install_base_rules(struct nft_manager *mgr,
				   const struct airportal_config *config,
				   uint16_t portal_port)
{
	char script[4096];
	char walled_ipv4[1024];

	mgr->portal_port = portal_port;
	build_walled_ipv4_elements(config, walled_ipv4, sizeof(walled_ipv4));
	if (!mgr->dry_run) {
		enable_bridge_netfilter();
		nft_delete_managed_tables();
		snprintf(script, sizeof(script),
			 "table inet " AIRPORTAL_NFT_TABLE " {\n"
			 "\tset captive_macs {\n"
			 "\t\ttype ether_addr\n"
			 "\t}\n"
			 "\tset walled_ipv4 {\n"
			 "\t\ttype ipv4_addr\n"
			 "\t\telements = { %s }\n"
			 "\t}\n"
			 "\tchain prerouting {\n"
			 "\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
			 "\t\tether saddr @captive_macs tcp dport 80 counter redirect to :%u\n"
			 "\t}\n"
			 "\tchain forward {\n"
			 "\t\ttype filter hook forward priority filter; policy accept;\n"
			 "\t\tether saddr @captive_macs ip daddr @walled_ipv4 counter accept\n"
			 "\t\tether saddr @captive_macs udp dport { 53, 67, 68 } counter accept\n"
			 "\t\tether saddr @captive_macs tcp dport 53 counter accept\n"
			 "\t\tether saddr @captive_macs counter drop\n"
			 "\t}\n"
			 "}\n",
			 walled_ipv4, portal_port);
		if (run_nft_script(script) != 0) {
			ap_log_error("nft_base_rules_failed table=inet_%s port=%u",
				     AIRPORTAL_NFT_TABLE, portal_port);
			return -1;
		}
	}

	mgr->ready = true;
	ap_log_info("nft_base_rules_ready table=inet_%s mode=%s port=%u bridge_nf=enabled",
		    AIRPORTAL_NFT_TABLE,
		    mgr->dry_run ? "dry_run" : "native", portal_port);
	return 0;
}

int nft_manager_add_captive_client(struct nft_manager *mgr,
				   const struct airportal_client *client)
{
	if (!mgr->ready || !client)
		return -1;
	log_client_action("add_captive_client", client);
	if (!mgr->dry_run && nft_set_client_element("add", client, false) != 0)
		return -1;
	return 0;
}

int nft_manager_authorize_client(struct nft_manager *mgr,
				 const struct airportal_client *client,
				 uint32_t timeout_sec)
{
	if (!mgr->ready || !client)
		return -1;
	(void)timeout_sec;
	log_client_action("authorize_client", client);
	if (!mgr->dry_run)
		nft_set_client_element("delete", client, true);
	return 0;
}

int nft_manager_block_client(struct nft_manager *mgr,
			     const struct airportal_client *client)
{
	if (!mgr->ready || !client)
		return -1;
	log_client_action("block_client", client);
	if (!mgr->dry_run && nft_set_client_element("add", client, false) != 0)
		return -1;
	return 0;
}

int nft_manager_remove_client(struct nft_manager *mgr,
			      const struct airportal_client *client)
{
	if (!mgr->ready || !client)
		return -1;
	log_client_action("remove_client", client);
	if (!mgr->dry_run)
		nft_set_client_element("delete", client, true);
	return 0;
}

int nft_manager_flush_managed_state(struct nft_manager *mgr)
{
	if (!mgr->ready)
		return 0;
	if (!mgr->dry_run)
		nft_delete_managed_tables();
	ap_log_info("nft_flush_managed_state table=inet_%s", AIRPORTAL_NFT_TABLE);
	mgr->ready = false;
	return 0;
}
