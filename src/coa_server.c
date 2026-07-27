#include "coa_server.h"

#include "airportal.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RADIUS_CODE_DISCONNECT_REQUEST 40
#define RADIUS_CODE_DISCONNECT_ACK 41
#define RADIUS_CODE_DISCONNECT_NAK 42
#define RADIUS_CODE_COA_REQUEST 43
#define RADIUS_CODE_COA_ACK 44
#define RADIUS_CODE_COA_NAK 45

#define RADIUS_ATTR_USER_NAME 1
#define RADIUS_ATTR_REPLY_MESSAGE 18
#define RADIUS_ATTR_FILTER_ID 11
#define RADIUS_ATTR_CLASS 25
#define RADIUS_ATTR_VENDOR_SPECIFIC 26
#define RADIUS_ATTR_SESSION_TIMEOUT 27
#define RADIUS_ATTR_IDLE_TIMEOUT 28
#define RADIUS_ATTR_ACCT_SESSION_ID 44
#define RADIUS_ATTR_ERROR_CAUSE 101
#define RADIUS_ATTR_CALLING_STATION_ID 31

#define RADIUS_ERROR_CAUSE_UNSUPPORTED_SERVICE 405
#define RADIUS_ERROR_CAUSE_SESSION_CONTEXT_NOT_FOUND 503
#define RADIUS_ERROR_CAUSE_INVALID_REQUEST 506
#define RADIUS_PACKET_MAX 4096
#define RADIUS_AUTHENTICATOR_LEN 16

#define RADIUS_VENDOR_WISPR 14122
#define RADIUS_VENDOR_CHILLISPOT 14559
#define WISPR_BANDWIDTH_MAX_UP 7
#define WISPR_BANDWIDTH_MAX_DOWN 8
#define CHILLISPOT_MAX_INPUT_OCTETS 1
#define CHILLISPOT_MAX_OUTPUT_OCTETS 2
#define CHILLISPOT_MAX_TOTAL_OCTETS 3
#define CHILLISPOT_BANDWIDTH_MAX_UP 4
#define CHILLISPOT_BANDWIDTH_MAX_DOWN 5

struct coa_server_state {
	int fd;
	ev_io watcher;
	struct airportal_daemon *daemon;
};

struct coa_request {
	uint8_t code;
	uint8_t id;
	uint16_t length;
	uint8_t authenticator[RADIUS_AUTHENTICATOR_LEN];
	const uint8_t *attrs;
	size_t attr_len;
	char session_id[96];
	uint8_t mac[6];
	bool has_mac;
	struct airportal_session_policy policy;
	bool has_session_timeout;
	bool has_idle_timeout;
	bool has_filter_id;
	bool has_class;
	bool has_max_input_octets;
	bool has_max_output_octets;
	bool has_max_total_octets;
	bool has_max_upload_bps;
	bool has_max_download_bps;
	bool has_policy_update;
};

static void set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags >= 0)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static bool md5_parts(const uint8_t *a, size_t a_len,
		      const uint8_t *b, size_t b_len,
		      const uint8_t *c, size_t c_len,
		      uint8_t out[RADIUS_AUTHENTICATOR_LEN])
{
	EVP_MD_CTX *ctx;
	unsigned int len = 0;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return false;
	if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1 ||
	    EVP_DigestUpdate(ctx, a, a_len) != 1 ||
	    EVP_DigestUpdate(ctx, b, b_len) != 1 ||
	    (c_len && EVP_DigestUpdate(ctx, c, c_len) != 1) ||
	    EVP_DigestFinal_ex(ctx, out, &len) != 1) {
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	return len == RADIUS_AUTHENTICATOR_LEN;
}

static int read_secret(const char *path, char *secret, size_t secret_len)
{
	FILE *fp;
	size_t n;

	if (!path || !path[0] || !secret || secret_len == 0)
		return -1;
	fp = fopen(path, "r");
	if (!fp)
		return -1;
	n = fread(secret, 1, secret_len - 1, fp);
	fclose(fp);
	while (n > 0 && (secret[n - 1] == '\n' || secret[n - 1] == '\r' ||
			 secret[n - 1] == ' ' || secret[n - 1] == '\t'))
		n--;
	secret[n] = '\0';
	return n > 0 ? 0 : -1;
}

static bool sockaddr_to_ip(const struct sockaddr *addr, char *buf, size_t len)
{
	if (!addr || !buf || len == 0)
		return false;
	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;

		return inet_ntop(AF_INET, &sin->sin_addr, buf, len) != NULL;
	}
	if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;

		return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, len) != NULL;
	}
	return false;
}

static bool radius_host_matches_peer(const char *host, const char *peer_ip)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	bool matched = false;

	if (!host || !host[0] || !peer_ip || !peer_ip[0])
		return false;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_family = AF_UNSPEC;
	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		return false;
	for (ai = res; ai; ai = ai->ai_next) {
		char addr[INET6_ADDRSTRLEN];

		if (!sockaddr_to_ip(ai->ai_addr, addr, sizeof(addr)))
			continue;
		if (strcmp(addr, peer_ip) == 0) {
			matched = true;
			break;
		}
	}
	freeaddrinfo(res);
	return matched;
}

static const struct airportal_radius_config *
coa_radius_profile(const struct airportal_config *config,
		   const struct sockaddr *peer)
{
	size_t i;
	char peer_ip[INET6_ADDRSTRLEN];

	if (!sockaddr_to_ip(peer, peer_ip, sizeof(peer_ip)))
		return NULL;
	for (i = 0; i < config->radius_count; i++) {
		const struct airportal_radius_config *radius = &config->radius[i];

		if (radius->coa_port != config->global.coa_port)
			continue;
		if (radius_host_matches_peer(radius->auth_server, peer_ip) ||
		    radius_host_matches_peer(radius->acct_server, peer_ip))
			return &config->radius[i];
	}
	ap_log_warn("coa_source_rejected peer=%s", peer_ip);
	return NULL;
}

static bool verify_request_authenticator(const uint8_t *packet, size_t len,
					 const char *secret)
{
	uint8_t copy[RADIUS_PACKET_MAX];
	uint8_t digest[RADIUS_AUTHENTICATOR_LEN];
	uint8_t zeros[RADIUS_AUTHENTICATOR_LEN] = { 0 };

	if (len > sizeof(copy) || len < 20)
		return false;
	memcpy(copy, packet, len);
	memcpy(copy + 4, zeros, sizeof(zeros));
	if (!md5_parts(copy, len, (const uint8_t *)secret, strlen(secret),
		       NULL, 0, digest))
		return false;
	return memcmp(digest, packet + 4, RADIUS_AUTHENTICATOR_LEN) == 0;
}

static void copy_text_attr(char *dst, size_t dst_len,
			   const uint8_t *src, size_t src_len)
{
	size_t len;

	if (!dst || dst_len == 0)
		return;
	len = src_len < dst_len - 1 ? src_len : dst_len - 1;
	memcpy(dst, src, len);
	dst[len] = '\0';
}

static bool parse_coa_request(const uint8_t *packet, size_t packet_len,
			      struct coa_request *request)
{
	size_t offset = 20;
	uint16_t len;

	if (packet_len < 20)
		return false;
	memcpy(&len, packet + 2, sizeof(len));
	len = ntohs(len);
	if (len != packet_len)
		return false;

	memset(request, 0, sizeof(*request));
	request->code = packet[0];
	request->id = packet[1];
	request->length = len;
	memcpy(request->authenticator, packet + 4, RADIUS_AUTHENTICATOR_LEN);
	request->attrs = packet + 20;
	request->attr_len = packet_len - 20;

	while (offset + 2 <= packet_len) {
		uint8_t type = packet[offset];
		uint8_t attr_len = packet[offset + 1];
		const uint8_t *value;
		size_t value_len;
		char text[128];

		if (attr_len < 2 || offset + attr_len > packet_len)
			return false;
		value = packet + offset + 2;
		value_len = attr_len - 2;
		if (type == RADIUS_ATTR_ACCT_SESSION_ID) {
			copy_text_attr(request->session_id, sizeof(request->session_id),
				       value, value_len);
		} else if (type == RADIUS_ATTR_CALLING_STATION_ID) {
			copy_text_attr(text, sizeof(text), value, value_len);
			request->has_mac = airportal_parse_mac(text, request->mac);
		}
		offset += attr_len;
	}
	return true;
}

static void request_set_u32(struct coa_request *request, uint8_t type,
			    uint32_t value)
{
	if (type == RADIUS_ATTR_SESSION_TIMEOUT) {
		request->policy.session_timeout_sec = value;
		request->has_session_timeout = true;
	} else if (type == RADIUS_ATTR_IDLE_TIMEOUT) {
		request->policy.idle_timeout_sec = value;
		request->has_idle_timeout = true;
	}
	request->has_policy_update = true;
}

static void request_set_vendor_u32(struct coa_request *request,
				   uint32_t vendor_id, uint8_t type,
				   uint32_t value)
{
	if (vendor_id == RADIUS_VENDOR_CHILLISPOT) {
		if (type == CHILLISPOT_MAX_INPUT_OCTETS) {
			request->policy.max_input_octets = value;
			request->has_max_input_octets = true;
		} else if (type == CHILLISPOT_MAX_OUTPUT_OCTETS) {
			request->policy.max_output_octets = value;
			request->has_max_output_octets = true;
		} else if (type == CHILLISPOT_MAX_TOTAL_OCTETS) {
			request->policy.max_total_octets = value;
			request->has_max_total_octets = true;
		} else if (type == CHILLISPOT_BANDWIDTH_MAX_UP) {
			request->policy.max_upload_bps = value;
			request->has_max_upload_bps = true;
		} else if (type == CHILLISPOT_BANDWIDTH_MAX_DOWN) {
			request->policy.max_download_bps = value;
			request->has_max_download_bps = true;
		} else {
			return;
		}
	} else if (vendor_id == RADIUS_VENDOR_WISPR) {
		if (type == WISPR_BANDWIDTH_MAX_UP) {
			request->policy.max_upload_bps = value;
			request->has_max_upload_bps = true;
		} else if (type == WISPR_BANDWIDTH_MAX_DOWN) {
			request->policy.max_download_bps = value;
			request->has_max_download_bps = true;
		} else {
			return;
		}
	} else {
		return;
	}
	request->has_policy_update = true;
}

static void parse_coa_vendor_attrs(struct coa_request *request,
				   uint32_t vendor_id, const uint8_t *attrs,
				   size_t len)
{
	size_t offset = 0;

	while (offset + 2 <= len) {
		uint8_t type = attrs[offset];
		uint8_t attr_len = attrs[offset + 1];
		const uint8_t *value;
		uint32_t u32;

		if (attr_len < 2 || offset + attr_len > len)
			break;
		value = attrs + offset + 2;
		if (attr_len - 2 == 4) {
			memcpy(&u32, value, sizeof(u32));
			request_set_vendor_u32(request, vendor_id, type,
					       ntohl(u32));
		}
		offset += attr_len;
	}
}

static void parse_coa_policy_attrs(struct coa_request *request)
{
	size_t offset = 0;

	while (offset + 2 <= request->attr_len) {
		uint8_t type = request->attrs[offset];
		uint8_t attr_len = request->attrs[offset + 1];
		const uint8_t *value;
		size_t value_len;
		uint32_t u32;

		if (attr_len < 2 || offset + attr_len > request->attr_len)
			break;
		value = request->attrs + offset + 2;
		value_len = attr_len - 2;
		if (value_len == 4 &&
		    (type == RADIUS_ATTR_SESSION_TIMEOUT ||
		     type == RADIUS_ATTR_IDLE_TIMEOUT)) {
			memcpy(&u32, value, sizeof(u32));
			request_set_u32(request, type, ntohl(u32));
		} else if (type == RADIUS_ATTR_FILTER_ID) {
			copy_text_attr(request->policy.filter_id,
				       sizeof(request->policy.filter_id),
				       value, value_len);
			request->has_filter_id = true;
			request->has_policy_update = true;
		} else if (type == RADIUS_ATTR_CLASS) {
			copy_text_attr(request->policy.radius_class,
				       sizeof(request->policy.radius_class),
				       value, value_len);
			request->has_class = true;
			request->has_policy_update = true;
		} else if (type == RADIUS_ATTR_VENDOR_SPECIFIC &&
			   value_len >= 6) {
			uint32_t vendor_id;

			memcpy(&vendor_id, value, sizeof(vendor_id));
			parse_coa_vendor_attrs(request, ntohl(vendor_id),
					       value + 4, value_len - 4);
		}
		offset += attr_len;
	}
}

static void merge_policy_update(struct airportal_session_policy *dst,
				const struct coa_request *request)
{
	if (request->has_session_timeout)
		dst->session_timeout_sec = request->policy.session_timeout_sec;
	if (request->has_idle_timeout)
		dst->idle_timeout_sec = request->policy.idle_timeout_sec;
	if (request->has_filter_id)
		snprintf(dst->filter_id, sizeof(dst->filter_id), "%s",
			 request->policy.filter_id);
	if (request->has_class)
		snprintf(dst->radius_class, sizeof(dst->radius_class), "%s",
			 request->policy.radius_class);
	if (request->has_max_input_octets)
		dst->max_input_octets = request->policy.max_input_octets;
	if (request->has_max_output_octets)
		dst->max_output_octets = request->policy.max_output_octets;
	if (request->has_max_total_octets)
		dst->max_total_octets = request->policy.max_total_octets;
	if (request->has_max_upload_bps)
		dst->max_upload_bps = request->policy.max_upload_bps;
	if (request->has_max_download_bps)
		dst->max_download_bps = request->policy.max_download_bps;
}

static bool response_add_attr(uint8_t *attrs, size_t *attr_len,
			      uint8_t type, const void *data, size_t len)
{
	uint8_t *p;

	if (len > 253 || *attr_len + len + 2 > RADIUS_PACKET_MAX - 20)
		return false;
	p = attrs + *attr_len;
	p[0] = type;
	p[1] = (uint8_t)(len + 2);
	if (len)
		memcpy(p + 2, data, len);
	*attr_len += len + 2;
	return true;
}

static bool response_add_text(uint8_t *attrs, size_t *attr_len,
			      uint8_t type, const char *value)
{
	return response_add_attr(attrs, attr_len, type, value, strlen(value));
}

static bool response_add_u32(uint8_t *attrs, size_t *attr_len,
			     uint8_t type, uint32_t value)
{
	uint32_t be = htonl(value);

	return response_add_attr(attrs, attr_len, type, &be, sizeof(be));
}

static ssize_t build_response(uint8_t code, const struct coa_request *request,
			      const char *secret, uint8_t *out, size_t out_len,
			      uint32_t error_cause, const char *message)
{
	uint8_t attrs[RADIUS_PACKET_MAX - 20];
	uint8_t digest[RADIUS_AUTHENTICATOR_LEN];
	size_t attr_len = 0;
	uint16_t len;

	if (message && !response_add_text(attrs, &attr_len,
					  RADIUS_ATTR_REPLY_MESSAGE, message))
		return -1;
	if (error_cause &&
	    !response_add_u32(attrs, &attr_len, RADIUS_ATTR_ERROR_CAUSE,
			      error_cause))
		return -1;
	if (out_len < 20 + attr_len)
		return -1;

	len = htons((uint16_t)(20 + attr_len));
	out[0] = code;
	out[1] = request->id;
	memcpy(out + 2, &len, sizeof(len));
	memcpy(out + 4, request->authenticator, RADIUS_AUTHENTICATOR_LEN);
	memcpy(out + 20, attrs, attr_len);
	if (!md5_parts(out, 20 + attr_len, (const uint8_t *)secret,
		       strlen(secret), NULL, 0, digest))
		return -1;
	memcpy(out + 4, digest, RADIUS_AUTHENTICATOR_LEN);
	return (ssize_t)(20 + attr_len);
}

static struct airportal_client *
find_client_for_request(struct airportal_daemon *daemon,
			const struct coa_request *request)
{
	size_t i;

	if (request->session_id[0]) {
		struct airportal_session *session =
			airportal_session_find_by_id(&daemon->sessions,
						     request->session_id);

		if (session)
			return session->client;
	}
	if (!request->has_mac)
		return NULL;

	for (i = 0; i < AIRPORTAL_MAX_CLIENTS; i++) {
		struct airportal_client *client = &daemon->clients.clients[i];

		if (!daemon->clients.used[i])
			continue;
		if (memcmp(client->key.mac, request->mac, sizeof(request->mac)) == 0)
			return client;
	}
	return NULL;
}

static void handle_coa_packet(struct coa_server_state *state,
			      const uint8_t *packet, size_t packet_len,
			      const struct sockaddr *peer, socklen_t peer_len)
{
	struct airportal_daemon *daemon = state->daemon;
	const struct airportal_radius_config *radius;
	struct coa_request request;
	struct airportal_client *client;
	struct airportal_session *session;
	struct airportal_session_policy policy;
	uint8_t response[RADIUS_PACKET_MAX];
	char secret[256];
	uint8_t response_code;
	uint32_t error_cause = 0;
	const char *message = NULL;
	ssize_t response_len;

	radius = coa_radius_profile(&daemon->config, peer);
	if (!radius || read_secret(radius->secret_file, secret, sizeof(secret)) != 0)
		return;
	if (!parse_coa_request(packet, packet_len, &request) ||
	    !verify_request_authenticator(packet, packet_len, secret))
		return;
	parse_coa_policy_attrs(&request);

	daemon->metrics.coa_requests++;
	if (request.code == RADIUS_CODE_COA_REQUEST) {
		client = find_client_for_request(daemon, &request);
		session = client ?
			airportal_session_find_by_client(&daemon->sessions,
							 client) : NULL;
		if (!client || !session) {
			response_code = RADIUS_CODE_COA_NAK;
			error_cause = RADIUS_ERROR_CAUSE_SESSION_CONTEXT_NOT_FOUND;
			message = "session context not found";
		} else if (!request.has_policy_update) {
			response_code = RADIUS_CODE_COA_NAK;
			error_cause = RADIUS_ERROR_CAUSE_INVALID_REQUEST;
			message = "no supported policy attributes";
		} else {
			policy = session->policy;
			merge_policy_update(&policy, &request);
			if (airportal_update_client_policy(daemon, client, &policy,
							   "coa_update") != 0) {
				response_code = RADIUS_CODE_COA_NAK;
				error_cause =
					RADIUS_ERROR_CAUSE_SESSION_CONTEXT_NOT_FOUND;
				message = "policy update failed";
			} else {
				response_code = RADIUS_CODE_COA_ACK;
				ap_log_info("coa_update_ack session_id=%s ifname=%s portal_id=%u",
					    session->session_id, client->ifname,
					    client->key.portal_id);
			}
		}
	} else if (request.code != RADIUS_CODE_DISCONNECT_REQUEST) {
		return;
	} else {
		client = find_client_for_request(daemon, &request);
		if (!client) {
			response_code = RADIUS_CODE_DISCONNECT_NAK;
			error_cause = RADIUS_ERROR_CAUSE_SESSION_CONTEXT_NOT_FOUND;
			message = "session context not found";
		} else if (airportal_disconnect_client(daemon, client->key.mac,
						       client->ifname,
						       client->key.portal_id,
						       "coa_disconnect") != 0) {
			response_code = RADIUS_CODE_DISCONNECT_NAK;
			error_cause = RADIUS_ERROR_CAUSE_SESSION_CONTEXT_NOT_FOUND;
			message = "disconnect failed";
		} else {
			response_code = RADIUS_CODE_DISCONNECT_ACK;
			ap_log_info("coa_disconnect_ack ifname=%s portal_id=%u",
				    client->ifname, client->key.portal_id);
		}
	}

	response_len = build_response(response_code, &request, secret, response,
				      sizeof(response), error_cause, message);
	if (response_len > 0)
		sendto(state->fd, response, (size_t)response_len, 0,
		       peer, peer_len);
}

static void coa_read_cb(EV_P_ ev_io *w, int revents)
{
	struct coa_server_state *state = (struct coa_server_state *)w->data;

	(void)loop;
	(void)revents;
	while (true) {
		uint8_t packet[RADIUS_PACKET_MAX];
		struct sockaddr_storage peer;
		socklen_t peer_len = sizeof(peer);
		ssize_t n;

		n = recvfrom(state->fd, packet, sizeof(packet), 0,
			     (struct sockaddr *)&peer, &peer_len);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			break;
		}
		handle_coa_packet(state, packet, (size_t)n,
				  (struct sockaddr *)&peer, peer_len);
	}
}

int coa_server_init(struct airportal_daemon *daemon)
{
	struct coa_server_state *state;
	struct sockaddr_in addr;

	state = calloc(1, sizeof(*state));
	if (!state)
		return -1;
	state->fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (state->fd < 0)
		goto fail;
	set_nonblocking(state->fd);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(daemon->config.global.coa_port);
	if (bind(state->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		goto fail;

	state->daemon = daemon;
	ev_io_init(&state->watcher, coa_read_cb, state->fd, EV_READ);
	state->watcher.data = state;
	ev_io_start(daemon->loop, &state->watcher);
	daemon->coa_server = state;
	ap_log_info("coa_server_ready port=%u", daemon->config.global.coa_port);
	return 0;

fail:
	if (state->fd >= 0)
		close(state->fd);
	free(state);
	return -1;
}

void coa_server_shutdown(struct airportal_daemon *daemon)
{
	struct coa_server_state *state =
		(struct coa_server_state *)daemon->coa_server;

	if (!state)
		return;
	ev_io_stop(daemon->loop, &state->watcher);
	close(state->fd);
	free(state);
	daemon->coa_server = NULL;
}
