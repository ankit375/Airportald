#include "coa_server.h"

#include "airportal.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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
#define RADIUS_ATTR_ACCT_SESSION_ID 44
#define RADIUS_ATTR_ERROR_CAUSE 101
#define RADIUS_ATTR_CALLING_STATION_ID 31

#define RADIUS_ERROR_CAUSE_UNSUPPORTED_SERVICE 405
#define RADIUS_ERROR_CAUSE_SESSION_CONTEXT_NOT_FOUND 503
#define RADIUS_PACKET_MAX 4096
#define RADIUS_AUTHENTICATOR_LEN 16

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

static const struct airportal_radius_config *
coa_radius_profile(const struct airportal_config *config)
{
	size_t i;

	for (i = 0; i < config->radius_count; i++) {
		if (config->radius[i].coa_port == config->global.coa_port)
			return &config->radius[i];
	}
	return config->radius_count ? &config->radius[0] : NULL;
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
	uint8_t response[RADIUS_PACKET_MAX];
	char secret[256];
	uint8_t response_code;
	uint32_t error_cause = 0;
	const char *message = NULL;
	ssize_t response_len;

	radius = coa_radius_profile(&daemon->config);
	if (!radius || read_secret(radius->secret_file, secret, sizeof(secret)) != 0)
		return;
	if (!parse_coa_request(packet, packet_len, &request) ||
	    !verify_request_authenticator(packet, packet_len, secret))
		return;

	daemon->metrics.coa_requests++;
	if (request.code == RADIUS_CODE_COA_REQUEST) {
		response_code = RADIUS_CODE_COA_NAK;
		error_cause = RADIUS_ERROR_CAUSE_UNSUPPORTED_SERVICE;
		message = "CoA-Request not supported";
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
