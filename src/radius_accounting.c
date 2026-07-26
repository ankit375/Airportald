#include "radius_accounting.h"

#include "airportal.h"
#include "log.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RADIUS_CODE_ACCOUNTING_REQUEST 4
#define RADIUS_CODE_ACCOUNTING_RESPONSE 5

#define RADIUS_ATTR_USER_NAME 1
#define RADIUS_ATTR_SERVICE_TYPE 6
#define RADIUS_ATTR_FRAMED_MTU 12
#define RADIUS_ATTR_CLASS 25
#define RADIUS_ATTR_CALLED_STATION_ID 30
#define RADIUS_ATTR_CALLING_STATION_ID 31
#define RADIUS_ATTR_NAS_IDENTIFIER 32
#define RADIUS_ATTR_ACCT_STATUS_TYPE 40
#define RADIUS_ATTR_ACCT_INPUT_OCTETS 42
#define RADIUS_ATTR_ACCT_OUTPUT_OCTETS 43
#define RADIUS_ATTR_ACCT_SESSION_ID 44
#define RADIUS_ATTR_ACCT_SESSION_TIME 46
#define RADIUS_ATTR_ACCT_TERMINATE_CAUSE 49
#define RADIUS_ATTR_NAS_PORT_TYPE 61

#define RADIUS_ACCT_STATUS_START 1
#define RADIUS_ACCT_STATUS_STOP 2
#define RADIUS_ACCT_STATUS_INTERIM_UPDATE 3
#define RADIUS_ACCT_TERMINATE_USER_REQUEST 1
#define RADIUS_ACCT_TERMINATE_SESSION_TIMEOUT 5
#define RADIUS_ACCT_TERMINATE_ADMIN_RESET 6
#define RADIUS_SERVICE_TYPE_LOGIN 1
#define RADIUS_NAS_PORT_TYPE_WIRELESS_80211 19
#define RADIUS_PACKET_MAX 4096
#define RADIUS_AUTHENTICATOR_LEN 16

struct radius_acct_packet {
	uint8_t code;
	uint8_t id;
	uint8_t authenticator[RADIUS_AUTHENTICATOR_LEN];
	uint8_t attrs[RADIUS_PACKET_MAX - 20];
	size_t attr_len;
};

int radius_accounting_init(struct airportal_daemon *daemon)
{
	(void)daemon;
	return 0;
}

void radius_accounting_shutdown(struct airportal_daemon *daemon)
{
	(void)daemon;
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

static bool packet_add_attr(struct radius_acct_packet *packet, uint8_t type,
			    const void *data, size_t len)
{
	uint8_t *p;

	if (len > 253 || packet->attr_len + len + 2 > sizeof(packet->attrs))
		return false;
	p = packet->attrs + packet->attr_len;
	p[0] = type;
	p[1] = (uint8_t)(len + 2);
	if (len)
		memcpy(p + 2, data, len);
	packet->attr_len += len + 2;
	return true;
}

static bool packet_add_string(struct radius_acct_packet *packet, uint8_t type,
			      const char *value)
{
	if (!value)
		value = "";
	return packet_add_attr(packet, type, value, strlen(value));
}

static bool packet_add_u32(struct radius_acct_packet *packet, uint8_t type,
			   uint32_t value)
{
	uint32_t be = htonl(value);

	return packet_add_attr(packet, type, &be, sizeof(be));
}

static size_t packet_serialize(struct radius_acct_packet *packet,
			       const char *secret, uint8_t *out, size_t out_len)
{
	uint16_t len = htons((uint16_t)(20 + packet->attr_len));
	uint8_t zeros[RADIUS_AUTHENTICATOR_LEN] = { 0 };

	if (out_len < 20 + packet->attr_len)
		return 0;
	out[0] = packet->code;
	out[1] = packet->id;
	memcpy(out + 2, &len, sizeof(len));
	memcpy(out + 4, zeros, sizeof(zeros));
	memcpy(out + 20, packet->attrs, packet->attr_len);
	if (!md5_parts(out, 20 + packet->attr_len,
		       (const uint8_t *)secret, strlen(secret),
		       NULL, 0, packet->authenticator))
		return 0;
	memcpy(out + 4, packet->authenticator, RADIUS_AUTHENTICATOR_LEN);
	return 20 + packet->attr_len;
}

static int connect_radius_socket(const struct airportal_radius_config *radius)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	char port[16];
	int fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_family = AF_UNSPEC;
	snprintf(port, sizeof(port), "%u", radius->acct_port);
	if (getaddrinfo(radius->acct_server, port, &hints, &res) != 0)
		return -1;

	for (ai = res; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
			    ai->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

static bool verify_response_authenticator(const uint8_t *response, size_t len,
					  const uint8_t request_auth[RADIUS_AUTHENTICATOR_LEN],
					  const char *secret)
{
	uint8_t copy[RADIUS_PACKET_MAX];
	uint8_t digest[RADIUS_AUTHENTICATOR_LEN];

	if (len > sizeof(copy) || len < 20)
		return false;
	memcpy(copy, response, len);
	memcpy(copy + 4, request_auth, RADIUS_AUTHENTICATOR_LEN);
	if (!md5_parts(copy, len, (const uint8_t *)secret, strlen(secret),
		       NULL, 0, digest))
		return false;
	return memcmp(digest, response + 4, RADIUS_AUTHENTICATOR_LEN) == 0;
}

static const struct airportal_radius_config *
session_radius_profile(struct airportal_daemon *daemon,
		       const struct airportal_session *session)
{
	const struct airportal_portal_config *portal;

	if (!session || !session->client)
		return NULL;
	portal = airportal_config_find_portal_by_id(&daemon->config,
						    session->client->key.portal_id);
	if (!portal || strcmp(portal->auth_mode, "radius") != 0)
		return NULL;
	return airportal_config_find_radius_by_name(&daemon->config,
						    portal->radius_profile);
}

static uint32_t terminate_cause_for_reason(const char *reason)
{
	if (reason && strcmp(reason, "session_timeout") == 0)
		return RADIUS_ACCT_TERMINATE_SESSION_TIMEOUT;
	if (reason && strcmp(reason, "admin_disconnect") == 0)
		return RADIUS_ACCT_TERMINATE_ADMIN_RESET;
	return RADIUS_ACCT_TERMINATE_USER_REQUEST;
}

static bool build_accounting_request(struct airportal_daemon *daemon,
				     const struct airportal_radius_config *radius,
				     const struct airportal_session *session,
				     uint32_t status_type, const char *reason,
				     struct radius_acct_packet *packet)
{
	char mac[18];
	uint64_t now = airportal_monotonic_ms();
	uint32_t elapsed = 0;

	memset(packet, 0, sizeof(*packet));
	packet->code = RADIUS_CODE_ACCOUNTING_REQUEST;
	if (RAND_bytes(&packet->id, sizeof(packet->id)) != 1)
		return false;

	airportal_format_mac(session->client->key.mac, mac, sizeof(mac));
	if (now > session->started_at_ms)
		elapsed = (uint32_t)((now - session->started_at_ms) / 1000u);

	if (!packet_add_string(packet, RADIUS_ATTR_USER_NAME,
			       session->client->username) ||
	    !packet_add_string(packet, RADIUS_ATTR_ACCT_SESSION_ID,
			       session->session_id) ||
	    !packet_add_u32(packet, RADIUS_ATTR_ACCT_STATUS_TYPE, status_type) ||
	    !packet_add_string(packet, RADIUS_ATTR_CALLING_STATION_ID, mac) ||
	    !packet_add_string(packet, RADIUS_ATTR_CALLED_STATION_ID,
			       session->client->bssid[0] ?
			       session->client->bssid : session->client->ifname) ||
	    !packet_add_string(packet, RADIUS_ATTR_NAS_IDENTIFIER,
			       radius->nas_identifier[0] ?
			       radius->nas_identifier :
			       daemon->config.global.device_id) ||
	    !packet_add_u32(packet, RADIUS_ATTR_SERVICE_TYPE,
			    RADIUS_SERVICE_TYPE_LOGIN) ||
	    !packet_add_u32(packet, RADIUS_ATTR_NAS_PORT_TYPE,
			    RADIUS_NAS_PORT_TYPE_WIRELESS_80211) ||
	    !packet_add_u32(packet, RADIUS_ATTR_FRAMED_MTU, 1500))
		return false;

	if (session->policy.radius_class[0] &&
	    !packet_add_string(packet, RADIUS_ATTR_CLASS,
			       session->policy.radius_class))
		return false;
	if (status_type == RADIUS_ACCT_STATUS_STOP ||
	    status_type == RADIUS_ACCT_STATUS_INTERIM_UPDATE) {
		if (!packet_add_u32(packet, RADIUS_ATTR_ACCT_INPUT_OCTETS,
				    (uint32_t)session->input_octets) ||
		    !packet_add_u32(packet, RADIUS_ATTR_ACCT_OUTPUT_OCTETS,
				    (uint32_t)session->output_octets) ||
		    !packet_add_u32(packet, RADIUS_ATTR_ACCT_SESSION_TIME,
				    elapsed))
			return false;
	}
	if (status_type == RADIUS_ACCT_STATUS_STOP) {
		if (!packet_add_u32(packet, RADIUS_ATTR_ACCT_TERMINATE_CAUSE,
				    terminate_cause_for_reason(reason)))
			return false;
	}
	return true;
}

static int send_accounting(struct airportal_daemon *daemon,
			   const struct airportal_session *session,
			   uint32_t status_type, const char *reason)
{
	const struct airportal_radius_config *radius;
	struct radius_acct_packet packet;
	uint8_t request[RADIUS_PACKET_MAX];
	uint8_t response[RADIUS_PACKET_MAX];
	char secret[256];
	size_t request_len;
	uint32_t attempts;
	int fd;
	int rc = -1;

	radius = session_radius_profile(daemon, session);
	if (!radius)
		return 0;
	if (read_secret(radius->secret_file, secret, sizeof(secret)) != 0)
		return -1;
	if (!build_accounting_request(daemon, radius, session, status_type,
				      reason, &packet))
		return -1;
	request_len = packet_serialize(&packet, secret, request, sizeof(request));
	if (request_len == 0)
		return -1;
	fd = connect_radius_socket(radius);
	if (fd < 0)
		return -1;

	for (attempts = 0; attempts < radius->retry_count; attempts++) {
		struct pollfd pfd;
		uint16_t response_len;
		ssize_t n;

		if (send(fd, request, request_len, 0) != (ssize_t)request_len)
			break;
		memset(&pfd, 0, sizeof(pfd));
		pfd.fd = fd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, (int)radius->timeout_ms) <= 0)
			continue;
		n = recv(fd, response, sizeof(response), 0);
		if (n < 20 || response[0] != RADIUS_CODE_ACCOUNTING_RESPONSE ||
		    response[1] != packet.id)
			continue;
		memcpy(&response_len, response + 2, sizeof(response_len));
		if (ntohs(response_len) != (uint16_t)n)
			continue;
		if (!verify_response_authenticator(response, (size_t)n,
						   packet.authenticator, secret))
			continue;
		rc = 0;
		break;
	}

	close(fd);
	return rc;
}

int radius_accounting_start(struct airportal_daemon *daemon,
			    const struct airportal_session *session)
{
	int rc = send_accounting(daemon, session, RADIUS_ACCT_STATUS_START, NULL);

	if (rc == 0 && session)
		ap_log_info("radius_accounting_start session_id=%s", session->session_id);
	return rc;
}

int radius_accounting_interim_update(struct airportal_daemon *daemon,
				     const struct airportal_session *session)
{
	int rc = send_accounting(daemon, session,
				 RADIUS_ACCT_STATUS_INTERIM_UPDATE, NULL);

	if (rc == 0 && session)
		ap_log_info("radius_accounting_interim_update session_id=%s",
			    session->session_id);
	return rc;
}

int radius_accounting_stop(struct airportal_daemon *daemon,
			   const struct airportal_session *session,
			   const char *reason)
{
	int rc = send_accounting(daemon, session, RADIUS_ACCT_STATUS_STOP, reason);

	if (rc == 0 && session)
		ap_log_info("radius_accounting_stop session_id=%s reason=%s",
			    session->session_id, reason ? reason : "unknown");
	return rc;
}
