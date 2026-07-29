#include "radius_client.h"

#include "airportal.h"
#include "log.h"
#include "radius_transport.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define RADIUS_CODE_ACCESS_REQUEST 1
#define RADIUS_CODE_ACCESS_ACCEPT 2
#define RADIUS_CODE_ACCESS_REJECT 3
#define RADIUS_CODE_ACCESS_CHALLENGE 11

#define RADIUS_ATTR_USER_NAME 1
#define RADIUS_ATTR_USER_PASSWORD 2
#define RADIUS_ATTR_SERVICE_TYPE 6
#define RADIUS_ATTR_FILTER_ID 11
#define RADIUS_ATTR_REPLY_MESSAGE 18
#define RADIUS_ATTR_FRAMED_MTU 12
#define RADIUS_ATTR_CLASS 25
#define RADIUS_ATTR_VENDOR_SPECIFIC 26
#define RADIUS_ATTR_SESSION_TIMEOUT 27
#define RADIUS_ATTR_IDLE_TIMEOUT 28
#define RADIUS_ATTR_CALLED_STATION_ID 30
#define RADIUS_ATTR_CALLING_STATION_ID 31
#define RADIUS_ATTR_NAS_IDENTIFIER 32
#define RADIUS_ATTR_NAS_PORT_TYPE 61

#define RADIUS_SERVICE_TYPE_LOGIN 1
#define RADIUS_NAS_PORT_TYPE_WIRELESS_80211 19
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

struct radius_packet {
	uint8_t code;
	uint8_t id;
	uint16_t length;
	uint8_t authenticator[RADIUS_AUTHENTICATOR_LEN];
	uint8_t attrs[RADIUS_PACKET_MAX - 20];
	size_t attr_len;
};

int radius_client_init(struct airportal_daemon *daemon)
{
	(void)daemon;
	return 0;
}

void radius_client_shutdown(struct airportal_daemon *daemon)
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

static bool packet_add_attr(struct radius_packet *packet, uint8_t type,
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

static bool packet_add_string(struct radius_packet *packet, uint8_t type,
			      const char *value)
{
	return packet_add_attr(packet, type, value, strlen(value));
}

static bool packet_add_u32(struct radius_packet *packet, uint8_t type,
			   uint32_t value)
{
	uint32_t be = htonl(value);

	return packet_add_attr(packet, type, &be, sizeof(be));
}

static bool encrypt_user_password(const char *password, const char *secret,
				  const uint8_t request_auth[RADIUS_AUTHENTICATOR_LEN],
				  uint8_t *out, size_t *out_len)
{
	uint8_t padded[128] = { 0 };
	uint8_t digest[RADIUS_AUTHENTICATOR_LEN];
	const uint8_t *prev = request_auth;
	size_t password_len;
	size_t padded_len;
	size_t secret_len = strlen(secret);
	size_t offset;

	password_len = strlen(password);
	if (password_len > sizeof(padded))
		password_len = sizeof(padded);
	memcpy(padded, password, password_len);
	padded_len = ((password_len + 15) / 16) * 16;
	if (padded_len == 0)
		padded_len = 16;

	for (offset = 0; offset < padded_len; offset += 16) {
		size_t i;

		if (!md5_parts((const uint8_t *)secret, secret_len, prev, 16,
			       NULL, 0, digest))
			return false;
		for (i = 0; i < 16; i++)
			out[offset + i] = padded[offset + i] ^ digest[i];
		prev = out + offset;
	}
	*out_len = padded_len;
	return true;
}

static bool packet_add_user_password(struct radius_packet *packet,
				     const char *password, const char *secret)
{
	uint8_t encrypted[128];
	size_t encrypted_len = 0;

	if (!encrypt_user_password(password, secret, packet->authenticator,
				   encrypted, &encrypted_len))
		return false;
	return packet_add_attr(packet, RADIUS_ATTR_USER_PASSWORD,
			       encrypted, encrypted_len);
}

static size_t packet_serialize(const struct radius_packet *packet,
			       uint8_t *out, size_t out_len)
{
	uint16_t len = htons((uint16_t)(20 + packet->attr_len));

	if (out_len < 20 + packet->attr_len)
		return 0;
	out[0] = packet->code;
	out[1] = packet->id;
	memcpy(out + 2, &len, sizeof(len));
	memcpy(out + 4, packet->authenticator, RADIUS_AUTHENTICATOR_LEN);
	memcpy(out + 20, packet->attrs, packet->attr_len);
	return 20 + packet->attr_len;
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

static void copy_radius_text(char *dst, size_t dst_len,
			     const uint8_t *src, size_t src_len)
{
	size_t len;

	if (!dst || dst_len == 0)
		return;
	len = src_len < dst_len - 1 ? src_len : dst_len - 1;
	memcpy(dst, src, len);
	dst[len] = '\0';
}

static void parse_vendor_attrs(uint32_t vendor_id, const uint8_t *attrs,
			       size_t len,
			       struct airportal_session_policy *policy)
{
	size_t offset = 0;

	while (offset + 2 <= len) {
		uint8_t type = attrs[offset];
		uint8_t attr_len = attrs[offset + 1];
		const uint8_t *value;
		size_t value_len;
		uint32_t u32;

		if (attr_len < 2 || offset + attr_len > len)
			break;
		value = attrs + offset + 2;
		value_len = attr_len - 2;
		if (value_len != 4) {
			offset += attr_len;
			continue;
		}

		memcpy(&u32, value, sizeof(u32));
		u32 = ntohl(u32);
		if (vendor_id == RADIUS_VENDOR_CHILLISPOT) {
			if (type == CHILLISPOT_MAX_INPUT_OCTETS)
				policy->max_input_octets = u32;
			else if (type == CHILLISPOT_MAX_OUTPUT_OCTETS)
				policy->max_output_octets = u32;
			else if (type == CHILLISPOT_MAX_TOTAL_OCTETS)
				policy->max_total_octets = u32;
			else if (type == CHILLISPOT_BANDWIDTH_MAX_UP)
				policy->max_upload_bps = u32;
			else if (type == CHILLISPOT_BANDWIDTH_MAX_DOWN)
				policy->max_download_bps = u32;
		} else if (vendor_id == RADIUS_VENDOR_WISPR) {
			if (type == WISPR_BANDWIDTH_MAX_UP)
				policy->max_upload_bps = u32;
			else if (type == WISPR_BANDWIDTH_MAX_DOWN)
				policy->max_download_bps = u32;
		}
		offset += attr_len;
	}
}

static void parse_accept_attrs(const uint8_t *attrs, size_t len,
			       struct airportal_session_policy *policy)
{
	size_t offset = 0;

	while (offset + 2 <= len) {
		uint8_t type = attrs[offset];
		uint8_t attr_len = attrs[offset + 1];
		const uint8_t *value;
		size_t value_len;
		uint32_t u32;

		if (attr_len < 2 || offset + attr_len > len)
			break;
		value = attrs + offset + 2;
		value_len = attr_len - 2;
		if (value_len == 4 &&
		    (type == RADIUS_ATTR_SESSION_TIMEOUT ||
		     type == RADIUS_ATTR_IDLE_TIMEOUT)) {
			memcpy(&u32, value, sizeof(u32));
			u32 = ntohl(u32);
			if (type == RADIUS_ATTR_SESSION_TIMEOUT)
				policy->session_timeout_sec = u32;
			else
				policy->idle_timeout_sec = u32;
		} else if (type == RADIUS_ATTR_FILTER_ID) {
			copy_radius_text(policy->filter_id, sizeof(policy->filter_id),
					 value, value_len);
		} else if (type == RADIUS_ATTR_CLASS) {
			copy_radius_text(policy->radius_class,
					 sizeof(policy->radius_class),
					 value, value_len);
		} else if (type == RADIUS_ATTR_VENDOR_SPECIFIC &&
			   value_len >= 6) {
			uint32_t vendor_id;

			memcpy(&vendor_id, value, sizeof(vendor_id));
			vendor_id = ntohl(vendor_id);
			parse_vendor_attrs(vendor_id, value + 4, value_len - 4,
					   policy);
		}
		offset += attr_len;
	}
}

static void parse_reply_message(const uint8_t *attrs, size_t len,
				char *message, size_t message_len)
{
	size_t offset = 0;

	if (!message || message_len == 0)
		return;
	message[0] = '\0';
	while (offset + 2 <= len) {
		uint8_t type = attrs[offset];
		uint8_t attr_len = attrs[offset + 1];
		const uint8_t *value;
		size_t value_len;

		if (attr_len < 2 || offset + attr_len > len)
			break;
		value = attrs + offset + 2;
		value_len = attr_len - 2;
		if (type == RADIUS_ATTR_REPLY_MESSAGE) {
			copy_radius_text(message, message_len, value, value_len);
			return;
		}
		offset += attr_len;
	}
}

static bool build_access_request(const struct airportal_daemon *daemon,
				 const struct airportal_radius_config *radius,
				 const struct airportal_client *client,
				 const char *username, const char *password,
				 const char *secret, struct radius_packet *packet)
{
	char mac[18];

	memset(packet, 0, sizeof(*packet));
	packet->code = RADIUS_CODE_ACCESS_REQUEST;
	if (RAND_bytes(&packet->id, sizeof(packet->id)) != 1 ||
	    RAND_bytes(packet->authenticator, sizeof(packet->authenticator)) != 1)
		return false;

	airportal_format_mac(client->key.mac, mac, sizeof(mac));
	return packet_add_string(packet, RADIUS_ATTR_USER_NAME, username) &&
	       packet_add_user_password(packet, password, secret) &&
	       packet_add_string(packet, RADIUS_ATTR_CALLING_STATION_ID, mac) &&
	       packet_add_string(packet, RADIUS_ATTR_CALLED_STATION_ID,
				 client->bssid[0] ? client->bssid : client->ifname) &&
	       packet_add_string(packet, RADIUS_ATTR_NAS_IDENTIFIER,
				 radius->nas_identifier[0] ?
				 radius->nas_identifier :
				 daemon->config.global.device_id) &&
	       packet_add_u32(packet, RADIUS_ATTR_SERVICE_TYPE,
			      RADIUS_SERVICE_TYPE_LOGIN) &&
	       packet_add_u32(packet, RADIUS_ATTR_NAS_PORT_TYPE,
			      RADIUS_NAS_PORT_TYPE_WIRELESS_80211) &&
	       packet_add_u32(packet, RADIUS_ATTR_FRAMED_MTU, 1500);
}

enum radius_auth_result
radius_client_authenticate(struct airportal_daemon *daemon,
			   const struct airportal_radius_config *radius,
			   const struct airportal_portal_config *portal,
			   const struct airportal_client *client,
			   const char *username,
			   const char *password,
			   struct airportal_session_policy *policy)
{
	struct radius_packet packet;
	uint8_t request[RADIUS_PACKET_MAX];
	uint8_t response[RADIUS_PACKET_MAX];
	char secret[256];
	size_t request_len;
	uint32_t attempts;
	enum radius_auth_result result = RADIUS_AUTH_TIMEOUT;

	(void)portal;
	if (!daemon || !radius || !client || !username || !username[0] ||
	    !password || !policy)
		return RADIUS_AUTH_ERROR;
	if (read_secret(radius->secret_file, secret, sizeof(secret)) != 0)
		return RADIUS_AUTH_ERROR;
	if (!build_access_request(daemon, radius, client, username, password,
				  secret, &packet))
		return RADIUS_AUTH_ERROR;
	ap_log_info("radius_auth_request username=%s server=%s port=%u transport=%s nas_identifier=%s",
		    username, radius->auth_server, radius->auth_port,
		    radius->transport[0] ? radius->transport : "udp",
		    radius->nas_identifier[0] ? radius->nas_identifier :
		    daemon->config.global.device_id);
	request_len = packet_serialize(&packet, request, sizeof(request));
	if (request_len == 0)
		return RADIUS_AUTH_ERROR;

	for (attempts = 0; attempts < radius->retry_count; attempts++) {
		uint16_t response_len;
		size_t n = 0;
		int transport_rc;

		transport_rc = radius_transport_exchange(radius,
							 radius->auth_server,
							 radius->auth_port,
							 request, request_len,
							 response, sizeof(response),
							 &n);
		if (transport_rc < 0) {
			result = RADIUS_AUTH_ERROR;
			break;
		}
		if (transport_rc > 0)
			continue;
		if (n < 20)
			continue;
		if (response[1] != packet.id)
			continue;
		memcpy(&response_len, response + 2, sizeof(response_len));
		if (ntohs(response_len) != (uint16_t)n)
			continue;
		if (!verify_response_authenticator(response, (size_t)n,
						   packet.authenticator, secret)) {
			result = RADIUS_AUTH_ERROR;
			break;
		}
		if (response[0] == RADIUS_CODE_ACCESS_ACCEPT) {
			parse_accept_attrs(response + 20, (size_t)n - 20, policy);
			result = RADIUS_AUTH_ACCEPT;
			break;
		}
		if (response[0] == RADIUS_CODE_ACCESS_REJECT ||
		    response[0] == RADIUS_CODE_ACCESS_CHALLENGE) {
			char reply_message[128];

			parse_reply_message(response + 20, (size_t)n - 20,
					    reply_message, sizeof(reply_message));
			ap_log_warn("radius_auth_reject username=%s code=%u reply=%s",
				    username, response[0],
				    reply_message[0] ? reply_message : "-");
			result = RADIUS_AUTH_REJECT;
			break;
		}
	}

	if (result == RADIUS_AUTH_TIMEOUT)
		daemon->metrics.radius_timeouts++;
	return result;
}
