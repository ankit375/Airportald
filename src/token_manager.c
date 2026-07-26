#include "token_manager.h"

#include "log.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void hex_encode(const uint8_t *in, size_t in_len, char *out,
		       size_t out_len)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;

	if (out_len < in_len * 2 + 1)
		return;
	for (i = 0; i < in_len; i++) {
		out[i * 2] = hex[in[i] >> 4];
		out[i * 2 + 1] = hex[in[i] & 0xf];
	}
	out[in_len * 2] = '\0';
}

static int hex_decode(const char *in, uint8_t *out, size_t out_len)
{
	size_t len = strlen(in);
	size_t i;

	if (len != out_len * 2)
		return -1;
	for (i = 0; i < out_len; i++) {
		int hi;
		int lo;

		if (!isxdigit((unsigned char)in[i * 2]) ||
		    !isxdigit((unsigned char)in[i * 2 + 1]))
			return -1;
		hi = in[i * 2] <= '9' ? in[i * 2] - '0' :
		     tolower((unsigned char)in[i * 2]) - 'a' + 10;
		lo = in[i * 2 + 1] <= '9' ? in[i * 2 + 1] - '0' :
		     tolower((unsigned char)in[i * 2 + 1]) - 'a' + 10;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

static int sign_payload(struct token_manager *mgr, const char *payload,
			char signature[SHA256_DIGEST_LENGTH * 2 + 1])
{
	unsigned int len = 0;
	uint8_t digest[EVP_MAX_MD_SIZE];

	if (!HMAC(EVP_sha256(), mgr->key, sizeof(mgr->key),
		  (const unsigned char *)payload, strlen(payload), digest, &len))
		return -1;
	if (len != SHA256_DIGEST_LENGTH)
		return -1;
	hex_encode(digest, SHA256_DIGEST_LENGTH, signature,
		   SHA256_DIGEST_LENGTH * 2 + 1);
	return 0;
}

static bool constant_time_equal(const char *a, const char *b)
{
	size_t alen = strlen(a);
	size_t blen = strlen(b);
	size_t i;
	unsigned char diff = (unsigned char)(alen ^ blen);
	size_t max = alen > blen ? alen : blen;

	for (i = 0; i < max; i++) {
		unsigned char ca = i < alen ? (unsigned char)a[i] : 0;
		unsigned char cb = i < blen ? (unsigned char)b[i] : 0;
		diff |= ca ^ cb;
	}

	return diff == 0;
}

int token_manager_init(struct token_manager *mgr, const char *key_file)
{
	FILE *fp;
	char hex_key[65];

	memset(mgr, 0, sizeof(*mgr));
	if (key_file && key_file[0] && access(key_file, R_OK) == 0) {
		fp = fopen(key_file, "r");
		if (!fp)
			return -1;
		if (!fgets(hex_key, sizeof(hex_key), fp)) {
			fclose(fp);
			return -1;
		}
		fclose(fp);
		hex_key[strcspn(hex_key, "\r\n")] = '\0';
		if (hex_decode(hex_key, mgr->key, sizeof(mgr->key)) != 0)
			return -1;
	} else if (RAND_bytes(mgr->key, sizeof(mgr->key)) != 1) {
		return -1;
	}

	mgr->has_key = true;
	return 0;
}

static bool nonce_seen(struct token_manager *mgr, const char *nonce)
{
	size_t i;

	for (i = 0; i < sizeof(mgr->nonces) / sizeof(mgr->nonces[0]); i++) {
		if (strcmp(mgr->nonces[i], nonce) == 0)
			return true;
	}
	return false;
}

static void remember_nonce(struct token_manager *mgr, const char *nonce)
{
	snprintf(mgr->nonces[mgr->nonce_next], sizeof(mgr->nonces[mgr->nonce_next]),
		 "%s", nonce);
	mgr->nonce_next = (mgr->nonce_next + 1) %
			  (sizeof(mgr->nonces) / sizeof(mgr->nonces[0]));
}

int token_create(struct token_manager *mgr,
		 const struct airportal_client *client,
		 const struct airportal_portal_config *portal,
		 char **out_token)
{
	uint8_t nonce_raw[16];
	char nonce[33];
	char mac[18];
	char payload[1024];
	char signature[SHA256_DIGEST_LENGTH * 2 + 1];
	char *token;
	uint64_t now = airportal_wall_time_sec();

	if (!mgr || !mgr->has_key || !client || !portal || !out_token)
		return -1;
	if (RAND_bytes(nonce_raw, sizeof(nonce_raw)) != 1)
		return -1;

	hex_encode(nonce_raw, sizeof(nonce_raw), nonce, sizeof(nonce));
	airportal_format_mac(client->key.mac, mac, sizeof(mac));
	snprintf(payload, sizeof(payload),
		 "1|ap|%u|%s|%s|%s|%llu|%llu|%s|%u",
		 portal->portal_id, mac, client->has_ipv4 ? inet_ntoa(client->ipv4) : "-",
		 client->ifname, (unsigned long long)now,
		 (unsigned long long)(now + 300u), nonce, client->auth_generation);

	if (sign_payload(mgr, payload, signature) != 0)
		return -1;

	token = calloc(1, strlen(payload) + strlen(signature) + 2);
	if (!token)
		return -1;
	sprintf(token, "%s.%s", payload, signature);
	*out_token = token;
	return 0;
}

int token_validate(struct token_manager *mgr,
		   const char *token,
		   struct airportal_token_claims *claims)
{
	char copy[AIRPORTAL_TOKEN_MAX];
	char *sig;
	char expected[SHA256_DIGEST_LENGTH * 2 + 1];
	char *saveptr = NULL;
	char *field;
	uint8_t mac[6];
	unsigned long long ull;

	if (!mgr || !mgr->has_key || !token || !claims || strlen(token) >= sizeof(copy))
		return -1;

	snprintf(copy, sizeof(copy), "%s", token);
	sig = strrchr(copy, '.');
	if (!sig)
		return -1;
	*sig++ = '\0';

	if (sign_payload(mgr, copy, expected) != 0 ||
	    !constant_time_equal(expected, sig))
		return -1;

	memset(claims, 0, sizeof(*claims));
	field = strtok_r(copy, "|", &saveptr);
	if (!field || strcmp(field, "1") != 0)
		return -1;
	claims->version = 1;

	field = strtok_r(NULL, "|", &saveptr);
	if (!field)
		return -1;
	snprintf(claims->device_id, sizeof(claims->device_id), "%s", field);

	field = strtok_r(NULL, "|", &saveptr);
	if (!field)
		return -1;
	claims->portal_id = (uint32_t)strtoul(field, NULL, 10);

	field = strtok_r(NULL, "|", &saveptr);
	if (!field || !airportal_parse_mac(field, mac))
		return -1;
	memcpy(claims->client_mac, mac, sizeof(mac));

	field = strtok_r(NULL, "|", &saveptr);
	if (!field)
		return -1;
	snprintf(claims->client_ip, sizeof(claims->client_ip), "%s", field);

	field = strtok_r(NULL, "|", &saveptr);
	if (!field)
		return -1;
	snprintf(claims->ifname, sizeof(claims->ifname), "%s", field);

	field = strtok_r(NULL, "|", &saveptr);
	if (!field)
		return -1;
	ull = strtoull(field, NULL, 10);
	claims->issued_at = (uint64_t)ull;

	field = strtok_r(NULL, "|", &saveptr);
	if (!field)
		return -1;
	ull = strtoull(field, NULL, 10);
	claims->expires_at = (uint64_t)ull;
	if (airportal_wall_time_sec() > claims->expires_at)
		return -1;

	field = strtok_r(NULL, "|", &saveptr);
	if (!field || nonce_seen(mgr, field))
		return -1;
	snprintf(claims->nonce, sizeof(claims->nonce), "%s", field);

	field = strtok_r(NULL, "|", &saveptr);
	if (!field)
		return -1;
	claims->generation = (uint32_t)strtoul(field, NULL, 10);

	remember_nonce(mgr, claims->nonce);
	return 0;
}
