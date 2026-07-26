#include "portal_http.h"

#include "log.h"
#include "radius_client.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct portal_http_state {
	int fd;
	ev_io watcher;
	struct portal_http_client *clients;
	struct airportal_daemon *daemon;
};

struct portal_http_client {
	int fd;
	ev_io watcher;
	ev_timer timeout;
	struct portal_http_state *state;
	struct portal_http_client *next;
	struct in_addr peer_ipv4;
	struct in_addr local_ipv4;
	bool has_peer_ipv4;
	bool has_local_ipv4;
};

static void close_client(int fd)
{
	if (fd >= 0)
		close(fd);
}

static void set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags >= 0)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static bool arp_lookup_ipv4(struct in_addr ipv4, uint8_t mac[6])
{
	FILE *fp;
	char ip[INET_ADDRSTRLEN];
	char line[256];
	char arp_ip[INET_ADDRSTRLEN];
	char hw_type[16];
	char flags[16];
	char mac_text[18];
	char mask[64];
	char dev[IFNAMSIZ];

	if (!inet_ntop(AF_INET, &ipv4, ip, sizeof(ip)))
		return false;

	fp = fopen("/proc/net/arp", "r");
	if (!fp)
		return false;

	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return false;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%15s %15s %15s %17s %63s %15s",
			   arp_ip, hw_type, flags, mac_text, mask, dev) != 6)
			continue;
		if (strcmp(arp_ip, ip) == 0 &&
		    airportal_parse_mac(mac_text, mac)) {
			fclose(fp);
			return true;
		}
	}

	fclose(fp);
	return false;
}

static struct airportal_client *
client_for_peer_ipv4(struct airportal_daemon *daemon, struct in_addr peer_ipv4,
		     const struct airportal_portal_config **portal)
{
	struct airportal_client *client;
	uint8_t mac[6];

	*portal = NULL;

	client = airportal_client_find_by_ipv4_state(&daemon->clients, peer_ipv4,
						    AIRPORTAL_CLIENT_CAPTIVE);
	if (!client && arp_lookup_ipv4(peer_ipv4, mac)) {
		client = airportal_client_find_unique_by_mac_state(
			&daemon->clients, mac, AIRPORTAL_CLIENT_CAPTIVE);
		if (client)
			airportal_client_set_ipv4(client, peer_ipv4);
	}

	if (!client)
		return NULL;

	*portal = airportal_config_find_portal_by_id(&daemon->config,
						     client->key.portal_id);
	if (!*portal)
		return NULL;
	return client;
}

static void write_response(int fd, const char *status, const char *headers,
			   const char *body)
{
	char response[8192];

	snprintf(response, sizeof(response),
		 "HTTP/1.1 %s\r\n"
		 "Connection: close\r\n"
		 "Cache-Control: no-store\r\n"
		 "%s"
		 "Content-Length: %zu\r\n\r\n%s",
		 status, headers ? headers : "", body ? strlen(body) : 0,
		 body ? body : "");
	send(fd, response, strlen(response), MSG_NOSIGNAL);
}

static void append_text(char *buf, size_t buf_len, size_t *used, const char *text)
{
	int n;

	if (*used >= buf_len)
		return;
	n = snprintf(buf + *used, buf_len - *used, "%s", text ? text : "");
	if (n < 0)
		return;
	if ((size_t)n >= buf_len - *used)
		*used = buf_len;
	else
		*used += (size_t)n;
}

static bool url_unreserved(unsigned char c)
{
	return isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~';
}

static void append_url_encoded(char *buf, size_t buf_len, size_t *used,
			       const char *value)
{
	static const char hex[] = "0123456789ABCDEF";
	const unsigned char *p = (const unsigned char *)value;
	char tmp[4];

	if (!value)
		return;
	for (; *p; p++) {
		if (url_unreserved(*p)) {
			tmp[0] = (char)*p;
			tmp[1] = '\0';
			append_text(buf, buf_len, used, tmp);
		} else {
			tmp[0] = '%';
			tmp[1] = hex[*p >> 4];
			tmp[2] = hex[*p & 0xf];
			tmp[3] = '\0';
			append_text(buf, buf_len, used, tmp);
		}
	}
}

static void append_query_param(char *buf, size_t buf_len, size_t *used,
			       bool *first, const char *name, const char *value)
{
	append_text(buf, buf_len, used, *first ? "" : "&");
	*first = false;
	append_url_encoded(buf, buf_len, used, name);
	append_text(buf, buf_len, used, "=");
	append_url_encoded(buf, buf_len, used, value ? value : "");
}

static int hex_value(char c);

static bool hex_decode_byte(const char *hex, uint8_t *out)
{
	int hi = hex_value(hex[0]);
	int lo = hex_value(hex[1]);

	if (hi < 0 || lo < 0)
		return false;
	*out = (uint8_t)((hi << 4) | lo);
	return true;
}

static bool hex_decode_fixed(const char *hex, uint8_t *out, size_t out_len)
{
	size_t i;

	if (!hex || strlen(hex) != out_len * 2)
		return false;
	for (i = 0; i < out_len; i++) {
		if (!hex_decode_byte(hex + (i * 2), &out[i]))
			return false;
	}
	return true;
}

static bool md5_two_parts(const uint8_t *a, size_t a_len,
			  const uint8_t *b, size_t b_len, uint8_t out[16])
{
	EVP_MD_CTX *ctx;
	unsigned int len = 0;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return false;
	if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1 ||
	    EVP_DigestUpdate(ctx, a, a_len) != 1 ||
	    EVP_DigestUpdate(ctx, b, b_len) != 1 ||
	    EVP_DigestFinal_ex(ctx, out, &len) != 1) {
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	return len == 16;
}

static bool ensure_uam_challenge(struct airportal_client *client)
{
	uint8_t random[16];
	static const char hex[] = "0123456789abcdef";
	size_t i;

	if (client->uam_challenge[0])
		return true;
	if (RAND_bytes(random, sizeof(random)) != 1)
		return false;
	for (i = 0; i < sizeof(random); i++) {
		client->uam_challenge[i * 2] = hex[random[i] >> 4];
		client->uam_challenge[i * 2 + 1] = hex[random[i] & 0xf];
	}
	client->uam_challenge[32] = '\0';
	return true;
}

static bool decode_uam_password(const char *encoded, const char *challenge,
				const char *uam_secret, char *password,
				size_t password_len)
{
	uint8_t challenge_bytes[16];
	uint8_t pad[16];
	uint8_t encrypted[16];
	size_t encoded_len;
	size_t encrypted_len;
	size_t i;

	if (!encoded || !challenge || !uam_secret || !uam_secret[0] ||
	    !password || password_len == 0)
		return false;
	encoded_len = strlen(encoded);
	if (encoded_len == 0 || encoded_len > 32 || (encoded_len % 2) != 0)
		return false;
	encrypted_len = encoded_len / 2;
	if (!hex_decode_fixed(challenge, challenge_bytes, sizeof(challenge_bytes)) ||
	    !hex_decode_fixed(encoded, encrypted, encrypted_len) ||
	    !md5_two_parts(challenge_bytes, sizeof(challenge_bytes),
			   (const uint8_t *)uam_secret, strlen(uam_secret), pad))
		return false;
	if (encrypted_len >= password_len)
		encrypted_len = password_len - 1;
	for (i = 0; i < encrypted_len; i++)
		password[i] = (char)(encrypted[i] ^ pad[i]);
	while (encrypted_len > 0 && password[encrypted_len - 1] == '\0')
		encrypted_len--;
	password[encrypted_len] = '\0';
	return password[0] != '\0';
}

static bool request_has_method(const char *req, const char *method)
{
	size_t len;

	if (!req || !method)
		return false;
	len = strlen(method);
	return strncmp(req, method, len) == 0 && req[len] == ' ';
}

static bool request_target_is(const char *req, const char *target)
{
	const char *path;
	size_t len;

	if (!request_has_method(req, "GET") &&
	    !request_has_method(req, "HEAD") &&
	    !request_has_method(req, "POST"))
		return false;

	path = strchr(req, ' ');
	if (!path)
		return false;
	path++;
	len = strlen(target);
	return strncmp(path, target, len) == 0 && path[len] == ' ';
}

static bool request_target_has_prefix(const char *req, const char *prefix)
{
	const char *path;
	size_t len;

	if (!request_has_method(req, "GET") &&
	    !request_has_method(req, "HEAD") &&
	    !request_has_method(req, "POST"))
		return false;

	path = strchr(req, ' ');
	if (!path)
		return false;
	path++;
	len = strlen(prefix);
	return strncmp(path, prefix, len) == 0 &&
	       (path[len] == ' ' || path[len] == '?' || path[len] == '/');
}

static bool request_is_redirectable(const char *req)
{
	return strncmp(req, "GET ", 4) == 0 || strncmp(req, "HEAD ", 5) == 0;
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	c = (char)tolower((unsigned char)c);
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static void url_decode(char *value)
{
	char *src = value;
	char *dst = value;

	while (*src) {
		if (*src == '%' && isxdigit((unsigned char)src[1]) &&
		    isxdigit((unsigned char)src[2])) {
			int hi = hex_value(src[1]);
			int lo = hex_value(src[2]);

			*dst++ = (char)((hi << 4) | lo);
			src += 3;
		} else if (*src == '+') {
			*dst++ = ' ';
			src++;
		} else {
			*dst++ = *src++;
		}
	}
	*dst = '\0';
}

static bool get_request_target(const char *req, char *target, size_t target_len)
{
	const char *start;
	const char *end;
	size_t len;

	if (!target || target_len == 0 ||
	    (!request_has_method(req, "GET") &&
	     !request_has_method(req, "HEAD") &&
	     !request_has_method(req, "POST")))
		return false;

	start = strchr(req, ' ');
	if (!start)
		return false;
	start++;
	end = strchr(start, ' ');
	if (!end || end <= start)
		return false;

	len = (size_t)(end - start);
	if (len >= target_len)
		len = target_len - 1;
	memcpy(target, start, len);
	target[len] = '\0';
	return true;
}

static void request_method(const char *req, char *method, size_t method_len)
{
	const char *end;
	size_t len;

	if (!req || !method || method_len == 0)
		return;
	method[0] = '\0';
	end = strchr(req, ' ');
	if (!end || end == req)
		return;
	len = (size_t)(end - req);
	if (len >= method_len)
		len = method_len - 1;
	memcpy(method, req, len);
	method[len] = '\0';
}

static bool query_param(char *target, const char *name, char *out, size_t out_len)
{
	char *query;
	char *saveptr = NULL;
	char *pair;
	size_t name_len;

	if (!target || !name || !out || out_len == 0)
		return false;
	out[0] = '\0';
	query = strchr(target, '?');
	if (!query)
		return false;
	*query++ = '\0';
	name_len = strlen(name);

	for (pair = strtok_r(query, "&", &saveptr); pair;
	     pair = strtok_r(NULL, "&", &saveptr)) {
		if (strncmp(pair, name, name_len) == 0 && pair[name_len] == '=') {
			snprintf(out, out_len, "%s", pair + name_len + 1);
			url_decode(out);
			return true;
		}
	}
	return false;
}

static bool param_from_pairs(const char *pairs, const char *name,
			     char *out, size_t out_len)
{
	char copy[2048];
	char *saveptr = NULL;
	char *pair;
	size_t name_len;

	if (!pairs || !name || !out || out_len == 0)
		return false;
	out[0] = '\0';
	snprintf(copy, sizeof(copy), "%s", pairs);
	name_len = strlen(name);

	for (pair = strtok_r(copy, "&", &saveptr); pair;
	     pair = strtok_r(NULL, "&", &saveptr)) {
		if (strncmp(pair, name, name_len) == 0 && pair[name_len] == '=') {
			snprintf(out, out_len, "%s", pair + name_len + 1);
			url_decode(out);
			return true;
		}
	}
	return false;
}

static const char *request_body(const char *req)
{
	const char *body;

	if (!req)
		return NULL;
	body = strstr(req, "\r\n\r\n");
	if (body)
		return body + 4;
	body = strstr(req, "\n\n");
	if (body)
		return body + 2;
	return NULL;
}

static bool query_param_copy(const char *req, const char *name,
			     char *out, size_t out_len)
{
	char target[AIRPORTAL_TOKEN_MAX + 256];
	const char *body;

	if (get_request_target(req, target, sizeof(target)) &&
	    query_param(target, name, out, out_len))
		return true;
	body = request_body(req);
	return param_from_pairs(body, name, out, out_len);
}

static void send_connected_response(int fd, const char *redirect_url)
{
	char headers[1024];

	if (redirect_url && redirect_url[0]) {
		snprintf(headers, sizeof(headers), "Location: %s\r\n", redirect_url);
		write_response(fd, "302 Found", headers, "");
		return;
	}
	write_response(fd, "200 OK", "Content-Type: text/html\r\n",
		       "<!doctype html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Connected</title></head><body><h1>Connected</h1><p>You can now use the internet.</p></body></html>\n");
}

static bool jsonp_callback_is_safe(const char *callback)
{
	const unsigned char *p = (const unsigned char *)callback;

	if (!callback || !callback[0])
		return false;
	for (; *p; p++) {
		if (!isalnum(*p) && *p != '_' && *p != '.' && *p != '$' &&
		    *p != '[' && *p != ']')
			return false;
	}
	return true;
}

static void json_escape(char *buf, size_t buf_len, const char *value)
{
	size_t used = 0;
	const unsigned char *p = (const unsigned char *)value;

	if (!buf || buf_len == 0)
		return;
	buf[0] = '\0';
	for (; value && *p; p++) {
		char tmp[8];

		if (*p == '"' || *p == '\\') {
			tmp[0] = '\\';
			tmp[1] = (char)*p;
			tmp[2] = '\0';
			append_text(buf, buf_len, &used, tmp);
		} else if (*p < 0x20) {
			snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
			append_text(buf, buf_len, &used, tmp);
		} else {
			tmp[0] = (char)*p;
			tmp[1] = '\0';
			append_text(buf, buf_len, &used, tmp);
		}
	}
}

static void handle_uam_password_request(struct portal_http_client *http_client)
{
	const char *req = (const char *)http_client->watcher.data;
	char password[256];
	char callback[128];
	char escaped_password[512];
	char body[4096];

	if (!query_param_copy(req, "password", password, sizeof(password)) &&
	    !query_param_copy(req, "Password", password, sizeof(password))) {
		write_response(http_client->fd, "400 Bad Request",
			       "Content-Type: application/json\r\n"
			       "Access-Control-Allow-Origin: *\r\n",
			       "{\"res\":\"failed\",\"message\":\"missing password\"}\n");
		return;
	}
	if (!query_param_copy(req, "callback", callback, sizeof(callback)) &&
	    !query_param_copy(req, "jsonp", callback, sizeof(callback)))
		callback[0] = '\0';

	json_escape(escaped_password, sizeof(escaped_password), password);
	snprintf(body, sizeof(body),
		 "{\"res\":\"success\",\"response\":\"%s\",\"password\":\"%s\","
		 "\"encryptedPassword\":\"%s\",\"encrypted_password\":\"%s\"}",
		 escaped_password, escaped_password, escaped_password,
		 escaped_password);
	if (jsonp_callback_is_safe(callback)) {
		char wrapped[4352];

		snprintf(wrapped, sizeof(wrapped), "%s(%s);\n", callback, body);
		write_response(http_client->fd, "200 OK",
			       "Content-Type: application/javascript\r\n"
			       "Access-Control-Allow-Origin: *\r\n",
			       wrapped);
	} else {
		write_response(http_client->fd, "200 OK",
			       "Content-Type: application/json\r\n"
			       "Access-Control-Allow-Origin: *\r\n",
			       body);
	}
	ap_log_info("portal_http_uam_password_response status=success");
}

static void send_json_logon_result(int fd, const char *res, const char *message)
{
	char body[2048];
	const bool success = res && strcmp(res, "success") == 0;

	snprintf(body, sizeof(body),
		 "<!doctype html><html><head><meta name=\"viewport\" "
		 "content=\"width=device-width,initial-scale=1\">"
		 "<title>AirPortal</title>"
		 "<style>body{font-family:system-ui,sans-serif;margin:0;"
		 "min-height:100vh;display:grid;place-items:center;"
		 "background:#0f172a;color:#e5e7eb}.card{max-width:360px;"
		 "padding:28px;border-radius:12px;background:#111827;"
		 "box-shadow:0 20px 60px rgba(0,0,0,.35);text-align:center}"
		 "h1{font-size:24px;margin:0 0 10px}p{color:#9ca3af}"
		 "</style></head><body><div class=\"card\"><h1>%s</h1>"
		 "<p>%s</p></div><script>%s</script></body></html>\n",
		 success ? "Connected" : "Authentication failed",
		 message ? message : "",
		 success ?
		 "setTimeout(function(){try{if(window.opener){window.opener.location.href='http://neverssl.com/';window.close();return;}}catch(e){}window.location.href='http://neverssl.com/';},600);" :
		 "setTimeout(function(){try{window.close();}catch(e){}},2500);");
	write_response(fd, "200 OK",
		       "Content-Type: text/html\r\n"
		       "Access-Control-Allow-Origin: *\r\n",
		       body);
}

static void handle_auth_complete(struct portal_http_client *http_client)
{
	struct portal_http_state *state = http_client->state;
	int fd = http_client->fd;
	const char *req = NULL;
	char target[AIRPORTAL_TOKEN_MAX + 256];
	char redirect_target[AIRPORTAL_TOKEN_MAX + 256];
	char token[AIRPORTAL_TOKEN_MAX];
	char username[128];
	char password[128];
	char redirect_url[512];
	char method[16];
	char response[128];
	char res[32];
	struct airportal_token_claims claims;
	const struct airportal_portal_config *portal;
	const struct airportal_radius_config *radius = NULL;
	struct airportal_client *client;
	struct airportal_session_policy policy;
	bool have_token;
	bool external_success;
	bool coova_json_logon;

	req = (const char *)http_client->watcher.data;
	request_method(req, method, sizeof(method));
	coova_json_logon = request_target_has_prefix(req, "/json/logon");
	external_success = request_target_has_prefix(req, "/online") ||
			   request_target_has_prefix(req, "/success") ||
			   request_target_has_prefix(req, "/callback") ||
			   request_target_has_prefix(req, "/uam_callback");

	have_token = get_request_target(req, target, sizeof(target)) &&
		     query_param(target, "token", token, sizeof(token));
	if (!query_param_copy(req, "username", username, sizeof(username)) &&
	    !query_param_copy(req, "UserName", username, sizeof(username)) &&
	    !query_param_copy(req, "User-Name", username, sizeof(username)) &&
	    !query_param_copy(req, "login", username, sizeof(username)) &&
	    !query_param_copy(req, "user", username, sizeof(username)))
		snprintf(username, sizeof(username), "portal");
	if (!query_param_copy(req, "password", password, sizeof(password)) &&
	    !query_param_copy(req, "Password", password, sizeof(password)) &&
	    !query_param_copy(req, "UserPassword", password, sizeof(password)) &&
	    !query_param_copy(req, "User-Password", password, sizeof(password)))
		password[0] = '\0';
	if (!query_param_copy(req, "response", response, sizeof(response)) &&
	    !query_param_copy(req, "chap", response, sizeof(response)))
		response[0] = '\0';
	if (!query_param_copy(req, "res", res, sizeof(res)))
		res[0] = '\0';
	if (request_target_has_prefix(req, "/logon") &&
	    (response[0] || strcmp(res, "success") == 0 || strcmp(res, "already") == 0))
		external_success = true;
	if (!query_param_copy(req, "userurl", redirect_url, sizeof(redirect_url)) &&
	    !query_param_copy(req, "redir", redirect_url, sizeof(redirect_url)))
		redirect_url[0] = '\0';
	if (external_success && !redirect_url[0])
		snprintf(redirect_url, sizeof(redirect_url), "http://neverssl.com/");

	ap_log_info("portal_http_auth_request path=%s method=%s token=%s username=%s",
		    get_request_target(req, redirect_target, sizeof(redirect_target)) ?
		    redirect_target : "unknown", method, have_token ? "yes" : "no",
		    username[0] ? username : "-");

	if (have_token && token_validate(&state->daemon->tokens, token, &claims) != 0) {
		state->daemon->metrics.token_validation_failures++;
		state->daemon->metrics.auth_rejects++;
		ap_log_warn("portal_http_auth_reject reason=invalid_token");
		write_response(fd, "403 Forbidden", "Content-Type: text/plain\r\n",
			       "invalid or expired token\n");
		return;
	}

	if (have_token) {
		portal = airportal_config_find_portal_by_id(&state->daemon->config,
							    claims.portal_id);
		client = airportal_client_find_by_mac_if_portal(&state->daemon->clients,
							       claims.client_mac,
							       claims.ifname,
							       claims.portal_id);
	} else if (http_client->has_peer_ipv4) {
		client = client_for_peer_ipv4(state->daemon, http_client->peer_ipv4,
					      &portal);
		if (client) {
			memcpy(claims.client_mac, client->key.mac,
			       sizeof(claims.client_mac));
			snprintf(claims.ifname, sizeof(claims.ifname), "%s",
				 client->ifname);
			claims.portal_id = client->key.portal_id;
		}
	} else {
		client = NULL;
		portal = NULL;
	}
	if (!portal || !client) {
		state->daemon->metrics.auth_rejects++;
		ap_log_warn("portal_http_auth_reject reason=client_not_found token=%s",
			    have_token ? "yes" : "no");
		write_response(fd, "404 Not Found", "Content-Type: text/plain\r\n",
			       "client not found\n");
		return;
	}

	if (strcmp(portal->auth_mode, "radius") == 0 && portal->uam_secret[0] &&
	    password[0] && client->uam_challenge[0]) {
		char decoded[128];

		if (decode_uam_password(password, client->uam_challenge,
					portal->uam_secret, decoded,
					sizeof(decoded))) {
			snprintf(password, sizeof(password), "%s", decoded);
			ap_log_info("portal_http_uam_password_decode status=success username=%s",
				    username);
		}
	}

	if (strcmp(portal->auth_mode, "radius") == 0 && external_success) {
		state->daemon->metrics.auth_rejects++;
		ap_log_warn("portal_http_auth_reject reason=external_success_disabled_for_radius username=%s",
			    username);
		write_response(fd, "403 Forbidden", "Content-Type: text/plain\r\n",
			       "radius credentials required\n");
		return;
	}

	if (strcmp(portal->auth_mode, "radius") == 0 && !external_success) {
		enum radius_auth_result radius_result;

		if (!username[0] || !password[0]) {
			state->daemon->metrics.auth_rejects++;
			ap_log_warn("portal_http_auth_reject reason=missing_radius_credentials");
			if (coova_json_logon) {
				send_json_logon_result(fd, "failed",
						       "missing credentials");
				return;
			}
			write_response(fd, "400 Bad Request",
				       "Content-Type: text/plain\r\n",
				       "missing radius credentials\n");
			return;
		}
		radius = airportal_config_find_radius_by_name(&state->daemon->config,
							      portal->radius_profile);
		memset(&policy, 0, sizeof(policy));
		policy.session_timeout_sec = portal->default_session_timeout;
		policy.idle_timeout_sec = portal->default_idle_timeout;
		policy.idle_activity_threshold_bytes =
			portal->default_idle_activity_threshold_bytes;
		policy.accounting_interval_sec =
			state->daemon->config.global.default_accounting_interval;
		policy.allow_ipv4 = true;
		radius_result = radius_client_authenticate(state->daemon, radius,
							   portal, client,
							   username, password,
							   &policy);
		if (radius_result == RADIUS_AUTH_REJECT) {
			state->daemon->metrics.auth_rejects++;
			ap_log_warn("portal_http_auth_reject reason=radius_reject username=%s",
				    username);
			if (coova_json_logon) {
				send_json_logon_result(fd, "failed",
						       "radius rejected");
				return;
			}
			write_response(fd, "403 Forbidden",
				       "Content-Type: text/plain\r\n",
				       "radius rejected\n");
			return;
		}
		if (radius_result != RADIUS_AUTH_ACCEPT) {
			state->daemon->metrics.auth_rejects++;
			ap_log_warn("portal_http_auth_reject reason=radius_unavailable username=%s",
				    username);
			if (coova_json_logon) {
				send_json_logon_result(fd, "failed",
						       "radius unavailable");
				return;
			}
			write_response(fd, "504 Gateway Timeout",
				       "Content-Type: text/plain\r\n",
				       "radius unavailable\n");
			return;
		}
		if (airportal_authorize_client(state->daemon, claims.client_mac,
					       claims.ifname, claims.portal_id,
					       username, &policy) != 0) {
			state->daemon->metrics.auth_rejects++;
			ap_log_warn("portal_http_auth_reject reason=authorize_failed username=%s",
				    username);
			if (coova_json_logon) {
				send_json_logon_result(fd, "failed",
						       "authorize failed");
				return;
			}
			write_response(fd, "500 Internal Server Error",
				       "Content-Type: text/plain\r\n",
				       "authorize failed\n");
			return;
		}
	} else if (external_success) {
		memset(&policy, 0, sizeof(policy));
		policy.session_timeout_sec = portal->default_session_timeout;
		policy.idle_timeout_sec = portal->default_idle_timeout;
		policy.idle_activity_threshold_bytes =
			portal->default_idle_activity_threshold_bytes;
		policy.accounting_interval_sec =
			state->daemon->config.global.default_accounting_interval;
		policy.allow_ipv4 = true;
		if (airportal_authorize_client(state->daemon, claims.client_mac,
					       claims.ifname, claims.portal_id,
					       username, &policy) != 0) {
			state->daemon->metrics.auth_rejects++;
			ap_log_warn("portal_http_auth_reject reason=authorize_failed username=%s",
				    username);
			write_response(fd, "500 Internal Server Error",
				       "Content-Type: text/plain\r\n",
				       "authorize failed\n");
			return;
		}
	} else if (airportal_authorize_client(state->daemon, claims.client_mac,
					      claims.ifname, claims.portal_id,
					      username, NULL) != 0) {
		state->daemon->metrics.auth_rejects++;
		ap_log_warn("portal_http_auth_reject reason=authorize_failed username=%s",
			    username);
		write_response(fd, "500 Internal Server Error",
			       "Content-Type: text/plain\r\n",
			       "authorize failed\n");
		return;
	}

	ap_log_info("portal_http_auth_accept username=%s portal_id=%u ifname=%s",
		    username, claims.portal_id, claims.ifname);
	if (coova_json_logon) {
		send_json_logon_result(fd, "success", "connected");
		return;
	}
	send_connected_response(fd, redirect_url);
}

static void build_callback_url(const struct portal_http_client *http_client,
			       const char *path, const char *token,
			       const char *userurl, char *buf, size_t buf_len)
{
	char local_ip[INET_ADDRSTRLEN] = "127.0.0.1";
	const char *host =
		http_client->state->daemon->config.global.portal_http_host;
	char encoded_userurl[768];
	size_t used = 0;

	if (!host[0] && http_client->has_local_ipv4)
		inet_ntop(AF_INET, &http_client->local_ipv4, local_ip,
			  sizeof(local_ip));
	snprintf(buf, buf_len, "http://%s:%u%s?token=%s",
		 host[0] ? host : local_ip,
		 http_client->state->daemon->config.global.portal_http_port,
		 path, token);
	if (userurl && userurl[0]) {
		snprintf(encoded_userurl, sizeof(encoded_userurl), "%s", buf);
		used = strlen(encoded_userurl);
		append_text(encoded_userurl, sizeof(encoded_userurl), &used,
			    "&userurl=");
		append_url_encoded(encoded_userurl, sizeof(encoded_userurl),
				   &used, userurl);
		snprintf(buf, buf_len, "%s", encoded_userurl);
	}
}

static void build_portal_location(struct portal_http_client *http_client,
				  const struct airportal_portal_config *portal,
				  const struct airportal_client *client,
				  const char *token, const char *req,
				  char *location, size_t location_len)
{
	struct portal_http_state *state = http_client->state;
	const struct airportal_radius_config *radius = NULL;
	char client_mac[18];
	char client_ip[INET_ADDRSTRLEN] = "";
	char local_ip[64] = "";
	const char *callback_host = state->daemon->config.global.portal_http_host;
	char userurl[512] = "";
	char auth_url[768];
	char logon_url[768];
	char online_url[768];
	char uamport[16];
	size_t used = 0;
	bool first;

	airportal_format_mac(client->key.mac, client_mac, sizeof(client_mac));
	if (client->has_ipv4)
		inet_ntop(AF_INET, &client->ipv4, client_ip, sizeof(client_ip));
	else if (http_client->has_peer_ipv4)
		inet_ntop(AF_INET, &http_client->peer_ipv4, client_ip,
			  sizeof(client_ip));
	if (callback_host[0])
		snprintf(local_ip, sizeof(local_ip), "%s", callback_host);
	else if (http_client->has_local_ipv4)
		inet_ntop(AF_INET, &http_client->local_ipv4, local_ip,
			  sizeof(local_ip));
	get_request_target(req, userurl, sizeof(userurl));
	build_callback_url(http_client, "/online", token, userurl, online_url,
			   sizeof(online_url));
	build_callback_url(http_client, "/logon", token, userurl, logon_url,
			   sizeof(logon_url));
	build_callback_url(http_client, "/auth/complete", token, userurl,
			   auth_url, sizeof(auth_url));
	snprintf(uamport, sizeof(uamport), "%u",
		 state->daemon->config.global.portal_http_port);
	if (portal->radius_profile[0])
		radius = airportal_config_find_radius_by_name(&state->daemon->config,
							      portal->radius_profile);

	append_text(location, location_len, &used, portal->portal_url);
	first = strchr(portal->portal_url, '?') == NULL;
	append_text(location, location_len, &used, first ? "?" : "&");
	append_query_param(location, location_len, &used, &first, "token", token);
	append_query_param(location, location_len, &used, &first, "challenge",
			   client->uam_challenge[0] ? client->uam_challenge : token);
	append_query_param(location, location_len, &used, &first, "uamchallenge",
			   client->uam_challenge[0] ? client->uam_challenge : token);
	append_query_param(location, location_len, &used, &first, "login_url",
			   logon_url);
	append_query_param(location, location_len, &used, &first, "loginurl",
			   logon_url);
	append_query_param(location, location_len, &used, &first, "uamlogin",
			   logon_url);
	append_query_param(location, location_len, &used, &first, "auth_url",
			   auth_url);
	append_query_param(location, location_len, &used, &first, "online_url",
			   online_url);
	append_query_param(location, location_len, &used, &first, "success_url",
			   online_url);
	append_query_param(location, location_len, &used, &first, "callback_url",
			   online_url);
	append_query_param(location, location_len, &used, &first, "uam_callback",
			   online_url);
	append_query_param(location, location_len, &used, &first, "uamip",
			   local_ip);
	append_query_param(location, location_len, &used, &first, "uamport",
			   uamport);
	append_query_param(location, location_len, &used, &first, "mac",
			   client_mac);
	append_query_param(location, location_len, &used, &first, "ip",
			   client_ip);
	append_query_param(location, location_len, &used, &first, "called",
			   client->bssid[0] ? client->bssid : client->ifname);
	append_query_param(location, location_len, &used, &first, "nasid",
			   radius && radius->nas_identifier[0] ?
			   radius->nas_identifier :
			   state->daemon->config.global.device_id);
	append_query_param(location, location_len, &used, &first, "sessionid",
			   client->session_id);
	append_query_param(location, location_len, &used, &first, "userurl",
			   userurl);
	append_query_param(location, location_len, &used, &first, "res",
			   "notyet");
	append_query_param(location, location_len, &used, &first, "ssid",
			   client->ssid);
}

static void handle_prelogin_success(struct portal_http_client *http_client,
				    const struct airportal_portal_config *portal,
				    const struct airportal_client *client)
{
	char headers[4096];

	(void)portal;
	(void)client;
	snprintf(headers, sizeof(headers), "Location: http://neverssl.com/\r\n");
	write_response(http_client->fd, "302 Found", headers, "");
	ap_log_info("portal_http_prelogin_redirect target=http://neverssl.com/");
}

static void handle_http_client(struct portal_http_client *http_client)
{
	struct portal_http_state *state = http_client->state;
	int fd = http_client->fd;
	char req[4096];
	ssize_t n;

	n = recv(fd, req, sizeof(req) - 1, 0);
	if (n <= 0) {
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return;
		return;
	}
	req[n] = '\0';

	if (request_target_is(req, "/health") ||
	    request_target_is(req, "/status")) {
		write_response(fd, "200 OK", "Content-Type: application/json\r\n",
			       "{\"ok\":true}\n");
		return;
	}

	if (request_target_has_prefix(req, "/auth/complete") ||
	    request_target_has_prefix(req, "/auth/uam") ||
	    request_target_has_prefix(req, "/json/logon") ||
	    request_target_has_prefix(req, "/login") ||
	    request_target_has_prefix(req, "/logon") ||
	    request_target_has_prefix(req, "/online")) {
		http_client->watcher.data = req;
		if (request_target_has_prefix(req, "/auth/uam"))
			handle_uam_password_request(http_client);
		else
			handle_auth_complete(http_client);
		http_client->watcher.data = http_client;
		return;
	}

	if (request_target_has_prefix(req, "/portal")) {
		write_response(fd, "200 OK", "Content-Type: text/html\r\n",
			       "<!doctype html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>AirPortal</title></head><body><h1>AirPortal</h1><p>Captive portal redirect is active.</p></body></html>\n");
		return;
	}

	if (request_is_redirectable(req)) {
		const struct airportal_portal_config *portal = NULL;
		struct airportal_client *client = NULL;
		char *token = NULL;
		char headers[4096];
		char location[3584];
		char client_mac[18];
		char peer_ip[INET_ADDRSTRLEN] = "-";
		char target[512] = "unknown";
		bool prelogin;

		if (http_client->has_peer_ipv4)
			client = client_for_peer_ipv4(state->daemon,
						      http_client->peer_ipv4,
						      &portal);
		if (!client || !portal ||
		    token_create(&state->daemon->tokens, client, portal, &token) != 0) {
			write_response(fd, "503 Service Unavailable",
				       "Content-Type: text/plain\r\n",
				       "portal unavailable\n");
			return;
		}
		if (!ensure_uam_challenge(client)) {
			free(token);
			write_response(fd, "503 Service Unavailable",
				       "Content-Type: text/plain\r\n",
				       "portal unavailable\n");
			return;
		}

		prelogin = request_target_has_prefix(req, "/prelogin");
		if (prelogin) {
			handle_prelogin_success(http_client, portal, client);
		} else {
			build_portal_location(http_client, portal, client, token, req,
					      location, sizeof(location));
			snprintf(headers, sizeof(headers), "Location: %s\r\n",
				 location);
			write_response(fd, "302 Found", headers, "");
		}
		state->daemon->metrics.http_redirects++;
		airportal_format_mac(client->key.mac, client_mac,
				      sizeof(client_mac));
		if (http_client->has_peer_ipv4)
			inet_ntop(AF_INET, &http_client->peer_ipv4, peer_ip,
				  sizeof(peer_ip));
		get_request_target(req, target, sizeof(target));
		ap_log_info("portal_http_redirect mac=%s ip=%s ifname=%s portal_id=%u uamip=%s mode=%s target=%s",
			    client_mac, peer_ip, client->ifname,
			    client->key.portal_id,
			    state->daemon->config.global.portal_http_host[0] ?
			    state->daemon->config.global.portal_http_host : "auto",
			    prelogin ? "prelogin" : "redirect",
			    target);
		free(token);
		return;
	}

	write_response(fd, "404 Not Found", "Content-Type: text/plain\r\n",
		       "not found\n");
}

static void portal_http_client_close(EV_P_ struct portal_http_client *client)
{
	struct portal_http_state *state = client->state;
	struct portal_http_client **p;

	ev_io_stop(loop, &client->watcher);
	ev_timer_stop(loop, &client->timeout);
	for (p = &state->clients; *p; p = &(*p)->next) {
		if (*p == client) {
			*p = client->next;
			break;
		}
	}
	close_client(client->fd);
	free(client);
}

static void client_read_cb(EV_P_ ev_io *w, int revents)
{
	struct portal_http_client *client = (struct portal_http_client *)w->data;

	(void)revents;
	handle_http_client(client);
	portal_http_client_close(loop, client);
}

static void client_timeout_cb(EV_P_ ev_timer *w, int revents)
{
	struct portal_http_client *client = (struct portal_http_client *)w->data;

	(void)revents;
	portal_http_client_close(loop, client);
}

static void accept_cb(EV_P_ ev_io *w, int revents)
{
	struct portal_http_state *state = (struct portal_http_state *)w->data;
	struct portal_http_client *client;
	struct sockaddr_in peer;
	socklen_t peer_len;
	int fd;

	(void)revents;
	while (true) {
		peer_len = sizeof(peer);
		memset(&peer, 0, sizeof(peer));
		fd = accept(state->fd, (struct sockaddr *)&peer, &peer_len);
		if (fd < 0)
			break;
		client = calloc(1, sizeof(*client));
		if (!client) {
			close_client(fd);
			continue;
		}
		set_nonblocking(fd);
		client->fd = fd;
		client->state = state;
		if (peer_len >= sizeof(peer) && peer.sin_family == AF_INET) {
			client->peer_ipv4 = peer.sin_addr;
			client->has_peer_ipv4 = true;
		}
		peer_len = sizeof(peer);
		memset(&peer, 0, sizeof(peer));
		if (getsockname(fd, (struct sockaddr *)&peer, &peer_len) == 0 &&
		    peer_len >= sizeof(peer) && peer.sin_family == AF_INET) {
			client->local_ipv4 = peer.sin_addr;
			client->has_local_ipv4 = true;
		}
		client->next = state->clients;
		state->clients = client;

		ev_io_init(&client->watcher, client_read_cb, fd, EV_READ);
		client->watcher.data = client;
		ev_timer_init(&client->timeout, client_timeout_cb, 5.0, 0.0);
		client->timeout.data = client;
		ev_io_start(loop, &client->watcher);
		ev_timer_start(loop, &client->timeout);
	}
}

int portal_http_init(struct airportal_daemon *daemon)
{
	struct portal_http_state *state;
	struct sockaddr_in addr;
	int yes = 1;

	state = calloc(1, sizeof(*state));
	if (!state)
		return -1;
	state->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (state->fd < 0)
		goto fail;

	setsockopt(state->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	set_nonblocking(state->fd);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(daemon->config.global.portal_http_port);
	if (bind(state->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		goto fail;
	if (listen(state->fd, 16) != 0)
		goto fail;

	state->daemon = daemon;
	ev_io_init(&state->watcher, accept_cb, state->fd, EV_READ);
	state->watcher.data = state;
	ev_io_start(daemon->loop, &state->watcher);
	daemon->portal_http = state;
	ap_log_info("portal_http_ready port=%u", daemon->config.global.portal_http_port);
	return 0;

fail:
	if (state->fd >= 0)
		close(state->fd);
	free(state);
	return -1;
}

void portal_http_shutdown(struct airportal_daemon *daemon)
{
	struct portal_http_state *state = daemon->portal_http;
	struct portal_http_client *client;

	if (!state)
		return;
	ev_io_stop(daemon->loop, &state->watcher);
	while ((client = state->clients) != NULL)
		portal_http_client_close(daemon->loop, client);
	close(state->fd);
	free(state);
	daemon->portal_http = NULL;
}
