#include "radius_transport.h"

#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RADIUS_HEADER_LEN 20
#define RADIUS_PACKET_MAX 4096

bool radius_transport_is_radsec(const struct airportal_radius_config *radius)
{
	return radius && strcmp(radius->transport, "radsec") == 0;
}

static int connect_socket(const char *host, uint16_t port, int socktype,
			  uint32_t timeout_ms)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	char port_text[16];
	int fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = socktype;
	hints.ai_family = AF_UNSPEC;
	snprintf(port_text, sizeof(port_text), "%u", port);
	if (getaddrinfo(host, port_text, &hints, &res) != 0)
		return -1;

	for (ai = res; ai; ai = ai->ai_next) {
		int flags;

		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
			    ai->ai_protocol);
		if (fd < 0)
			continue;
		if (socktype == SOCK_DGRAM) {
			if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
				break;
		} else {
			flags = fcntl(fd, F_GETFL, 0);
			if (flags >= 0)
				fcntl(fd, F_SETFL, flags | O_NONBLOCK);
			if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
				if (flags >= 0)
					fcntl(fd, F_SETFL, flags);
				break;
			}
			if (errno == EINPROGRESS) {
				struct pollfd pfd = { .fd = fd, .events = POLLOUT };
				int err = 0;
				socklen_t err_len = sizeof(err);

				if (poll(&pfd, 1, (int)timeout_ms) > 0 &&
				    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err,
					       &err_len) == 0 && err == 0) {
					if (flags >= 0)
						fcntl(fd, F_SETFL, flags);
					break;
				}
			}
		}
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

static int exchange_udp(const struct airportal_radius_config *radius,
			const char *host, uint16_t port,
			const uint8_t *request, size_t request_len,
			uint8_t *response, size_t response_len,
			size_t *actual_response_len)
{
	struct pollfd pfd;
	ssize_t n;
	int fd;

	fd = connect_socket(host, port, SOCK_DGRAM, radius->timeout_ms);
	if (fd < 0)
		return -1;
	if (send(fd, request, request_len, 0) != (ssize_t)request_len) {
		close(fd);
		return -1;
	}
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, (int)radius->timeout_ms) <= 0) {
		close(fd);
		return 1;
	}
	n = recv(fd, response, response_len, 0);
	close(fd);
	if (n <= 0)
		return -1;
	*actual_response_len = (size_t)n;
	return 0;
}

static bool load_crl(SSL_CTX *ctx, const char *path)
{
	X509_STORE *store;
	X509_LOOKUP *lookup;

	if (!path || !path[0])
		return true;
	store = SSL_CTX_get_cert_store(ctx);
	if (!store)
		return false;
	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if (!lookup)
		return false;
	if (X509_load_crl_file(lookup, path, X509_FILETYPE_PEM) != 1)
		return false;
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
	return true;
}

static int ssl_wait(SSL *ssl, int rc, uint32_t timeout_ms)
{
	int err = SSL_get_error(ssl, rc);
	struct pollfd pfd;

	if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
		return -1;
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = SSL_get_fd(ssl);
	pfd.events = err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
	return poll(&pfd, 1, (int)timeout_ms) > 0 ? 0 : -1;
}

static int ssl_write_all(SSL *ssl, const uint8_t *buf, size_t len,
			 uint32_t timeout_ms)
{
	size_t done = 0;

	while (done < len) {
		int n = SSL_write(ssl, buf + done, (int)(len - done));

		if (n > 0) {
			done += (size_t)n;
			continue;
		}
		if (ssl_wait(ssl, n, timeout_ms) != 0)
			return -1;
	}
	return 0;
}

static int ssl_read_exact(SSL *ssl, uint8_t *buf, size_t len,
			  uint32_t timeout_ms)
{
	size_t done = 0;

	while (done < len) {
		int n = SSL_read(ssl, buf + done, (int)(len - done));

		if (n > 0) {
			done += (size_t)n;
			continue;
		}
		if (ssl_wait(ssl, n, timeout_ms) != 0)
			return -1;
	}
	return 0;
}

static int exchange_radsec(const struct airportal_radius_config *radius,
			   const char *host, uint16_t port,
			   const uint8_t *request, size_t request_len,
			   uint8_t *response, size_t response_len,
			   size_t *actual_response_len)
{
	const char *server_name;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	uint8_t header[4];
	uint16_t radius_len;
	int fd = -1;
	int rc = -1;

	if (!radius->radsec_ca_cert[0]) {
		ap_log_warn("radsec_failed reason=missing_ca profile=%s", radius->name);
		return -1;
	}
	fd = connect_socket(host, port, SOCK_STREAM, radius->timeout_ms);
	if (fd < 0)
		return -1;
	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx)
		goto out;
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_load_verify_locations(ctx, radius->radsec_ca_cert, NULL) != 1)
		goto out;
	if (!load_crl(ctx, radius->radsec_crl_file))
		goto out;
	if (radius->radsec_client_cert[0] &&
	    SSL_CTX_use_certificate_file(ctx, radius->radsec_client_cert,
					 SSL_FILETYPE_PEM) != 1)
		goto out;
	if (radius->radsec_client_key[0] &&
	    SSL_CTX_use_PrivateKey_file(ctx, radius->radsec_client_key,
					SSL_FILETYPE_PEM) != 1)
		goto out;
	if (radius->radsec_client_cert[0] && radius->radsec_client_key[0] &&
	    SSL_CTX_check_private_key(ctx) != 1)
		goto out;

	ssl = SSL_new(ctx);
	if (!ssl)
		goto out;
	SSL_set_fd(ssl, fd);
	server_name = radius->radsec_server_name[0] ?
		      radius->radsec_server_name : host;
	if (server_name[0])
		SSL_set_tlsext_host_name(ssl, server_name);
	if (radius->radsec_verify_host && server_name[0])
		X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), server_name, 0);
	while ((rc = SSL_connect(ssl)) != 1) {
		if (ssl_wait(ssl, rc, radius->timeout_ms) != 0)
			goto out;
	}
	if (ssl_write_all(ssl, request, request_len, radius->timeout_ms) != 0)
		goto out;
	if (ssl_read_exact(ssl, header, sizeof(header), radius->timeout_ms) != 0)
		goto out;
	memcpy(response, header, sizeof(header));
	memcpy(&radius_len, header + 2, sizeof(radius_len));
	radius_len = ntohs(radius_len);
	if (radius_len < RADIUS_HEADER_LEN || radius_len > response_len ||
	    radius_len > RADIUS_PACKET_MAX)
		goto out;
	if (ssl_read_exact(ssl, response + sizeof(header),
			   radius_len - sizeof(header), radius->timeout_ms) != 0)
		goto out;
	*actual_response_len = radius_len;
	rc = 0;
out:
	if (rc != 0)
		ap_log_warn("radsec_exchange_failed profile=%s host=%s port=%u error=%lu",
			    radius->name, host, port, ERR_get_error());
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (ctx)
		SSL_CTX_free(ctx);
	if (fd >= 0)
		close(fd);
	return rc;
}

int radius_transport_exchange(const struct airportal_radius_config *radius,
			      const char *host, uint16_t port,
			      const uint8_t *request, size_t request_len,
			      uint8_t *response, size_t response_len,
			      size_t *actual_response_len)
{
	if (!radius || !host || !request || !response || !actual_response_len)
		return -1;
	*actual_response_len = 0;
	if (radius_transport_is_radsec(radius))
		return exchange_radsec(radius, host, port, request, request_len,
				       response, response_len,
				       actual_response_len);
	return exchange_udp(radius, host, port, request, request_len,
			    response, response_len, actual_response_len);
}
