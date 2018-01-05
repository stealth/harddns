/*
 * This file is part of harddns.
 *
 * (C) 2016-2018 by Sebastian Krahmer,
 *                  sebastian [dot] krahmer [at] gmail [dot] com
 *
 * harddns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * harddns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with harddns. If not, see <http://www.gnu.org/licenses/>.
 */

#include <string>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include "ssl.h"

extern "C" {
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
}


namespace harddns {


using namespace std;

ssl_box *ssl_conn = nullptr;


static int tcp_connect(const char *host, uint16_t port = 443)
{
	int sock = -1;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	// first, try as IPv4 address
	if (inet_pton(AF_INET, host, &sin.sin_addr) == 1) {
		if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
			return -1;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(port);
		if (connect(sock, reinterpret_cast<sockaddr *>(&sin), sizeof(sin)) < 0)
			return -1;
	} else if (inet_pton(AF_INET6, host, &sin6.sin6_addr) == 1) {
		if ((sock = socket(PF_INET6, SOCK_STREAM, 0)) < 0)
			return -1;
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(port);
		if (connect(sock, reinterpret_cast<sockaddr *>(&sin6), sizeof(sin6)) < 0)
			return -1;
	} else
		return -1;

	return sock;
}


ssl_box::ssl_box()
	: sock(-1), ssl_ctx(nullptr), ssl(nullptr)
{
}


ssl_box::~ssl_box()
{
	for (auto p : pinned) {
		EVP_PKEY_free(p);
	}
	if (ssl)
		SSL_free(ssl);
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	::close(sock);
}


int ssl_box::setup_ctx()
{
	const SSL_METHOD *method = nullptr;

	if ((method = TLSv1_2_client_method()) == nullptr)
		return build_error("TLSv12_client_method", -1);

	if ((ssl_ctx = SSL_CTX_new(method)) == nullptr)
		return build_error("SSL_CTX_new", -1);


	long op = SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1;
	op |= (SSL_OP_SINGLE_DH_USE|SSL_OP_SINGLE_ECDH_USE|SSL_OP_NO_TICKET);

	if ((SSL_CTX_set_options(ssl_ctx, op) & op) != op)
		return build_error("SSL_CTX_set_options:", -1);

	if (SSL_CTX_load_verify_locations(ssl_ctx, NULL, "/etc/ssl/certs") != 1)
		return build_error("SSL_CTX_load_verify_locations:", -1);

	if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1)
		return build_error("SSL_CTX_set_default_verify_paths: %s\n", -1);

	SSL_CTX_set_verify(ssl_ctx,
	                       SSL_VERIFY_PEER|
 	                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
	                       nullptr);
	SSL_CTX_set_verify_depth(ssl_ctx, 100);

	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);

#ifdef CIPHER_LIST
	if (SSL_CTX_set_cipher_list(ssl_ctx, CIPHER_LIST) != 1)
		return build_error("SSL_CTX_set_cipher_list:", -1);
#endif

	return 0;
}


static int post_connection_check(X509 *x509, const map<string, int> &hosts)
{
	X509_NAME *subj = X509_get_subject_name(x509);
	if (!subj)
		return -1;

	int loc = -1;
	X509_NAME_ENTRY *e = nullptr;
	for (;;) {
		loc = X509_NAME_get_index_by_NID(subj, NID_commonName, loc);
		if (loc == -1 || loc == -2)
			break;
		e = X509_NAME_get_entry(subj, loc);		// e must not be freed
		if (!e)
			break;
		ASN1_STRING *as = X509_NAME_ENTRY_get_data(e);
		if (!as)
			break;
		int len = ASN1_STRING_length(as);
		if (len < 0 || len > 0x1000)
			return -1;
		string s = string(reinterpret_cast<char *>(ASN1_STRING_data(as)), len);		// ASN1_STRING_data() must not be freed
		if (hosts.count(s) > 0)
			return 1;
	}
	return 0;
}


int ssl_box::connect_ssl(const string &host)
{
	::close(sock);
	if (ssl)
		SSL_free(ssl);

	if ((sock = tcp_connect(host.c_str())) < 0)
		return build_error("tcp_connect", -1);

	X509 *x509 = nullptr;

	if ((ssl = SSL_new(ssl_ctx)) == nullptr)
		return -1;
	SSL_set_fd(ssl, sock);
	if (SSL_connect(ssl) <= 0)
		return build_error("SSL_connect:", -1);

	// only set non blocking after SSL_connect()
	fcntl(sock, F_SETFL, O_RDWR|O_NONBLOCK);

	int err = 0;
	if ((err = SSL_get_verify_result(ssl)) != X509_V_OK)
		return build_error(X509_verify_cert_error_string(err), -1);

	if ((x509 = SSL_get_peer_certificate(ssl)) == nullptr)
		return build_error("SSL_get_peer_certificate", -1);

	if (post_connection_check(x509, {{"dns.google.com", 1},  {"*.google.com", 1}}) != 1)
		return build_error("SSL Post connection check failed. CN mismatch?", -1);

	EVP_PKEY *peer_key = nullptr;
	if (pinned.size() > 0)
		peer_key = X509_get_pubkey(x509);

	X509_free(x509);

	if (pinned.size() > 0) {

		if (!peer_key)
			return build_error("No key inside peer X509?!", -1);

		bool has = 0;
		for (auto p : pinned) {
			if (EVP_PKEY_cmp(p, peer_key) == 1)
				has = 1;
		}

		EVP_PKEY_free(peer_key);

		if (has != 1)
			return build_error("Peer X509 not in pinned list!", -1);
	}

	return 0;
}


void ssl_box::close()
{
	if (ssl)
		SSL_free(ssl);
	ssl = nullptr;
	::close(sock);
	sock = -1;
}


ssize_t ssl_box::send(const string &buf, long to)
{
	if (!ssl)
		return -1;

	int r = 0, written = 0;
	long waiting = 0;
	timespec ts = {0, 10000000};	// 10ms

	for (;waiting < to;) {
		r = SSL_write(ssl, buf.c_str() + written, buf.size() - written);

		switch (SSL_get_error(ssl, r)) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			r = 0;
			break;
		case SSL_ERROR_ZERO_RETURN:
			return build_error("SSL_write: Peer closed connection.", -1);
		default:
			return build_error("SSL_write:", -1);
		}

		if (r == 0) {
			nanosleep(&ts, nullptr);
			waiting += ts.tv_nsec;
		} else if (r > 0)
			written += r;

		if (written == (int)buf.size())
			break;
	}

	return written;
}


ssize_t ssl_box::recv(string &s, long to)
{
	if (!ssl)
		return -1;

	int r = 0;
	char buf[4096] = {0};
	long waiting = 0;
	timespec ts = {0, 10000000};	// 10ms

	s = "";

	for (;waiting < to;) {
		r = SSL_read(ssl, buf, sizeof(buf) - 1);
		switch (SSL_get_error(ssl, r)) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			r = 0;
			break;
		case SSL_ERROR_ZERO_RETURN:
			return build_error("SSL_read: Peer closed connection.", -1);
		default:
			return build_error("SSL_read:", -1);
		}

		if (r == 0) {
			nanosleep(&ts, nullptr);
			waiting += ts.tv_nsec;
		} else if (r > 0) {
			s = string(buf, r);
			break;
		}
	}

	return r;
}


} // namespace harddns

