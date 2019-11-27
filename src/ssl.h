/*
 * This file is part of harddns.
 *
 * (C) 2016-2019 by Sebastian Krahmer,
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

#ifndef harddns_ssl_h
#define harddns_ssl_h

#include <vector>
#include <cerrno>
#include <cstdio>
#include <string>
#include <memory>
#include <cstring>
#include <stdint.h>

extern "C" {
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
}


namespace harddns {


class ssl_box {

private:
	int d_sock{-1};

	std::vector<EVP_PKEY *> d_pinned;
	SSL_CTX *d_ssl_ctx{nullptr};
	SSL *d_ssl{nullptr};

	std::string d_err{""}, d_ns_ip{""};

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		int e = 0;
		d_err = "ssl_box::";
		d_err += msg;
		if ((e = ERR_get_error())) {
			ERR_load_crypto_strings();
			d_err += ":";
			d_err += ERR_error_string(e, nullptr);
			ERR_clear_error();
		} else if (errno) {
			d_err += ":";
			d_err += strerror(errno);
		}
		return r;
	}


public:

	ssl_box();

	virtual ~ssl_box();

	const char *why()
	{
		return d_err.c_str();
	}

	void add_pinned(EVP_PKEY *evp)
	{
		d_pinned.push_back(evp);
	}

	int setup_ctx();

	// 1s
	int connect(const std::string &, uint16_t port = 443, long to = 1000000000);

	// 1s
	ssize_t send(const std::string &, long to = 1000000000);

	ssize_t recv(std::string &, long to = 1000000000);

	void close();

	std::string peer()
	{
		return d_ns_ip;
	}
};


extern ssl_box *ssl_conn;

#if (OPENSSL_VERSION_NUMBER <= 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
#define ASN1_STRING_get0_data(x) ASN1_STRING_data(x)
#endif

}

#endif

