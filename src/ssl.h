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

extern "C" {
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
}


namespace harddns {

template<typename T> using free_ptr = std::unique_ptr<T, void (*)(T *)>;

class ssl_box {

private:
	int sock{-1};

	std::vector<EVP_PKEY *> pinned;
	SSL_CTX *ssl_ctx{nullptr};
	SSL *ssl{nullptr};

	std::string err{""}, ns_ip{""};

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		int e = 0;
		err = "ssl_box::";
		err += msg;
		if ((e = ERR_get_error())) {
			ERR_load_crypto_strings();
			err += ":";
			err += ERR_error_string(e, nullptr);
			ERR_clear_error();
		} else if (errno) {
			err += ":";
			err += strerror(errno);
		}
		return r;
	}


public:

	ssl_box();

	virtual ~ssl_box();

	const char *why()
	{
		return err.c_str();
	}

	void add_pinned(EVP_PKEY *evp)
	{
		pinned.push_back(evp);
	}

	int setup_ctx();

	int connect_ssl(const std::string &);

	// 1s
	ssize_t send(const std::string &, long to = 1000000000);

	ssize_t recv(std::string &, long to = 1000000000);

	void close();

	std::string peer()
	{
		return ns_ip;
	}
};


extern ssl_box *ssl_conn;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
#define ASN1_STRING_get0_data(x) ASN1_STRING_data(x)
#endif

}

#endif

