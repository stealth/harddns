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

#include <ftw.h>
#include <sys/types.h>
#include <string>
#include <syslog.h>
#include "config.h"
#include "ssl.h"
#include "dnshttps.h"

extern "C" {
#include <openssl/evp.h>
#include <openssl/err.h>
}


using namespace std;


static int pem_walk(const char *path, const struct stat *st, int typeflag, struct FTW *ftwbuf)
{
	FILE *f = nullptr;
	EVP_PKEY *pkey = nullptr;

	if (typeflag == FTW_F) {
		if (S_ISREG(st->st_mode) && string(path).find(".pem") != string::npos) {
			if (!(f = fopen(path, "r")))
				return 0;
			X509 *x509 = PEM_read_X509(f, nullptr, nullptr, nullptr);
			fclose(f);
			if (x509)
				pkey = X509_get_pubkey(x509);
			X509_free(x509);

			if (pkey)
				harddns::ssl_conn->add_pinned(pkey);	// transfers ownership
		}
	}

	return 0;
}


static int load_certificates()
{
	const string pinned_path = "/etc/harddns/pinned";
	return nftw(pinned_path.c_str(), pem_walk, 1024, FTW_PHYS);
}


void harddns_init()
{

	harddns::config::parse_config("/etc/harddns");

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	ERR_clear_error();

	if (!(harddns::ssl_conn = new (nothrow) harddns::ssl_box))
		return;

	harddns::ssl_conn->setup_ctx();

	load_certificates();

	harddns::dns = new (nothrow) harddns::dnshttps(harddns::ssl_conn);

	openlog("harddns", LOG_NDELAY|LOG_PID, LOG_DAEMON);
}


void harddns_fini()
{
	delete harddns::ssl_conn;
	delete harddns::dns;

	delete harddns::config::ns;
	delete harddns::config::ns_cfg;
}

