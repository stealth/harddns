/*
 * This file is part of harddns.
 *
 * (C) 2016-2023 by Sebastian Krahmer,
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

#ifndef harddns_config_h
#define harddns_config_h

#include <cstdint>
#include <string>
#include <map>
#include <list>

extern "C" {
#include <openssl/ssl.h>
}


namespace harddns {

namespace config {


extern std::list<std::string> *ns;
extern bool log_requests, nss_aaaa, cache_PTR;

extern std::map<std::string, std::string> internal_domains;

struct a_ns_cfg {
	std::string ip, cn, host, get;
	uint16_t port;
	bool rfc8484;
};

extern std::map<std::string, struct a_ns_cfg> *ns_cfg;


int parse_config(const std::string &cfgbase);


}


// Experimental: trying to avoid #ifdef macros in .cc files by using "if constexpr (WANT_TLS_0RTT)"
// but this requires to *declare* SSL_write_early_data() etc. in the false-case, since the compiler
// will evaluate the false-branch nevertheless, unlike with #ifdefs. This means that any potential
// function thats called but not available in the false case needs to be declared to make the
// syntax checker of the cc run happy, even though it won't be necessary to define these functions
// as they are not linked (the code is "compiled", but no machine code is generated for it).
// All this needs to be outside of the config namespace to not have ugly ns qualifiers in the code later
// (the SSL_ functions are global and calling them from within constexr blocks should look natural).
#ifdef TLS_0RTT
constexpr bool WANT_TLS_0RTT = 1;

enum { EARLY_DATA_ACCEPTED = SSL_EARLY_DATA_ACCEPTED };

#else
constexpr bool WANT_TLS_0RTT = 0;

// Need to substitute the SSL * by void *, so that there are no ambigious calls
// in case TLS_0RTT is false but the functions are nevertheless already defined
// by ssl libs.
int SSL_write_early_data(void *, const void *, size_t, size_t *);

int SSL_get_early_data_status(const void *);

uint32_t SSL_SESSION_get_max_early_data(const void *);

// will not result in actual code, so we can define any value if early data
// is not available in the libs
enum { EARLY_DATA_ACCEPTED = 0 };

#endif

}

#endif

