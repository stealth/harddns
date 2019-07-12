/*
 * This file is part of harddns.
 *
 * (C) 2019 by Sebastian Krahmer, sebastian [dot] krahmer [at] gmail [dot] com
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

#ifndef harddns_proxy_h
#define harddns_proxy_h

#include <unistd.h>
#include <sys/time.h>
#include <map>
#include <string>
#include <utility>
#include "dnshttps.h"


namespace harddns {

class doh_proxy {

	int d_sock{-1};

	int d_af{0};

	struct cache_elem_t {
		dnshttps::dns_reply answer;
		time_t valid_until;
	};

	std::map<std::pair<std::string, uint16_t>, cache_elem_t> d_rr_cache;

	void cache_insert(const std::string &, uint16_t, const dnshttps::dns_reply &);

	bool cache_lookup(const std::string &, uint16_t, dnshttps::dns_reply &);

	// As the dnshttp object we use the globally exported 'dns'
	// as used for the NSS module

	std::string d_err{""};

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		d_err = "doh_proxy::";
		d_err += msg;
		if (errno) {
			d_err += ":";
			d_err += strerror(errno);
		}
		return r;
	}


public:

	doh_proxy()
	{
	}

	virtual ~doh_proxy()
	{
		::close(d_sock);
	}

	int init(const std::string &, const std::string &);

	int loop();

	const char *why() { return d_err.c_str(); }

};

} // namespace

#endif

