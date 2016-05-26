/*
 * This file is part of harddns.
 *
 * (C) 2016 by Sebastian Krahmer,
 *             sebastian [dot] krahmer [at] gmail [dot] com
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

#ifndef harddns_https_h
#define harddns_https_h

#include <stdint.h>
#include <string>
#include <map>
#include "ssl.h"


namespace harddns {

class dnshttps {

	std::string err;

	ssl_box *ssl;

	template<class T>
	T build_error(const std::string &msg, T r)
	{
		int e = 0;
		err = "dnshttps::";
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

	dnshttps(ssl_box *s)
		: ssl(s)
	{
	}

	virtual ~dnshttps()
	{
	}

	const char *why()
	{
		return err.c_str();
	}

	int get(const std::string &, int, std::map<std::string, int> &, uint32_t &, std::string &);
};


extern dnshttps *dns;

}

#endif

