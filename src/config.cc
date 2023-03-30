/*
 * This file is part of harddns.
 *
 * (C) 2016-2020 by Sebastian Krahmer,
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

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <string>
#include <list>
#include <map>
#include <stdint.h>
#include <unistd.h>
#include "config.h"


namespace harddns {

namespace config {


using namespace std;


// must be pointers, as the C++ environment may not be set up
// already (global "string" variables properly initialized) when we parse
// and asign to here
list<string> *ns = nullptr;
map<string, struct a_ns_cfg> *ns_cfg = nullptr;

// map internal domain to internal NS IP
map<string, string> internal_domains;

bool log_requests = 0, nss_aaaa = 0, cache_PTR = 0;


int parse_config(const string &cfgbase)
{
	char buf[1024] = {0};
	FILE *f	= nullptr;

	if (!(ns = new (nothrow) list<string>))
		return -1;
	if (!(ns_cfg = new (nothrow) map<string, struct a_ns_cfg>))
		return -1;

	if (!(f = fopen((cfgbase + "/harddns.conf").c_str(), "r")))
		return -1;

	string sline = "", ns = "";

	for (;!feof(f);) {
		memset(buf, 0, sizeof(buf));
		if (!fgets(buf, sizeof(buf) - 1, f))
			break;
		sline = buf;

		sline.erase(remove(sline.begin(), sline.end(), ' '), sline.end());
		sline.erase(remove(sline.begin(), sline.end(), '\t'), sline.end());
		sline.erase(remove(sline.begin(), sline.end(), '\n'), sline.end());

		if (sline.find("log_requests") == 0)
			config::log_requests = 1;
		else if (sline.find("nss_aaaa") == 0)
			config::nss_aaaa = 1;
		else if (sline.find("internal_domain=") == 0) {
			string::size_type comma = sline.find(",");
			if (comma != string::npos && comma > 16)
				config::internal_domains[sline.substr(16, comma - 16)] = sline.substr(comma + 1);
		} else if (sline.find("rfc8484") == 0) {
			config::ns_cfg->find(ns)->second.rfc8484 = 1;
		} else if (sline.find("nameserver=") == 0) {
			ns = sline.substr(11);
			config::ns->push_back(ns);
			config::ns_cfg->insert(make_pair(ns, a_ns_cfg{ns, "no-cn", "no-host", "no-get", 443, 0}));
		} else if (sline.find("cn=") == 0) {
			config::ns_cfg->find(ns)->second.cn = sline.substr(3);
		} else if (sline.find("host=") == 0) {
			config::ns_cfg->find(ns)->second.host = sline.substr(5);
		} else if (sline.find("get=") == 0) {
			config::ns_cfg->find(ns)->second.get = sline.substr(4);
		} else if (sline.find("port=") == 0) {
			config::ns_cfg->find(ns)->second.port = (uint16_t)strtoul(sline.c_str() + 5, nullptr, 10);
		}
	}

	fclose(f);
	return 0;
}

}	// namespace

}	// namespace

