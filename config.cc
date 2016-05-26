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

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <string>
#include <unistd.h>


namespace harddns {

namespace config {


using namespace std;


// must be pointers, as the C++ environment may not be set up
// already (global "string" variables properly initialized) when we parse
// and asign to here
string *ns = nullptr;
bool log_requests = 0;


int parse_config(const string &cfgbase)
{
	char buf[1024] = {0};
	FILE *f	= nullptr;

	if (!(ns = new (nothrow) string("")))
		return -1;

	if (!(f = fopen((cfgbase + "/harddns.conf").c_str(), "r")))
		return -1;

	string sline = "";

	for (;!feof(f);) {
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf) - 1, f);
		sline = buf;

		sline.erase(remove(sline.begin(), sline.end(), ' '), sline.end());
		sline.erase(remove(sline.begin(), sline.end(), '\t'), sline.end());
		sline.erase(remove(sline.begin(), sline.end(), '\n'), sline.end());

		if (sline.find("log_requests") == 0)
			config::log_requests = 1;
		else if (sline.find("nameserver=") == 0)
			*config::ns = sline.substr(11);

	}

	fclose(f);
	return 0;
}

}	// namespace

}	// namespace
