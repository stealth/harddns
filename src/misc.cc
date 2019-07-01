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

#include <string>

namespace harddns {

using namespace std;

const uint8_t dns_max_label = 63;

/* "foo.bar" -> "\003foo\003bar\000"
 * automatically splits labels larger than 63 byte into
 * sub-domains
 */
int host2qname(const string &host, string &result)
{
	string split_host = "";
	string::size_type pos1 = 0, pos2 = 0;

	for (;pos1 < host.size();) {
		pos2 = host.find(".", pos1);
		if (pos2 == string::npos) {
			split_host += host.substr(pos1);
			break;
		}

		if (pos2 - pos1 > dns_max_label) {
			split_host += host.substr(pos1, dns_max_label);
			pos1 += dns_max_label;
		} else {
			split_host += host.substr(pos1, pos2 - pos1);
			pos1 = pos2 + 1;
		}

		split_host += ".";
	}

	try {
		result.clear();
		result.reserve(split_host.length() + 2);
		result.resize(split_host.length() + 2);
	} catch (...) {
		return -1;
	}

	int i = 0, j = 0, k = 0, l = 0;
	uint8_t how_much = 0;

	while (i < (int)split_host.length()) {
		l = i;
		how_much = 0;
		while (split_host[i] != '.' && i != (int)split_host.length()) {
			++how_much;
			++i;
		}
		result[j] = how_much;
		++j;
		i = l;
		for (k = 0; k < how_much; j++, i++, k++)
			result[j] = split_host[i];
		++i;
	}
	result[j] = '\0';
	return j + 1;
}


/*  "\003foo\003bar\000" -> foo.bar.
 */
int qname2host(const string &msg, string &result)
{
	string::size_type i = 0;
	uint8_t len = 0;

	result = "";
	string s = "";
	try {
		s.reserve(msg.length());
	} catch (...) {
		return -1;
	}

	while ((len = msg[i]) != 0) {
		if (len > dns_max_label)
			return -1;
		if (len + i + 1 > msg.size())
			return -1;
		s += msg.substr(i + 1, len);
		s += ".";
		i += len + 1;
	}
	result = s;
	return i + 1;
}


} // namespace

