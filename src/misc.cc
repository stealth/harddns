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
#include <cstring>
#include <cctype>
#include <algorithm>


namespace harddns {

using namespace std;

const uint8_t dns_max_label = 63;

/* "foo.bar" -> "\003foo\003bar\000"
 * "foo.bar." -> "\003foo\003bar\000"
 * automatically splits labels larger than 63 byte into
 * sub-domains
 */
int host2qname(const string &host, string &result)
{
	string split_host = "";
	string::size_type pos1 = 0, pos2 = 0;

	result = "";

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

	if (split_host.size() >= 2048)
		return -1;

	char buf[4096] = {0};
	memcpy(buf + 1, split_host.c_str(), split_host.size());

	// now, substitute dots by cnt
	string::size_type last_dot = 0;
	for (; last_dot < split_host.size();) {
		uint8_t i = 0;
		while (buf[last_dot + i] != '.' && buf[last_dot + i] != 0)
			++i;
		buf[last_dot] = i - 1;
		last_dot += i;

		// end of string without trailing "." ?
		if (buf[last_dot] == 0)
			break;
		// end with trailing "." ?
		if (buf[last_dot + 1] == 0) {
			buf[last_dot] = 0;
			break;
		}
	}

	result = string(buf, last_dot + 1);
	return last_dot + 1;
}


/*  "\003foo\003bar\000" -> foo.bar.
 */
int qname2host(const string &msg, string &result, string::size_type start_idx)
{
	string::size_type i = start_idx, r = 0;
	uint8_t len = 0, compress_depth = 0;

	result = "";
	string s = "";
	try {
		s.reserve(msg.length());
	} catch (...) {
		return -1;
	}

	while ((len = msg[i]) != 0) {
		if (len > dns_max_label) {
			// start_idx of 0 means we just have a qname string, not an entire DNS packet,
			// so we cant uncompress compressed labels
			if (start_idx == 0 || ++compress_depth > 10)
				return -1;
			// compressed?
			if (len & 0xc0) {
				if (i + 1 >= msg.size())
					return -1;
				i = msg[i + 1] & 0xff;
				if (i < 0 || i >= msg.size())
					return -1;
				// actually += 2, but the return will add 1
				// only for the first compression
				if (compress_depth <= 1)
					r += 1;
				continue;
			} else
				return -1;
		}
		if (len + i + 1 > msg.size())
			return -1;
		s += msg.substr(i + 1, len);
		s += ".";

		i += len + 1;

		if (compress_depth == 0)
			r += len + 1;
	}

	result = s;
	if (result.size() == 0)
		return 0;

	// RFC1035
	if (result.size() > 255) {
		result = "";
		return -1;
	}

	return r + 1;
}


// check charset, dont check label size
bool valid_name(const string &name)
{
	size_t l = name.size();
	if (l > 254 || l < 2)
		return 0;

	for (size_t i = 0; i < l; ++i) {
		if (name[i] >= '0' && name[i] <= '9')
			continue;
		if (name[i] >= 'a' && name[i] <= 'z')
			continue;
		if (name[i] >= 'A' && name[i] <= 'Z')
			continue;
		if (name[i] == '-' || name[i] == '.')
			continue;

		return 0;
	}

	return 1;
}


string A2PTR_fqdn(const string &rdata_A)
{
	string ret = "";
	if (rdata_A.size() != sizeof(uint32_t))
		return ret;

	char tmp[32] = {0};
	for (unsigned int i = sizeof(uint32_t); i > 0; --i) {
		snprintf(tmp, sizeof(tmp) - 1, "%d.", rdata_A[i - 1] & 0xff);
		ret += tmp;
	}
	ret += "in-addr.arpa";
	return ret;
}


string AAAA2PTR_fqdn(const string &rdata_AAAA)
{
	string ret = "";
	if (rdata_AAAA.size() != 16)
		return ret;

	char tmp[64] = {0};
	for (unsigned int i = 16; i > 0; --i) {
		snprintf(tmp, sizeof(tmp) - 1, "%1x.%1x.", rdata_AAAA[i - 1] & 0xf, (rdata_AAAA[i - 1] & 0xf0)>>4);
		ret += tmp;
	}
	ret += "ip6.arpa";
	return ret;
}


string lcs(const string &s)
{
	string rs = s;
	transform(rs.begin(), rs.end(), rs.begin(), [](unsigned char c){ return tolower(c); });
	return rs;
}


uint16_t ua_uint16(const void *vp)
{
	uint16_t x = 0;
	memcpy(&x, vp, sizeof(x));
	return x;
}


} // namespace

