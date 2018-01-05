/*
 * This file is part of harddns.
 *
 * (C) 2016-2018 by Sebastian Krahmer,
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

#include <string>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <map>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dnshttps.h"
#include "config.h"


namespace harddns {

using namespace std;


dnshttps *dns = nullptr;


// check charset, dont check label size
static bool valid_name(const string &name)
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


int dnshttps::get(const string &name, int af, map<string, int> &result, uint32_t &ttl, string &raw)
{

	result.clear();
	raw = "";
	ttl = 0;

	if (!ssl || !config::ns)
		return build_error("Not properly initialized.", -1);

	if (!valid_name(name))
		return build_error("Invalid FQDN", -1);

	string req = "GET /resolve?name=" + name, reply = "", tmp = "";
	req += "&edns_client_subnet=0.0.0.0/0";
	if (af == AF_INET)
		req += "&type=A";
	else if (af == AF_INET6)
		req += "&type=AAAA";
	else
		req += "&type=ANY";

	req += " HTTP/1.1\r\nHost: dns.google.com\r\nUser-Agent: harddns 0.1\r\nConnection: Keep-Alive\r\n";

	if (req.size() < 450)
		req += "X-Igno: " + string('X', 450 - req.size());

	req += "\r\n\r\n";


	// maybe closed due to error or not initialized in the first place
	if (ssl->send(req) < 0) {
		if (ssl->connect_ssl(*config::ns) < 0)
			return build_error("No SSL connection:" + string(ssl->why()), -1);
		if (ssl->send(req) != (int)req.size()) {
			ssl->close();
			return build_error("Unable to complete request.", -1);
		}
	}

	string::size_type idx = string::npos, content_idx = string::npos;
	size_t cl = 0;
	int i = 0, maxtries = 3;
	for (i = 0; i < maxtries; ++i) {
		if (ssl->recv(tmp) < 0) {
			ssl->close();
			return build_error("Error when receiving reply:" + string(ssl->why()), -1);
		}
		reply += tmp;

		if (reply.find("HTTP/1.1 200 OK") == string::npos) {
			ssl->close();
			return build_error("Error response from server.", -1);
		}

		if (reply.find("Transfer-Encoding: chunked\r\n") != string::npos && reply.find("\r\n0\r\n\r\n") != string::npos)
			break;

		if (cl == 0 && (idx = reply.find("Content-Length:")) != string::npos) {
			idx += 15;
			if (idx >= reply.size())
				continue;

			cl = strtoul(reply.c_str() + idx, nullptr, 10);
			if (cl > 65535) {
				ssl->close();
				return build_error("Insanely large reply.", -1);
			}
		}

		if (cl > 0 && (content_idx = reply.find("\r\n\r\n")) != string::npos) {
			content_idx += 4;
			if (content_idx <= reply.size() && reply.size() - content_idx < cl)
				continue;

			break;
		}
	}

	if (i == maxtries) {
		ssl->close();
		return build_error("Reply did not arrive in time.", -1);
	}

	string json = "";
	if (cl > 0 && content_idx != string::npos)
		json = reply.substr(content_idx);
		if (json.size() < cl) {
			ssl->close();
			return build_error("Incomplete read from server.", -1);
		}
	else {
		idx = reply.find("\r\n\r\n");
		if (idx == string::npos || idx + 4 >= reply.size()) {
			ssl->close();
			return build_error("Invalid reply.", -1);
		}
		idx += 4;
		for (;;) {
			string::size_type nl = reply.find("\r\n", idx);
			if (nl == string::npos || nl + 2 > reply.size()) {
				ssl->close();
				return build_error("Invalid reply.", -1);
			}
			cl = strtoul(reply.c_str() + idx, nullptr, 16);

			// end of chunk?
			if (cl == 0)
				break;

			if (cl > 65535 || nl + 2 + cl > reply.size()) {
				ssl->close();
				return build_error("Invalid reply.", -1);
			}
			idx = nl + 2;
			json += reply.substr(idx, cl);
			idx += cl + 2;
		}
	}

	raw = json;

	// Who needs boost property tree json parsers??
	// Turns out, C++ data structures were not really made for JSON. Maybe CORBA...
	json.erase(remove(json.begin(), json.end(), ' '), json.end());

	if (json.find("{\"Status\":0") != 0)
		return 0;
	if ((idx = json.find("\"Answer\":[")) == string::npos)
		return 0;


	idx += 10;
	char data[16] = {0};
	string::size_type idx2 = 0;

#ifdef STRICT_ANSWER
	string::size_type aidx = idx;

	string v4a = "\"name\":\"" + name;
	if (name[name.size() - 1] != '.')
		v4a += ".";
	v4a += "\",\"type\":1,\"TTL\":";

	string v6a = "\"name\":\"" + name;
	if (name[name.size() - 1] != '.')
		v6a += ".";
	v6a += "\",\"type\":28,\"TTL\":";

	for (;af == AF_INET || af == AF_UNSPEC;) {
		if ((idx = json.find(v4a, idx)) == string::npos)
			break;
		idx += v4a.size();

		// take first ttl
		if (ttl == 0)
			ttl = strtoul(json.c_str() + idx, nullptr, 10);
		if ((idx = json.find("\"data\":\"", idx)) == string::npos)
			break;
		idx += 8;
		if ((idx2 = json.find("\"", idx)) == string::npos)
			break;
		tmp = json.substr(idx, idx2 - idx);
		idx = idx2;
		if (inet_pton(AF_INET, tmp.c_str(), data) == 1)
			result[string(data, 4)] = AF_INET;
	}

	idx = aidx;

	for (;af == AF_INET6 || af == AF_UNSPEC;) {
		if ((idx = json.find(v6a, idx)) == string::npos)
			break;
		idx += v6a.size();

		// take first ttl
		if (ttl == 0)
			ttl = strtoul(json.c_str() + idx, nullptr, 10);
		if ((idx = json.find("\"data\":\"", idx)) == string::npos)
			break;
		idx += 8;
		if ((idx2 = json.find("\"", idx)) == string::npos)
			break;
		tmp = json.substr(idx, idx2 - idx);
		idx = idx2;
		if (inet_pton(AF_INET6, tmp.c_str(), data) == 1)
			result[string(data, 16)] = AF_INET6;
	}

#else
	for (;;) {
		if ((idx = json.find("\"data\":\"", idx)) == string::npos)
			break;
		idx += 8;
		if ((idx2 = json.find("\"", idx)) == string::npos)
			break;
		tmp = json.substr(idx, idx2 - idx);
		idx = idx2;
		if (inet_pton(AF_INET, tmp.c_str(), data) == 1) {
			result[string(data, 4)] = AF_INET;
		} else if (inet_pton(AF_INET6, tmp.c_str(), data) == 1) {
			result[string(data, 16)] = AF_INET6;
		}
	}
#endif

	if (ttl > 60*60)
		ttl = 60*60;

	return 0;
}

}

