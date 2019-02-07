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

#include <string>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <map>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
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

// https://developers.google.com/speed/public-dns/docs/dns-over-https
// https://developers.cloudflare.com/1.1.1.1/dns-over-https
// https://www.quad9.net/doh-quad9-dns-servers

int dnshttps::get(const string &name, int af, map<string, string> &result, uint32_t &ttl, string &raw)
{
	result.clear();
	raw = "";
	ttl = 0;

	if (!ssl || !config::ns)
		return build_error("Not properly initialized.", -1);

	if (!valid_name(name))
		return build_error("Invalid FQDN", -1);

	for (unsigned int i = 0; i < config::ns->size(); ++i) {

		string ns = ssl->peer();

		if (ns.size() == 0)
			ns = config::ns->front();

		const auto &cfg = config::ns_cfg->find(ns);
		if (cfg == config::ns_cfg->end())
			continue;
		const string &get = cfg->second.get;
		const string &host = cfg->second.host;

		printf(">>>> %s %s %s %s\n", cfg->second.ip.c_str(), cfg->second.get.c_str(), cfg->second.host.c_str(), cfg->second.cn.c_str());

		string req = "GET " + get + name, reply = "", tmp = "";
//		req += "&edns_client_subnet=0.0.0.0/0";
		if (af == AF_INET)
			req += "&type=A";
		else if (af == AF_INET6)
			req += "&type=AAAA";
		else
			req += "&type=ANY";

req += "&RD=1";

		req += " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: harddns 0.2\r\nConnection: Keep-Alive\r\n";

		if (req.size() < 450)
			req += "X-Igno: " + string(450 - req.size(), 'X');

		req += "\r\n\r\n";

		printf(">>>> %s\n", req.c_str());

		// maybe closed due to error or not initialized in the first place
		if (ssl->send(req) < 0) {
			ns = config::ns->front();
			if (ssl->connect_ssl(ns) < 0) {
				ssl->close();
				syslog(LOG_INFO, "No SSL connection to %s (%s)", ns.c_str(), ssl->why());
				continue;
			}
			if (ssl->send(req) != (int)req.size()) {
				ssl->close();
				syslog(LOG_INFO, "Unable to complete request to %s.", ns.c_str());
				continue;
			}

			// cycle through list of DNS servers
			config::ns->push_back(ns);
			config::ns->pop_front();
		}

		string::size_type idx = string::npos, content_idx = string::npos;
		size_t cl = 0;
		const int maxtries = 3;
		bool has_answer = 0;

		for (int j = 0; j < maxtries; ++j) {
			if (ssl->recv(tmp) < 0) {
				ssl->close();
				syslog(LOG_INFO, "Error when receiving reply from %s (%s)", ns.c_str(), ssl->why());
				break;
			}
			reply += tmp;

			if (reply.find("HTTP/1.1 200 OK") == string::npos) {
				ssl->close();
				syslog(LOG_INFO, "Error response from %s.", ns.c_str());
				break;
			}

			if (reply.find("Transfer-Encoding: chunked\r\n") != string::npos && reply.find("\r\n0\r\n\r\n") != string::npos) {
				has_answer = 1;
				break;
			}

			if (cl == 0 && (idx = reply.find("Content-Length:")) != string::npos) {
				idx += 15;
				if (idx >= reply.size())
					continue;

				cl = strtoul(reply.c_str() + idx, nullptr, 10);
				if (cl > 65535) {
					ssl->close();
					syslog(LOG_INFO, "Insanely large reply from %s", ns.c_str());
					break;
				}
			}

			if (cl > 0 && (content_idx = reply.find("\r\n\r\n")) != string::npos) {
				content_idx += 4;
				if (content_idx <= reply.size() && reply.size() - content_idx < cl)
					continue;

				has_answer = 1;
				break;
			}
		}

		if (!has_answer)
			ssl->close();
		else if (parse_json(name, af, result, ttl, raw, reply, content_idx, cl) == 0)
			return 0;
	}

	return -1;
}



int dnshttps::parse_json(const string &name, int af, map<string, string> &result, uint32_t &ttl, string &raw, const string &reply, string::size_type content_idx, size_t cl)
{
	string::size_type idx = string::npos;
	string json = "", tmp = "";

	if (cl > 0 && content_idx != string::npos) {
		json = reply.substr(content_idx);
		if (json.size() < cl)
			return build_error("Incomplete read from server.", -1);
	} else {
		// parse chunked encoding
		idx = reply.find("\r\n\r\n");
		if (idx == string::npos || idx + 4 >= reply.size())
			return build_error("Invalid reply.", -1);
		idx += 4;
		for (;;) {
			string::size_type nl = reply.find("\r\n", idx);
			if (nl == string::npos || nl + 2 > reply.size())
				return build_error("Invalid reply.", -1);
			cl = strtoul(reply.c_str() + idx, nullptr, 16);

			// end of chunk?
			if (cl == 0)
				break;

			if (cl > 65535 || nl + 2 + cl > reply.size())
				return build_error("Invalid reply.", -1);
			idx = nl + 2;
			json += reply.substr(idx, cl);
			idx += cl + 2;
		}
	}

	raw = json;

	printf(">>>> %s\n", raw.c_str());

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

	string::size_type aidx = idx;

	string v4a = "\"name\":\"" + name;
	if (name[name.size() - 1] != '.')
		v4a += ".";
	v4a += "\",\"type\":1,\"TTL\":";

	string v6a = "\"name\":\"" + name;
	if (name[name.size() - 1] != '.')
		v6a += ".";
	v6a += "\",\"type\":28,\"TTL\":";

	string cname = "\"name\":\"" + name;
	if (name[name.size() - 1] != '.')
		cname += ".";
	cname += "\",\"type\":5,\"TTL\":";

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
		if (inet_pton(AF_INET, tmp.c_str(), data) == 1) {
			printf(">>>> AF_INET -> %s\n", tmp.c_str());
			result[string(data, 4)] = "A";
		}
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
		if (inet_pton(AF_INET6, tmp.c_str(), data) == 1) {
			printf(">>>> AF_INET6 -> %s\n", tmp.c_str());
			result[string(data, 16)] = "AAAA";
		}
	}

	idx = aidx;

	for (; af == AF_UNSPEC;) {
		if ((idx = json.find(cname, idx)) == string::npos)
			break;
		idx += cname.size();

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
		result[tmp] = "CNAME";
		printf(">>>> CNAME -> %s\n", tmp.c_str());
	}

	if (ttl > 60*60)
		ttl = 60*60;

	return 0;
}

}

