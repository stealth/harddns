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
#include <sys/time.h>
#include <syslog.h>
#include "misc.h"
#include "dnshttps.h"
#include "net-headers.h"
#include "base64.h"
#include "config.h"


namespace harddns {

using namespace std;
using namespace net_headers;


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


// construct a DNS query for rfc8484
string make_query(const string &name, int af)
{
	timeval tv = {0, 0};
	gettimeofday(&tv, nullptr);

	string dns_query = "", qname = "", b64query = "";

	uint16_t qclass = htons(1), qtype = (af == AF_INET ? htons(dns_type::A) : htons(dns_type::AAAA));

	dnshdr qhdr;
	qhdr.q_count = htons(1);
	qhdr.qr = 0;
	qhdr.rd = 1;
	qhdr.id = tv.tv_usec % 0xffff;

	host2qname(name, qname);
	if (!qname.size())
		return b64query;

	dns_query = string(reinterpret_cast<char *>(&qhdr), sizeof(qhdr));
	dns_query += qname;
	dns_query += string(reinterpret_cast<char *>(&qtype), sizeof(uint16_t));
	dns_query += string(reinterpret_cast<char *>(&qclass), sizeof(uint16_t));

	b64url_encode(dns_query, b64query);
	return b64query;
}


// https://developers.google.com/speed/public-dns/docs/dns-over-https
// https://developers.cloudflare.com/1.1.1.1/dns-over-https/
// https://www.quad9.net/doh-quad9-dns-servers
// https://tools.ietf.org/html/rfc8484

int dnshttps::get(const string &name, int af, map<string, string> &result, uint32_t &ttl, string &raw)
{
	// don't:
	//result.clear();
	raw = "";

	if (!ssl || !config::ns)
		return build_error("Not properly initialized.", -1);

	if (!valid_name(name))
		return build_error("Invalid FQDN", -1);

	for (unsigned int i = 0; i < config::ns->size(); ++i) {

		string ns = ssl->peer();

		if (ns.size() == 0) {
			ns = config::ns->front();

			// cycle through list of DNS servers
			config::ns->push_back(ns);
			config::ns->pop_front();
		}

		const auto &cfg = config::ns_cfg->find(ns);
		if (cfg == config::ns_cfg->end())
			continue;
		const string &get = cfg->second.get;
		const string &host = cfg->second.host;

		//printf(">>>> %s %s %s %s\n", cfg->second.ip.c_str(), cfg->second.get.c_str(), cfg->second.host.c_str(), cfg->second.cn.c_str());

		string req = "GET " + get, reply = "", tmp = "";

		if (cfg->second.rfc8484) {
			string b64 = make_query(name, af);
			if (!b64.size())
				return build_error("Failed to create rfc8484 request.", -1);
			req += b64;
		} else {
			req += name;

			if (af == AF_INET)
				req += "&type=A";
			else if (af == AF_INET6)
				req += "&type=AAAA";
			else
				req += "&type=A";
		}

		req += " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: harddns 0.53\r\nConnection: Keep-Alive\r\n";

		if (cfg->second.rfc8484)
			req += "Accept: application/dns-message\r\n";
		else
			req += "Accept: application/dns-json\r\n";


		if (req.size() < 450)
			req += "X-Igno: " + string(450 - req.size(), 'X');

		req += "\r\n\r\n";

		//printf(">>>> %s\n", req.c_str());

		// maybe closed due to error or not initialized in the first place
		if (ssl->send(req) <= 0) {
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
		}

		string::size_type idx = string::npos, content_idx = string::npos;
		size_t cl = 0;
		const int maxtries = 3;
		bool has_answer = 0;

		for (int j = 0; j < maxtries; ++j) {
			if (ssl->recv(tmp) <= 0) {
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
		else {
			if (cfg->second.rfc8484)
				return parse_rfc8484(name, af, result, ttl, raw, reply, content_idx, cl);
			else
				return parse_json(name, af, result, ttl, raw, reply, content_idx, cl);
		}
	}

	return 0;
}


int dnshttps::parse_rfc8484(const string &name, int af, map<string, string> &result, uint32_t &ttl, string &raw, const string &reply, string::size_type content_idx, size_t cl)
{
	string dns_reply = "", tmp = "";
	string::size_type idx = string::npos, aidx = string::npos;
	bool has_answer = 0;

	if (cl > 0 && content_idx != string::npos) {
		dns_reply = reply.substr(content_idx);
		if (dns_reply.size() < cl)
			return build_error("Incomplete read from rfc8484 server.", -1);
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
			dns_reply += reply.substr(idx, cl);
			idx += cl + 2;
		}
	}

	// For rfc8484, do not pass around the raw (binary) message, which would potentially
	// be used for logging. Unused by now.
	raw = "";

	if (dns_reply.size() < sizeof(dnshdr) + 5)
		return build_error("Invalid reply.", -1);

	const dnshdr *dhdr = reinterpret_cast<const dnshdr *>(dns_reply.c_str());

	if (dhdr->qr != 1)
		return build_error("Invalid DNS header. Not a reply.", -1);

	if (dhdr->rcode != 0)
		return build_error("DNS error response from server.", -1);

	string aname = "", cname = "", fqdn = "";
	idx = sizeof(dnshdr);
	int qnlen = qname2host(dns_reply, fqdn, idx);
	if (qnlen <= 0 || idx + qnlen + 2*sizeof(uint16_t) >= dns_reply.size())
		return build_error("Invalid reply.", -1);
	if (string(name + ".") != fqdn)
		return build_error("Wrong name in awnser.", -1);

	idx += qnlen + 2*sizeof(uint16_t);
	aidx = idx;

	ttl = 60*60;

	uint16_t rdlen = 0, qtype = 0, qclass = 0;
	uint32_t cttl = 0;

	// first of all, find all CNAMEs for desired name
	map<string, int> fqdns{{fqdn, 1}};

	for (int i = 0;; ++i) {
		if (idx >= dns_reply.size())
			break;

		// also handles compressed labels
		if ((qnlen = qname2host(dns_reply, aname, idx)) <= 0)
			return build_error("Invalid reply.", -1);;

		// 10 -> qtype, qclass, ttl, rdlen
		if (idx + qnlen + 10 >= dns_reply.size())
			return build_error("Invalid reply.", -1);
		idx += qnlen;
		qtype = *reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx);
		idx += sizeof(uint16_t);
		qclass = *reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx);
		idx += sizeof(uint16_t);
		cttl = ntohl(*reinterpret_cast<const uint32_t *>(dns_reply.c_str() + idx));
		if (ttl > cttl)
			ttl = cttl;
		idx += sizeof(uint32_t);
		rdlen = ntohs(*reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx));
		idx += sizeof(uint16_t);

		if (idx + rdlen > dns_reply.size() || qclass != htons(1) || rdlen == 0)
			return build_error("Invalid reply.", -1);

		if (qtype == htons(dns_type::CNAME)) {
			if (qname2host(dns_reply, cname, idx) <= 0)
				return build_error("Invalid reply.", -1);;

			if (fqdns.count(aname) > 0)
				fqdns[cname] = 1;
		}

		idx += rdlen;
	}

	idx = aidx;
	for (int i = 0;; ++i) {
		if (idx >= dns_reply.size())
			break;

		if ((qnlen = qname2host(dns_reply, aname, idx)) <= 0)
			return build_error("Invalid reply.", -1);

		// 10 -> qtype, qclass, ttl, rdlen
		if (idx + qnlen + 10 >= dns_reply.size())
			return build_error("Invalid reply.", -1);
		idx += qnlen;
		qtype = *reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx);
		idx += sizeof(uint16_t);
		qclass = *reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx);
		idx += sizeof(uint16_t);

		// TTL. was already calculated last loop
		idx += sizeof(uint32_t);

		rdlen = ntohs(*reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx));
		idx += sizeof(uint16_t);

		if (idx + rdlen > dns_reply.size() || qclass != htons(1) || rdlen == 0)
			return build_error("Invalid reply.", -1);

		if (qtype == htons(dns_type::A) && fqdns.count(aname) > 0) {
			if (rdlen != 4)
				return build_error("Invalid reply.", -1);
			result[dns_reply.substr(idx, 4)] = "A";
			if (af == AF_INET || af == AF_UNSPEC)
				has_answer = 1;
		} else if (qtype == htons(dns_type::AAAA) && fqdns.count(aname) > 0) {
			if (rdlen != 16)
				return build_error("Invalid reply.", -1);
			result[dns_reply.substr(idx, 16)] = "AAAA";
			if (af == AF_INET6 || af == AF_UNSPEC)
				has_answer = 1;
		}

		idx += rdlen;
	}

	return has_answer ? 1 : 0;
}


int dnshttps::parse_json(const string &name, int af, map<string, string> &result, uint32_t &ttl, string &raw, const string &reply, string::size_type content_idx, size_t cl)
{
	bool has_answer = 0;

	string::size_type idx = string::npos, idx2 = string::npos, aidx = string::npos;
	string json = "", tmp = "";

	if (cl > 0 && content_idx != string::npos) {
		json = reply.substr(content_idx);
		if (json.size() < cl)
			return build_error("Incomplete read from json server.", -1);
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

	//printf(">>>> %s @ %s\n", name.c_str(), raw.c_str());

	// Who needs boost property tree json parsers??
	// Turns out, C++ data structures were not really made for JSON. Maybe CORBA...
	json.erase(remove(json.begin(), json.end(), ' '), json.end());

	if (json.find("{\"Status\":0") != 0)
		return 0;
	if ((idx = json.find("\"Answer\":[")) == string::npos)
		return 0;
	idx += 10;
	aidx = idx;

	ttl = 60*60;

	// first of all, find all CNAMEs
	vector<string> fqdns{name};
	string s = name;
	for (int level = 0; level < 10; ++level) {
		string cname = "\"name\":\"" + s;
		if (s[s.size() - 1] != '.')
			cname += ".";
		cname += "\",\"type\":5,\"TTL\":";

		if ((idx = json.find(cname, idx)) == string::npos)
			break;
		idx += cname.size();

		// take minimum ttl
		uint32_t cttl = strtoul(json.c_str() + idx, nullptr, 10);
		if (ttl > cttl)
			ttl = cttl;
		if ((idx = json.find("\"data\":\"", idx)) == string::npos)
			break;
		idx += 8;
		if ((idx2 = json.find("\"", idx)) == string::npos)
			break;
		tmp = json.substr(idx, idx2 - idx);
		idx = idx2;
		if (!valid_name(tmp))
			return build_error("Invalid DNS name.", -1);

		result[tmp] = "CNAME";
		fqdns.push_back(tmp);
		//printf(">>>> CNAME %s -> %s\n", s.c_str(), tmp.c_str());
		s = tmp;
	}

	idx = aidx;

	// now for the A and AAAA records for original name and all CNAMEs
	for (auto it = fqdns.begin(); it != fqdns.end(); ++it) {

		//printf(">>>> A/AAAA for %s\n", it->c_str());

		char data[16] = {0};

		string v4a = "\"name\":\"" + *it;
		if ((*it)[it->size() - 1] != '.')
			v4a += ".";
		v4a += "\",\"type\":1,\"TTL\":";

		string v6a = "\"name\":\"" + *it;
		if ((*it)[it->size() - 1] != '.')
			v6a += ".";
		v6a += "\",\"type\":28,\"TTL\":";

		for (;af == AF_INET || af == AF_UNSPEC;) {
			if ((idx = json.find(v4a, idx)) == string::npos)
				break;
			idx += v4a.size();

			uint32_t cttl = strtoul(json.c_str() + idx, nullptr, 10);
			if (ttl > cttl)
				ttl = cttl;
			if ((idx = json.find("\"data\":\"", idx)) == string::npos)
				break;
			idx += 8;
			if ((idx2 = json.find("\"", idx)) == string::npos)
				break;
			tmp = json.substr(idx, idx2 - idx);
			idx = idx2;
			if (inet_pton(AF_INET, tmp.c_str(), data) == 1) {
				//printf(">>>> AF_INET -> %s\n", tmp.c_str());
				result[string(data, 4)] = "A";
				has_answer = 1;
			}
		}

		idx = aidx;

		for (;af == AF_INET6 || af == AF_UNSPEC;) {
			if ((idx = json.find(v6a, idx)) == string::npos)
				break;
			idx += v6a.size();

			uint32_t cttl = strtoul(json.c_str() + idx, nullptr, 10);
			if (ttl > cttl)
				ttl = cttl;
			if ((idx = json.find("\"data\":\"", idx)) == string::npos)
				break;
			idx += 8;
			if ((idx2 = json.find("\"", idx)) == string::npos)
				break;
			tmp = json.substr(idx, idx2 - idx);
			idx = idx2;
			if (inet_pton(AF_INET6, tmp.c_str(), data) == 1) {
				//printf(">>>> AF_INET6 -> %s\n", tmp.c_str());
				result[string(data, 16)] = "AAAA";
				has_answer = 1;
			}
		}

	}

	return has_answer ? 1 : 0;
}

}

