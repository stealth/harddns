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
#include <sys/types.h>
#include <sys/socket.h>
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


// construct a DNS query for rfc8484
string make_query(const string &name, uint16_t qtype)
{
	timeval tv = {0, 0};
	gettimeofday(&tv, nullptr);

	string dns_query = "", qname = "", b64query = "";

	uint16_t qclass = htons(1);

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

int dnshttps::get(const string &name, uint16_t qtype, dns_reply &result, string &raw)
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
			string b64 = make_query(name, qtype);
			if (!b64.size())
				return build_error("Failed to create rfc8484 request.", -1);
			req += b64;
		} else {
			req += name;

			if (qtype == htons(dns_type::A))
				req += "&type=A";
			else if (qtype == htons(dns_type::AAAA))
				req += "&type=AAAA";
			else if (qtype == htons(dns_type::NS))
				req += "&type=NS";
			else if (qtype == htons(dns_type::MX))
				req += "&type=MX";
			else
				return build_error("Can't handle query type.", -1);
		}

		req += " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: harddns 0.56 github.com/stealth/harddns\r\nConnection: Keep-Alive\r\n";

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
			if (ssl->connect(ns, cfg->second.port) < 0) {
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
			int r = 0;
			if (cfg->second.rfc8484)
				r = parse_rfc8484(name, qtype, result, raw, reply, content_idx, cl);
			else
				r = parse_json(name, qtype, result, raw, reply, content_idx, cl);

			if (r >= 0)
				return r;

			syslog(LOG_INFO, "Error when parsing reply from %s for %s: %s", ns.c_str(), name.c_str(), this->why());
			ssl->close();
			continue;
		}
	}

	return 0;
}


int dnshttps::parse_rfc8484(const string &name, uint16_t type, dns_reply &result, string &raw, const string &reply, string::size_type content_idx, size_t cl)
{
	string dns_reply = "", tmp = "";
	string::size_type idx = string::npos, aidx = string::npos;
	bool has_answer = 0;
	unsigned int acnt = 0;

	if (cl > 0 && content_idx != string::npos) {
		dns_reply = reply.substr(content_idx);
		if (dns_reply.size() < cl)
			return build_error("Incomplete read from rfc8484 server.", -1);
	} else {
		// parse chunked encoding
		idx = reply.find("\r\n\r\n");
		if (idx == string::npos || idx + 4 >= reply.size())
			return build_error("Invalid reply (1).", -1);
		idx += 4;
		for (;;) {
			string::size_type nl = reply.find("\r\n", idx);
			if (nl == string::npos || nl + 2 > reply.size())
				return build_error("Invalid reply (2).", -1);
			cl = strtoul(reply.c_str() + idx, nullptr, 16);

			// end of chunk?
			if (cl == 0)
				break;

			if (cl > 65535 || nl + 2 + cl + 2 > reply.size())
				return build_error("Invalid reply (3).", -1);
			idx = nl + 2;
			dns_reply += reply.substr(idx, cl);
			idx += cl + 2;
		}
	}

	// For rfc8484, do not pass around the raw (binary) message, which would potentially
	// be used for logging. Unused by now.
	raw = "rfc8484 answer";

	if (dns_reply.size() < sizeof(dnshdr) + 5)
		return build_error("Invalid reply (4).", -1);

	const dnshdr *dhdr = reinterpret_cast<const dnshdr *>(dns_reply.c_str());

	if (dhdr->qr != 1)
		return build_error("Invalid DNS header. Not a reply.", -1);

	if (dhdr->rcode != 0)
		return build_error("DNS error response from server.", 0);

	string aname = "", cname = "", fqdn = "";
	idx = sizeof(dnshdr);
	int qnlen = qname2host(dns_reply, tmp, idx);
	if (qnlen <= 0 || idx + qnlen + 2*sizeof(uint16_t) >= dns_reply.size())
		return build_error("Invalid reply (5).", -1);
	fqdn = lcs(tmp);
	if (lcs(string(name + ".")) != fqdn)
		return build_error("Wrong name in awnser.", -1);

	idx += qnlen + 2*sizeof(uint16_t);
	aidx = idx;

	uint16_t rdlen = 0, qtype = 0, qclass = 0;
	uint32_t ttl = 0;

	// first of all, find all CNAMEs for desired name
	map<string, int> fqdns{{fqdn, 1}};

	for (int i = 0;; ++i) {
		if (idx >= dns_reply.size())
			break;

		// also handles compressed labels
		if ((qnlen = qname2host(dns_reply, tmp, idx)) <= 0)
			return build_error("Invalid reply (6).", -1);
		aname = lcs(tmp);

		// 10 -> qtype, qclass, ttl, rdlen
		if (idx + qnlen + 10 >= dns_reply.size())
			return build_error("Invalid reply (7).", -1);
		idx += qnlen;
		qtype = *reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx);
		idx += sizeof(uint16_t);
		qclass = *reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx);
		idx += sizeof(uint16_t);
		ttl = *reinterpret_cast<const uint32_t *>(dns_reply.c_str() + idx);
		idx += sizeof(uint32_t);
		rdlen = ntohs(*reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx));
		idx += sizeof(uint16_t);

		if (idx + rdlen > dns_reply.size() || qclass != htons(1) || rdlen == 0)
			return build_error("Invalid reply (8).", -1);

		if (qtype == htons(dns_type::CNAME)) {
			if (qname2host(dns_reply, tmp, idx) <= 0)
				return build_error("Invalid reply (9).", -1);
			cname = lcs(tmp);

			if (fqdns.count(aname) > 0) {
				fqdns[cname] = 1;

				// For NSS module, to have fqdn aliases w/o decoding avail
				result[acnt++] = {"NSS CNAME", 0, 0, ntohl(ttl), cname};
			}
		}

		idx += rdlen;
	}

	idx = aidx;
	for (int i = 0;; ++i) {
		if (idx >= dns_reply.size())
			break;

		// unlike in CNAME parsing loop, do not convert answer to lowercase,
		// as we want to put original name into answer
		if ((qnlen = qname2host(dns_reply, aname, idx)) <= 0)
			return build_error("Invalid reply (10).", -1);

		// 10 -> qtype, qclass, ttl, rdlen
		if (idx + qnlen + 10 >= dns_reply.size())
			return build_error("Invalid reply (11).", -1);
		idx += qnlen;
		qtype = *reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx);
		idx += sizeof(uint16_t);
		qclass = *reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx);
		idx += sizeof(uint16_t);
		ttl = *reinterpret_cast<const uint32_t *>(dns_reply.c_str() + idx);
		idx += sizeof(uint32_t);
		rdlen = ntohs(*reinterpret_cast<const uint16_t *>(dns_reply.c_str() + idx));
		idx += sizeof(uint16_t);

		if (idx + rdlen > dns_reply.size() || qclass != htons(1) || rdlen == 0)
			return build_error("Invalid reply (12).", -1);

		// Need to call host2qname() on orig embedded answer name,
		// because it may contain compression
		string qname = "";
		if (host2qname(aname, qname) <= 0)
			return build_error("Invalid reply (13).", -1);

		answer_t dns_ans{qname, qtype, qclass, ttl};

		if (qtype == htons(dns_type::A) && fqdns.count(lcs(aname)) > 0) {
			if (rdlen != 4)
				return build_error("Invalid reply.", -1);
			dns_ans.rdata = dns_reply.substr(idx, 4);
			result[acnt++] = dns_ans;
			has_answer = 1;
		} else if (qtype == htons(dns_type::AAAA) && fqdns.count(lcs(aname)) > 0) {
			if (rdlen != 16)
				return build_error("Invalid reply (14).", -1);
			dns_ans.rdata = dns_reply.substr(idx, 16);
			result[acnt++] = dns_ans;
			has_answer = 1;
		} else if (qtype == htons(dns_type::CNAME)) {
			string qcname = "";
			// uncompress cname answer
			if (qname2host(dns_reply, cname, idx) <= 0)
				return build_error("Invalid reply (15).", -1);
			if (host2qname(cname, qcname) <= 0)
				return build_error("Invalid reply (16).", -1);
			dns_ans.rdata = qcname;
			result[acnt++] = dns_ans;
		} else if (qtype == htons(dns_type::NS) && qtype == type) {
			//XXX: handle decompression
			dns_ans.rdata = dns_reply.substr(idx, rdlen);
			result[acnt++] = dns_ans;
			has_answer = 1;
		} else if (qtype == htons(dns_type::MX) && qtype == type) {
			dns_ans.rdata = dns_reply.substr(idx, rdlen);
			result[acnt++] = dns_ans;
			has_answer = 1;
		}

		idx += rdlen;
	}

	return has_answer ? 1 : 0;
}


int dnshttps::parse_json(const string &name, uint16_t type, dns_reply &result, string &raw, const string &reply, string::size_type content_idx, size_t cl)
{
	bool has_answer = 0;

	string::size_type idx = string::npos, idx2 = string::npos, aidx = string::npos;
	string json = "", tmp = "";
	unsigned int acnt = 0;

	if (cl > 0 && content_idx != string::npos) {
		json = reply.substr(content_idx);
		if (json.size() < cl)
			return build_error("Incomplete read from json server.", -1);
	} else {
		// parse chunked encoding
		idx = reply.find("\r\n\r\n");
		if (idx == string::npos || idx + 4 >= reply.size())
			return build_error("Invalid reply (1).", -1);
		idx += 4;
		for (;;) {
			string::size_type nl = reply.find("\r\n", idx);
			if (nl == string::npos || nl + 2 > reply.size())
				return build_error("Invalid reply.", -1);
			cl = strtoul(reply.c_str() + idx, nullptr, 16);

			// end of chunk?
			if (cl == 0)
				break;

			if (cl > 65535 || nl + 2 + cl + 2 > reply.size())
				return build_error("Invalid reply.", -1);
			idx = nl + 2;
			json += reply.substr(idx, cl);
			idx += cl + 2;
		}
	}

	raw = json;
	json = lcs(raw);

	//printf(">>>> %s @ %s\n", name.c_str(), raw.c_str());

	// Who needs boost property tree json parsers??
	// Turns out, C++ data structures were not really made for JSON. Maybe CORBA...
	json.erase(remove(json.begin(), json.end(), ' '), json.end());

	if (json.find("{\"status\":0") != 0)
		return 0;
	if ((idx = json.find("\"answer\":[")) == string::npos)
		return 0;
	idx += 10;
	aidx = idx;

	// first of all, find all CNAMEs
	string s = lcs(name);
	map<string, int> fqdns{{s, 1}};
	for (int level = 0; level < 10; ++level) {
		if (!valid_name(s))
			return build_error("Invalid DNS name.", -1);;
		string cname = "\"name\":\"" + s;
		if (s[s.size() - 1] != '.')
			cname += ".";
		cname += "\",\"type\":5,\"ttl\":";

		if ((idx = json.find(cname, idx)) == string::npos)
			break;
		idx += cname.size();

		uint32_t ttl = strtoul(json.c_str() + idx, nullptr, 10);
		if ((idx = json.find("\"data\":\"", idx)) == string::npos)
			break;
		idx += 8;
		if ((idx2 = json.find("\"", idx)) == string::npos)
			break;
		tmp = json.substr(idx, idx2 - idx);
		idx = idx2;
		if (!valid_name(tmp))
			return build_error("Invalid DNS name.", -1);

		if (tmp[tmp.size() - 1] == '.')
			tmp.erase(tmp.size() - 1, 1);

		string qname = "", cqname = "";
		if (host2qname(s, qname) <= 0)
			break;
		if (host2qname(tmp, cqname) <= 0)
			break;

		result[acnt++] = {qname, htons(dns_type::CNAME), htons(1), htonl(ttl), cqname};

		// for NSS module, to have fqdn alias w/o decoding avail
		result[acnt++] = {"NSS CNAME", 0, 0, ttl, tmp};

		if (fqdns.count(s) > 0)
			fqdns[tmp] = 1;

		//syslog(LOG_INFO, ">>>> CNAME %s -> %s\n", s.c_str(), tmp.c_str());
		s = tmp;
	}

	// now for the other records for original name and all CNAMEs
	for (auto it = fqdns.begin(); it != fqdns.end(); ++it) {

		if (!valid_name(it->first))
			continue;

		for (idx = aidx; idx <= json.size();) {

			char data[16] = {0};

			string ans = "\"name\":\"" + it->first;
			if ((it->first)[it->first.size() - 1] != '.')
				ans += ".";
			ans += "\",\"type\":";
			if ((idx = json.find(ans, idx)) == string::npos)
				break;
			idx += ans.size();
			uint16_t atype = (uint16_t)strtoul(json.c_str() + idx, nullptr, 10);

			ans = ",\"ttl\":";
			if ((idx = json.find(ans, idx)) == string::npos)
				break;
			idx += ans.size();

			uint32_t ttl = strtoul(json.c_str() + idx, nullptr, 10);
			if ((idx = json.find("\"data\":\"", idx)) == string::npos)
				break;
			idx += 8;
			if ((idx2 = json.find("\"", idx)) == string::npos)
				break;
			tmp = json.substr(idx, idx2 - idx);
			idx = idx2;

			string qname = "";
			if (host2qname(it->first, qname) <= 0)
				break;

			answer_t dns_ans{qname, htons(atype), htons(1), htonl(ttl)};

			if (atype == dns_type::A) {
				if (inet_pton(AF_INET, tmp.c_str(), data) == 1) {
					dns_ans.rdata = string(data, 4);
					result[acnt++] = dns_ans;
					has_answer = 1;
				}
			} else if (atype == dns_type::AAAA) {
				if (inet_pton(AF_INET6, tmp.c_str(), data) == 1) {
					dns_ans.rdata = string(data, 16);
					result[acnt++] = dns_ans;
					has_answer = 1;
				}
			} else if (atype == dns_type::NS) {
				if (!valid_name(tmp))
					return build_error("Invalid DNS name.", -1);

				if (tmp[tmp.size() - 1] == '.')
					tmp.erase(tmp.size() - 1, 1);

				if (host2qname(tmp, qname) <= 0)
					break;
				dns_ans.rdata = qname;
				result[acnt++] = dns_ans;
				has_answer = 1;
			} else if (type == dns_type::MX) {
			}
		}
	}

	return has_answer ? 1 : 0;
}

}

