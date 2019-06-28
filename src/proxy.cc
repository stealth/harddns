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

#include <map>
#include <string>
#include <utility>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "net-headers.h"
#include "proxy.h"
#include "misc.h"


namespace harddns {

using namespace std;
using namespace net_headers;


int doh_proxy::init(const string &laddr, const string &lport)
{
	addrinfo *tai = nullptr;

	if (getaddrinfo(laddr.c_str(), lport.c_str(), nullptr, &tai) != 0)
		return build_error("init: Unable to resolve local bind addr.", -1);
	free_ptr<addrinfo> ai(tai, freeaddrinfo);

	d_af = ai->ai_family;

	if ((d_sock = socket(ai->ai_family, SOCK_DGRAM, 0)) < 0)
		return build_error("init::socket:", -1);
	if (bind(d_sock, ai->ai_addr, ai->ai_addrlen) < 0)
		return build_error("init::bind:", -1);

	// No need to create a dnshttp object, it was globally created

	return 0;
}


void doh_proxy::cache_insert(const string &fqdn, int af, const string &rdata, uint32_t ttl)
{
	timeval tv;
	gettimeofday(&tv, nullptr);

	auto idx = d_rr_cache.find(make_pair(fqdn, af));

	if (idx != d_rr_cache.end())
		d_rr_cache.erase(idx);

	cache_elem_t elem{rdata, tv.tv_sec + ttl};

	d_rr_cache[make_pair(fqdn, af)] = elem;
}


bool doh_proxy::cache_lookup(const string &fqdn, int af, map<string, string> &result, uint32_t &ttl)
{
	timeval tv;
	gettimeofday(&tv, nullptr);

	if (d_rr_cache.size() == 0)
		return 0;

	auto idx = d_rr_cache.find(make_pair(fqdn, af));

	if (idx == d_rr_cache.end())
		return 0;

	auto elem = idx->second;

	if (elem.valid_until > tv.tv_sec) {
		ttl = elem.valid_until - tv.tv_sec;
		result.insert(make_pair(elem.rdata, af == AF_INET ? "A" : "AAAA"));
		return 1;
	}

	// timed out
	d_rr_cache.erase(idx);
	return 0;
}


int doh_proxy::loop()
{
	int r = 0;
	char buf[4096] = {0};
	sockaddr_in from4;
	sockaddr_in6 from6;
	sockaddr *from = reinterpret_cast<sockaddr *>(&from4);
	socklen_t flen = sizeof(from4);
	dnshdr *query = nullptr, answer;
	string fqdn = "", qname = "", raw = "", reply = "";
	map<string, string> result;
	uint16_t qtype = 0, qclass = 0;
	uint32_t ttl = 0;
	int af = 0;
	uint16_t clbl = htons(((1<<15)|(1<<14))|sizeof(dnshdr));

	if (d_af == AF_INET6) {
		from = reinterpret_cast<sockaddr *>(&from6);
		flen = sizeof(from6);
	}

	answer.qr = 1;
	answer.ra = 1;
	answer.q_count = htons(1);

	for (;;) {
		memset(buf, 0, sizeof(buf));
		if ((r = recvfrom(d_sock, buf, sizeof(buf), 0, from, &flen)) <= 0)
			continue;

		if ((size_t)r < sizeof(dnshdr) + 2*sizeof(uint16_t) + 1)
			continue;
		query = reinterpret_cast<dnshdr *>(buf);

		// query indeed?
		if (query->qr != 0 || query->opcode != 0)
			continue;
		if (query->q_count != htons(1))
			continue;

		// qnlen may be smaller than qname.size(), as there may be OPT stuff after the question
		qname = string(buf + sizeof(dnshdr), r - sizeof(dnshdr) - 2*sizeof(uint16_t));
		int qnlen = qname2host(qname, fqdn);
		if (qnlen <= 0)
			continue;

		qtype = *reinterpret_cast<uint16_t *>(buf + sizeof(dnshdr) + qnlen);
		qclass = *reinterpret_cast<uint16_t *>(buf + sizeof(dnshdr) + qnlen + sizeof(uint16_t));

		if (qtype != htons(dns_type::A) && qtype != htons(dns_type::AAAA))
			continue;
		if (qclass != htons(1))
			continue;
		af = (qtype == htons(dns_type::A) ? AF_INET : AF_INET6);

		auto dot = fqdn.rfind(".");
		if (dot != string::npos)
			fqdn.erase(dot, 1);

		//printf("%s %d %d\n", fqdn.c_str(), ntohs(qtype), ntohs(qclass));

		answer.id = query->id;

		result.clear();

		bool rdata_from_cache = 0;

		if (cache_lookup(fqdn, af, result, ttl))
			rdata_from_cache = 1;
		else if ((r = dns->get(fqdn, af, result, ttl, raw)) <= 0) {
			answer.a_count = 0;
			if (r < 0)
				answer.rcode = 2;
			else
				answer.rcode = 3;	// NXDOMAIN

			reply = string(reinterpret_cast<char *>(&answer), sizeof(answer));
			reply += string(buf + sizeof(dnshdr), qnlen + 2*sizeof(uint16_t));
			sendto(d_sock, reply.c_str(), reply.size(), 0, from, flen);
			continue;
		}

		// We found an answer
		answer.rcode = 0;
		// Not yet: Will later insert answer hdr into pos 0, as we don't know a_count by now
		//reply = string(reinterpret_cast<char *>(&answer), sizeof(answer));

		// copy orig question
		reply = string(buf + sizeof(dnshdr), qnlen + 2*sizeof(uint16_t));
		ttl = htonl(ttl);

		uint16_t rdlen = 0, n_answers = 0;

		for (auto i = result.begin(); i != result.end(); ++i) {

			if (af == AF_INET && i->second == "A") {
				rdlen = htons(4);
			} else if (af == AF_INET6 && i->second == "AAAA") {
				rdlen = htons(16);
			} else
				continue;

			if (!rdata_from_cache)
				cache_insert(fqdn, af, i->first, ntohl(ttl));

			// answer name is compression ptr to orig qname
			reply += string(reinterpret_cast<char *>(&clbl), sizeof(clbl));
			reply += string(reinterpret_cast<char *>(&qtype), sizeof(qtype));
			reply += string(reinterpret_cast<char *>(&qclass), sizeof(qclass));
			reply += string(reinterpret_cast<char *>(&ttl), sizeof(ttl));
			reply += string(reinterpret_cast<char *>(&rdlen), sizeof(rdlen));
			reply += i->first;

			++n_answers;
		}

		answer.a_count = htons(n_answers);
		reply.insert(0, string(reinterpret_cast<char *>(&answer), sizeof(answer)));

		sendto(d_sock, reply.c_str(), reply.size(), 0, from, flen);
	}

	return 0;
}


}

