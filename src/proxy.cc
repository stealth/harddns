/*
 * This file is part of harddns.
 *
 * (C) 2019-2020 by Sebastian Krahmer,
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

#include <map>
#include <string>
#include <cstring>
#include <utility>
#include <stdint.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "misc.h"
#include "proxy.h"
#include "config.h"
#include "net-headers.h"

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
	if (::bind(d_sock, ai->ai_addr, ai->ai_addrlen) < 0)
		return build_error("init::bind:", -1);

	// No need to create a dnshttp object, it was globally created

	return 0;
}


void doh_proxy::cache_insert(const string &fqdn, uint16_t qtype, const dnshttps::dns_reply &ans)
{
	timeval tv;
	gettimeofday(&tv, nullptr);

	auto idx = d_rr_cache.find(make_pair(fqdn, qtype));

	if (idx != d_rr_cache.end())
		d_rr_cache.erase(idx);

	uint32_t min_ttl = 0xffffffff;
	for (auto i = ans.begin(); i != ans.end(); ++i) {
		if (i->second.name.find("NSS") == 0)
			continue;
		if (min_ttl > ntohl(i->second.ttl))
			min_ttl = ntohl(i->second.ttl);
	}

	cache_elem_t elem{ans, tv.tv_sec + min_ttl};

	d_rr_cache[make_pair(fqdn, qtype)] = elem;
}


bool doh_proxy::cache_lookup(const string &fqdn, uint16_t qtype, dnshttps::dns_reply &result)
{
	timeval tv;
	gettimeofday(&tv, nullptr);

	if (d_rr_cache.size() == 0)
		return 0;

	auto idx = d_rr_cache.find(make_pair(fqdn, qtype));

	if (idx == d_rr_cache.end())
		return 0;

	if (idx->second.valid_until <= tv.tv_sec) {
		d_rr_cache.erase(idx);
		return 0;
	}

	auto elem = idx->second.answer;

	for (auto i = elem.begin(); i != elem.end(); ++i)
		i->second.ttl = htonl(idx->second.valid_until - tv.tv_sec);	// TTL in result map goes as network order

	result = elem;
	return 1;
}


int doh_proxy::forward_query(const string &ns, const string &src, const string &fqdn, uint16_t id, const char *buf, size_t blen)
{
	addrinfo *tai{nullptr}, hints;

	hints.ai_family = d_af;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICHOST;

	int r = 0;
	// local DNS server
	if ((r = getaddrinfo(ns.c_str(), "53", &hints, &tai)) != 0)
		return build_error("forward_query: Unable to resolve transparent forwarding address.", -1);

	free_ptr<addrinfo> ai(tai, freeaddrinfo);

	if (sendto(d_sock, buf, blen, 0, tai->ai_addr, tai->ai_addrlen) != (int)blen)
		return build_error("forward_query: sendto() error.", -1);

	// successfully sent, remember in cache to forward answers later
	// based on cache lookup
	string map_key = fqdn + string(reinterpret_cast<char *>(&id), sizeof(id));
	map_key += string(reinterpret_cast<char *>(tai->ai_addr), tai->ai_addrlen);
	d_fwd_cache[map_key] = src;

	if (config::log_requests)
		syslog(LOG_INFO, "proxy fwd %s to %s", fqdn.c_str(), ns.c_str());

	return 0;
}


int doh_proxy::forward_answer(const string &ns, const string &fqdn, uint16_t id, const char *buf, size_t blen)
{
	string map_key = fqdn + string(reinterpret_cast<char *>(&id), sizeof(id)) + ns;

	// Was there a query that we sent with this qname and ID to this NS?
	auto it = d_fwd_cache.find(map_key);

	if (it == d_fwd_cache.end())
		return build_error("forward_answer:: Answer for no request of " + fqdn, -1);

	if (sendto(d_sock, buf, blen, 0, reinterpret_cast<const sockaddr *>(it->second.c_str()), it->second.size()) != (int)blen)
		return build_error("forward_answer::sendto():", -1);

	d_fwd_cache.erase(it);

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
	dnshttps::dns_reply result;
	uint16_t qtype = 0, qclass = 0;

	if (d_af == AF_INET6) {
		from = reinterpret_cast<sockaddr *>(&from6);
		flen = sizeof(from6);
	}

	answer.qr = 1;
	answer.ra = 1;
	answer.q_count = htons(1);

	for (;;) {
		memset(buf, 0, sizeof(buf));
		memset(from, 0, flen);

		if ((r = recvfrom(d_sock, buf, sizeof(buf), 0, from, &flen)) <= 0)
			continue;

		errno = 0;

		if ((size_t)r < sizeof(dnshdr) + 2*sizeof(uint16_t) + 1)
			continue;
		query = reinterpret_cast<dnshdr *>(buf);

		if (query->q_count != htons(1))
			continue;

		// actually, the string qname will contain more than just the DNS qname but also
		// all the remaining data. But qname2host() stops after the trailing \0 is seen,
		// and the variable is just used for that translation
		qname = string(buf + sizeof(dnshdr), r - sizeof(dnshdr) - 2*sizeof(uint16_t));
		int qnlen = qname2host(qname, fqdn);
		if (qnlen <= 0)
			continue;

		// remove trailing dot
		auto dot = fqdn.rfind(".");
		if (dot != string::npos)
			fqdn.erase(dot, 1);

		// If an answer, check and possibly forward if we proxied previous
		// request to an internal DNS server. We only do a cache lookup based
		// on fqdn and ID. Its up to the client to verify that the answer is legit;
		// we are just forwarding from/to internal DNS server.
		if (query->qr == 1) {
			if (forward_answer(string(reinterpret_cast<char *>(from), flen), fqdn, query->id, buf, r) != 0)
				syslog(LOG_INFO, "Failed: %s", this->why());
			continue;
		}

		// must be a query by now
		if (query->opcode != 0)
			continue;

		bool has_fwd = 0;

		// check if we need to forward queries of internal domains to internal DNS
		for (auto it = config::internal_domains.begin(); it != config::internal_domains.end(); ++it) {

			// is internal domain suffix of fqdn?
			if (fqdn.size() >= it->first.size() && fqdn.find(it->first) == (fqdn.size() - it->first.size())) {
				if (forward_query(it->second, string(reinterpret_cast<char *>(from), flen), fqdn, query->id, buf, r) != 0)
					syslog(LOG_INFO, "Failed: %s", this->why());
				has_fwd = 1;
				break;
			}
		}

		if (has_fwd)
			continue;

		// It's important here that qname may not contain compression (qname2host() called
		// with start_idx = 0). Otherwise qnlen would be wrong.

		qtype = ua_uint16(buf + sizeof(dnshdr) + qnlen);
		qclass = ua_uint16(buf + sizeof(dnshdr) + qnlen + sizeof(uint16_t));

		if (qtype != htons(dns_type::A) && qtype != htons(dns_type::AAAA))
			continue;
		if (qclass != htons(1))
			continue;

		//printf("%s %d %d\n", fqdn.c_str(), ntohs(qtype), ntohs(qclass));

		answer.id = query->id;

		result.clear();

		bool rdata_from_cache = 0;

		raw = "";

		if (cache_lookup(fqdn, qtype, result))
			rdata_from_cache = 1;
		else if ((r = dns->get(fqdn, qtype, result, raw)) <= 0) {

			answer.a_count = 0;
			if (r < 0) {
				answer.rcode = 2;
				syslog(LOG_INFO, "proxy %s -> %s", fqdn.c_str(), dns->why());
			} else
				answer.rcode = 3;	// NXDOMAIN

			reply = string(reinterpret_cast<char *>(&answer), sizeof(answer));
			reply += string(buf + sizeof(dnshdr), qnlen + 2*sizeof(uint16_t));
			sendto(d_sock, reply.c_str(), reply.size(), 0, from, flen);
			continue;
		}

		if (config::log_requests)
			syslog(LOG_INFO, "proxy %s %s? -> %s", fqdn.c_str(), qtype == htons(dns_type::A) ? "A" : "AAAA", rdata_from_cache ? "(cached)" : raw.c_str());

		// We found an answer
		answer.rcode = 0;
		// Not yet: Will later insert answer hdr into pos 0, as we don't know a_count by now
		//reply = string(reinterpret_cast<char *>(&answer), sizeof(answer));

		// copy orig question
		reply = string(buf + sizeof(dnshdr), qnlen + 2*sizeof(uint16_t));

		if (!rdata_from_cache)
			cache_insert(fqdn, qtype, result);

		uint16_t rdlen = 0, n_answers = 0;

		// by using an integer to access the map like an vector index, we have
		// the order of elements as they were inserted by dns->get() by increasing index
		// as the records were parsed
		for (unsigned int i = 0; i < result.size(); ++i) {

			const auto &elem = result[i];

			// skip the entries that were created for NSS module
			if (elem.name.find("NSS") == 0)
				continue;

			rdlen = htons(elem.rdata.size());

			reply += elem.name;
			reply += string(reinterpret_cast<const char *>(&elem.qtype), sizeof(elem.qtype));
			reply += string(reinterpret_cast<const char *>(&elem.qclass), sizeof(elem.qclass));
			reply += string(reinterpret_cast<const char *>(&elem.ttl), sizeof(elem.ttl));
			reply += string(reinterpret_cast<const char *>(&rdlen), sizeof(rdlen));
			reply += elem.rdata;

			++n_answers;
		}

		answer.a_count = htons(n_answers);
		reply.insert(0, string(reinterpret_cast<char *>(&answer), sizeof(answer)));

		sendto(d_sock, reply.c_str(), reply.size(), 0, from, flen);
	}

	return 0;
}


}

