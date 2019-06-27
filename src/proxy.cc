#include <string>
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

	return 0;
}


int doh_proxy::loop()
{
	int r = 0;
	char buf[1024] = {0};
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
		af = (qtype == htons(dns_type::A) ? AF_INET : AF_INET6);

		auto dot = fqdn.rfind(".");
		if (dot != string::npos)
			fqdn.erase(dot, 1);

		printf("%s %d %d\n", fqdn.c_str(), ntohs(qtype), ntohs(qclass));

		answer.id = query->id;

		if ((r = dns->get(fqdn, af, result, ttl, raw)) <= 0) {
			answer.rcode = 2;
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

		// answer name is compression ptr to orig qname
		reply += string(reinterpret_cast<char *>(&clbl), sizeof(clbl));
		reply += string(reinterpret_cast<char *>(&qtype), sizeof(qtype));
		reply += string(reinterpret_cast<char *>(&qclass), sizeof(qclass));
		ttl = htonl(ttl);
		reply += string(reinterpret_cast<char *>(&ttl), sizeof(ttl));

		uint16_t rdlen = 0, n_answers = 0;

		for (auto i = result.begin(); i != result.end(); ++i) {
			if (af == AF_INET && i->second == "A") {
				rdlen = htons(4);
			} else if (af == AF_INET6 && i->second == "AAAA") {
				rdlen = htons(16);
			} else
				continue;
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

