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

#include <cstdio>
#include <resolv.h>
#include <nss.h>
#include <cerrno>
#include <cstring>
#include <string>
#include <cstdlib>
#include <stdint.h>
#include <syslog.h>
#include <netdb.h>
#include <signal.h>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include "dnshttps.h"
#include "config.h"
#include "ssl.h"


#define ALIGN(x) (((x) + __SIZEOF_POINTER__ - 1) & ~(__SIZEOF_POINTER__ - 1))

// as per https://developers.google.com/speed/public-dns/docs/dns-over-https
//
// API is at https://dns.google.com/resolve
// 216.58.214.78, 172.217.17.238
// openssl s_client -showcerts -connect dns.google.com:443

using namespace std;
using namespace harddns;


#if 0
extern "C" void harddns_init();

int main(int argc, char **argv)
{
	map<string, int> v;
	harddns_init();
	string r = "";
	uint32_t ttl = 0;

	dnshttps d(ssl_conn);
	if (d.get("kernel.org", AF_UNSPEC, v, ttl, r) < 0)
		printf("%s %s\n", d.why(), r.c_str());
	printf("%s\n", r.c_str());
}
#endif

// Not more than 1 thread to ask for a question at the same time
mutex ssl_mtx;

/* Most of the alloc/idx code was taken from libvirt and systemd-resolv nss modules. Interestingly
 * they are almost equal, including their comments and asserts.
 */

static  enum nss_status
do_nss_harddns_gethostbyname3_r(const char *name, int af, struct hostent *result,
                              char *buffer, size_t buflen, int *errnop,
                              int *herrnop, int32_t *ttlp, char **canonp)
{
	uint32_t ttl = 0;
	char *r_name = nullptr, *r_alias = nullptr, **r_aliases = nullptr, *r_addr = nullptr, **r_addr_list = nullptr;
	size_t naddr = 0, cnames = 0, i = 0;
	size_t nameLen = 0, need = 0, idx = 0, cname_len = 0;
	int alen = 4;

	if (af != AF_INET6 && af != AF_INET)
		return NSS_STATUS_TRYAGAIN;

	if (af == AF_INET6)
		alen = 16;

	map<string, string> res;
	string raw = "";

	{
		lock_guard<mutex> g(ssl_mtx);

		if (!dns)
			return NSS_STATUS_TRYAGAIN;

		// up to 3 levels of DNS recursion
		string s = name;
		for (i = 0; s.size() > 0 && naddr == 0 && i < 3; ++i) {
			printf(">>>> GET %s\n", s.c_str());
			if (dns->get(s, af, res, ttl, raw) < 0) {
				syslog(LOG_INFO, "%s", dns->why());
				return NSS_STATUS_TRYAGAIN;
			}
			s = "";
			for (auto j = res.begin(); j != res.end(); ++j) {
				if (af == AF_INET && j->second == "A")
					++naddr;
				if (af == AF_INET6 && j->second == "AAAA")
					++naddr;
				if (j->second == "CNAME")
					s = j->first;
			}
		}
	}

	if (config::log_requests)
		syslog(LOG_INFO, "%s %d? -> %s", name, af, raw.c_str());

	naddr = 0;
	for (auto j = res.begin(); j != res.end(); ++j) {
		if (af == AF_INET && j->second == "A")
			++naddr;
		if (af == AF_INET6 && j->second == "AAAA")
			++naddr;
		if (j->second == "CNAME") {
			cname_len += ALIGN(j->first.size() + 1);
			++cnames;
		}
	}

	if (naddr == 0)
		return NSS_STATUS_NOTFOUND;

	/* Found and have data */

	nameLen = strlen(name);

	/* We need space for:
	 * a) name
	 * b) alias
	 * c) addresses
	 * d) nullptr stem */
	need = ALIGN(nameLen + 1) + cname_len + (cnames + 1) * sizeof(char *) + naddr * ALIGN(alen) + (naddr + 2) * sizeof(char *);

	if (buflen < need) {
		*errnop = ENOMEM;
		*herrnop = TRY_AGAIN;
		return NSS_STATUS_TRYAGAIN;
	}

	/* First, append name */
	r_name = buffer;
	memcpy(r_name, name, nameLen + 1);
	idx = ALIGN(nameLen + 1);

	/* Second, create aliases array and aliases double ptr */
	r_alias = buffer + idx;
	r_aliases = reinterpret_cast<char **>(buffer + idx + cname_len);
	i = 0;
	for (auto j = res.begin(); j != res.end(); ++j) {
		if (j->second != "CNAME")
			continue;
		memcpy(r_alias + idx, j->first.c_str(), j->first.size() + 1);	// includes \0 terminator
		r_aliases[i++] = r_alias + idx;
		idx += ALIGN(j->first.size() + 1);
	}

	r_aliases[i] = nullptr;
	idx += sizeof(char *);

	/* Third, append addresses */
	r_addr = buffer + idx;
	i = 0;
	for (auto j = res.begin(); j != res.end(); ++j) {
		if (af == AF_INET && j->second != "A")
			continue;
		if (af == AF_INET6 && j->second != "AAAA")
			continue;
		memcpy(r_addr + i*ALIGN(alen), j->first.data(), alen);
		++i;
	}

	idx += naddr*ALIGN(alen);
	r_addr_list = reinterpret_cast<char **>(buffer + idx);

	/* Fourth, append address pointer array */
	for (i = 0; i < naddr; i++)
		r_addr_list[i] = r_addr + i*ALIGN(alen);

	r_addr_list[i] = nullptr;
	idx += (naddr + 1) * sizeof(char*);

	/* At this point, idx == need */

	result->h_name = r_name;
	result->h_aliases = r_aliases;
	result->h_addrtype = af;
	result->h_length = alen;
	result->h_addr_list = r_addr_list;

	if (ttlp)
		*ttlp = (int32_t)ttl;

	if (canonp)
		*canonp = r_name;

	/* Explicitly reset all error variables */
	*errnop = 0;
	*herrnop = NETDB_SUCCESS;
	h_errno = 0;

	return NSS_STATUS_SUCCESS;
}


extern "C" enum nss_status
_nss_harddns_gethostbyname3_r(const char *name, int af, struct hostent *result,
                              char *buffer, size_t buflen, int *errnop,
                              int *herrnop, int32_t *ttlp, char **canonp)
{
	struct sigaction new_sig, old_sig;
	memset(&new_sig, 0, sizeof(new_sig));
	new_sig.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &new_sig, &old_sig);

	enum nss_status r = do_nss_harddns_gethostbyname3_r(name, af, result, buffer, buflen, errnop, herrnop, ttlp, canonp);

	sigaction(SIGPIPE, &old_sig, nullptr);
	return r;
}


#if 1 //HAVE_STRUCT_GAIH_ADDRTUPLE

static enum nss_status
do_nss_harddns_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat,
                              char *buffer, size_t buflen, int *errnop,
                              int *herrnop, int32_t *ttlp)
{
	uint32_t ttl = 0;
	size_t naddr = 0;
	size_t nameLen = 0, need = 0, idx = 0;
	struct gaih_addrtuple *r_tuple = nullptr, *r_tuple_first = nullptr;
	char *r_name = nullptr;

	map<string, string> res;
	string raw = "";

	{
		lock_guard<mutex> g(ssl_mtx);

		if (!dns)
			return NSS_STATUS_TRYAGAIN;

		// up to 3 levels of DNS CNAME recursion
		string s = name;
		for (int i = 0; s.size() > 0 && naddr == 0 && i < 3; ++i) {
			if (dns->get(s, AF_INET, res, ttl, raw) < 0) {
				syslog(LOG_INFO, "%s", dns->why());
				return NSS_STATUS_TRYAGAIN;
			}
			if (dns->get(s, AF_INET6, res, ttl, raw) < 0) {
				syslog(LOG_INFO, "%s", dns->why());
				return NSS_STATUS_TRYAGAIN;
			}
			s = "";
			for (auto j = res.begin(); j != res.end(); ++j) {
				if (j->second == "A" || j->second == "AAAA")
					++naddr;
				if (j->second == "CNAME")
					s = j->first;
			}
		}
	}

	naddr = 0;
	for (auto j = res.begin(); j != res.end(); ++j) {
		if (j->second == "A" || j->second == "AAAA")
			++naddr;
	}
	if (naddr == 0)
		return NSS_STATUS_NOTFOUND;

	if (config::log_requests)
		syslog(LOG_INFO, "%s ANY? -> %s", name, raw.c_str());


	/* Found and have data */

	nameLen = strlen(name);

	/* We need space for:
	 * a) name
	 * b) addresses */
	need = ALIGN(nameLen + 1) + naddr * ALIGN(sizeof(struct gaih_addrtuple));

	if (buflen < need) {
		*errnop = ENOMEM;
		*herrnop = TRY_AGAIN;
		return NSS_STATUS_TRYAGAIN;
	}

	/* First, append name */
	r_name = buffer;
	memcpy(r_name, name, nameLen + 1);
	idx = ALIGN(nameLen + 1);

	/* Second, append addresses */
	size_t i = 0;
	r_tuple_first = reinterpret_cast<struct gaih_addrtuple *>(buffer + idx);
	for (auto j = res.begin(); j != res.end(); ++j) {
		if (j->second != "A" && j->second != "AAAA")
			continue;
		r_tuple = reinterpret_cast<struct gaih_addrtuple *>(buffer + idx);
		if (++i == naddr)
			r_tuple->next = nullptr;
		else
			r_tuple->next = reinterpret_cast<struct gaih_addrtuple *>(buffer + idx + ALIGN(sizeof(struct gaih_addrtuple)));
		idx += ALIGN(sizeof(struct gaih_addrtuple));
		r_tuple->name = r_name;
		r_tuple->family = j->second == "A" ? AF_INET : AF_INET6;
		r_tuple->scopeid = 0;
		memcpy(r_tuple->addr, j->first.data(), j->first.size());
	}

	if (*pat)
		**pat = *r_tuple_first;
	else
		*pat = r_tuple_first;

	if (ttlp)
		*ttlp = (int32_t)ttl;

	/* Explicitly reset all error variables */
	*errnop = 0;
	*herrnop = NETDB_SUCCESS;
	return NSS_STATUS_SUCCESS;
}


extern "C" enum nss_status
_nss_harddns_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat,
                              char *buffer, size_t buflen, int *errnop,
                              int *herrnop, int32_t *ttlp)
{
	struct sigaction new_sig, old_sig;
	memset(&new_sig, 0, sizeof(new_sig));
	new_sig.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &new_sig, &old_sig);

	enum nss_status r = do_nss_harddns_gethostbyname4_r(name, pat, buffer, buflen, errnop, herrnop, ttlp);

	sigaction(SIGPIPE, &old_sig, nullptr);
	return r;
}


#endif /* HAVE_STRUCT_GAIH_ADDRTUPLE */


extern "C" enum nss_status
_nss_harddns_gethostbyname_r(const char *name, struct hostent *result,
                             char *buffer, size_t buflen, int *errnop,
                             int *herrnop)
{
	int af = ((_res.options & RES_USE_INET6) ? AF_INET6 : AF_INET);

	return _nss_harddns_gethostbyname3_r(name, af, result, buffer, buflen,
	                                     errnop, herrnop, nullptr, nullptr);
}


extern "C" enum nss_status
_nss_harddns_gethostbyname2_r(const char *name, int af, struct hostent *result,
                              char *buffer, size_t buflen, int *errnop,
                              int *herrnop)
{
	return _nss_harddns_gethostbyname3_r(name, af, result, buffer, buflen,
	                                     errnop, herrnop, nullptr, nullptr);
}


