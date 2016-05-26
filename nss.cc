/*
 * This file is part of harddns.
 *
 * (C) 2016 by Sebastian Krahmer,
 *             sebastian [dot] krahmer [at] gmail [dot] com
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
extern void harddns_init();

int main(int argc, char **argv)
{
	map<string, int> v;
	harddns_init();
	string r = "";

	dnshttps d(ssl_conn);
	if (d.get("kernel.org", AF_UNSPEC, v, r) < 0)
		printf("%s %s\n", d.why(), r.c_str());
}
#endif

// Not more than 1 thread to ask for a question at the same time
mutex ssl_mtx;

/* Most of the alloc/idx code was taken from libvirt and systemd-resolv nss modules. Interestingly
 * they are almos equal, including their comments and asserts.
 */

extern "C" enum nss_status
_nss_harddns_gethostbyname3_r(const char *name, int af, struct hostent *result,
                              char *buffer, size_t buflen, int *errnop,
                              int *herrnop, int32_t *ttlp, char **canonp)
{
	uint32_t ttl = 0;
	char *r_name, **r_aliases, *r_addr, **r_addr_list;
	size_t naddr = 0, i = 0;
	size_t nameLen = 0, need = 0, idx = 0;
	int alen = 4;

	if (af == AF_UNSPEC)
		af = AF_INET;
	if (af == AF_INET6)
		alen = 16;

	map<string, int> res;
	string raw = "";
	{
	lock_guard<mutex> g(ssl_mtx);

	if (!dns || dns->get(name, af, res, ttl, raw) < 0) {
		if (dns)
			syslog(LOG_INFO, "%s", dns->why());
		return NSS_STATUS_TRYAGAIN;
	}

	}

	if (config::log_requests)
		syslog(LOG_INFO, "%s A%s? -> %s", name, (af == AF_INET)?"":"AAA", raw.c_str());

	if ((naddr = res.size()) == 0)
		return NSS_STATUS_NOTFOUND;

	/* Found and have data */

	nameLen = strlen(name);

	/* We need space for:
	 * a) name
	 * b) alias
	 * c) addresses
	 * d) nullptr stem */
	need = ALIGN(nameLen + 1) + naddr * ALIGN(alen) + (naddr + 2) * sizeof(char *);

	if (buflen < need) {
		*errnop = ENOMEM;
		*herrnop = TRY_AGAIN;
		return NSS_STATUS_TRYAGAIN;
	}

	/* First, append name */
	r_name = buffer;
	memcpy(r_name, name, nameLen + 1);
	idx = ALIGN(nameLen + 1);

	/* Second, create empty aliases array */
	r_aliases = reinterpret_cast<char **>(buffer + idx);
	r_aliases[0] = nullptr;
	idx += sizeof(char *);

	/* Third, append addresses */
	r_addr = buffer + idx;
	for (auto j = res.begin(); j != res.end(); ++j) {
		if (j->second == af)
			memcpy(r_addr + i*ALIGN(alen), j->first.c_str(), alen);
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

#if 1 //HAVE_STRUCT_GAIH_ADDRTUPLE
extern "C" enum nss_status
_nss_harddns_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat,
                              char *buffer, size_t buflen, int *errnop,
                              int *herrnop, int32_t *ttlp)
{
	uint32_t ttl = 0;
	size_t naddr;
	size_t nameLen, need, idx = 0;
	struct gaih_addrtuple *r_tuple, *r_tuple_first = nullptr;
	char *r_name;

	map<string, int> res;
	string raw = "";

	{
	lock_guard<mutex> g(ssl_mtx);

	if (!dns || dns->get(name, AF_UNSPEC, res, ttl, raw) < 0) {
		if (dns)
			syslog(LOG_INFO, "%s", dns->why());
		return NSS_STATUS_TRYAGAIN;
	}

	}

	if ((naddr = res.size()) == 0)
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
	size_t j = 0;
	r_tuple_first = reinterpret_cast<struct gaih_addrtuple *>(buffer + idx);
	for (auto i = res.begin(); i != res.end(); ++i) {
		r_tuple = reinterpret_cast<struct gaih_addrtuple *>(buffer + idx);
		if (++j == res.size())
			r_tuple->next = nullptr;
		else
			r_tuple->next =  reinterpret_cast<struct gaih_addrtuple *>(buffer + idx + ALIGN(sizeof(struct gaih_addrtuple)));
		idx += ALIGN(sizeof(struct gaih_addrtuple));
		r_tuple->name = r_name;
		r_tuple->family = i->second;
		r_tuple->scopeid = 0;
		memcpy(r_tuple->addr, i->first.c_str(), i->first.size());
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


