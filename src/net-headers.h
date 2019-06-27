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

/* some of the header definitions have been taken from various other
 * open-sourced include files
 */

#ifndef harddns_net_headers_h
#define harddns_net_headers_h

#include <sys/types.h>
#ifdef __linux__
#include <bits/endian.h>
#endif
#include <stdint.h>

#ifndef __BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#endif

#ifndef __BIG_ENDIAN
#define __BING_ENDIAN BIG_ENDIAN
#endif

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif

namespace harddns {

namespace net_headers {


class dnshdr {
public:
	uint16_t id;

#if __BYTE_ORDER == __BIG_ENDIAN
                        /* fields in third byte */
        uint16_t        qr: 1;          /* response flag */
        uint16_t        opcode: 4;      /* purpose of message */
        uint16_t        aa: 1;          /* authoritive answer */
        uint16_t        tc: 1;          /* truncated message */
        uint16_t        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        uint16_t        ra: 1;          /* recursion available */
        uint16_t        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        uint16_t        ad: 1;          /* authentic data from named */
        uint16_t        cd: 1;          /* checking disabled by resolver */
        uint16_t        rcode :4;       /* response code */
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
                        /* fields in third byte */
        uint16_t        rd :1;          /* recursion desired */
        uint16_t        tc :1;          /* truncated message */
        uint16_t        aa :1;          /* authoritive answer */
        uint16_t        opcode :4;      /* purpose of message */
        uint16_t        qr :1;          /* response flag */
                        /* fields in fourth byte */
        uint16_t        rcode :4;       /* response code */
        uint16_t        cd: 1;          /* checking disabled by resolver */
        uint16_t        ad: 1;          /* authentic data from named */
        uint16_t        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        uint16_t        ra :1;          /* recursion available */
#endif
/*
        union {
		u_int16_t flags;

		u_int16_t QR:1;
		u_int16_t opcode:4;
		u_int16_t AA:1;
		u_int16_t TC:1;
		u_int16_t RD:1;
		u_int16_t RA:1;
		u_int16_t zero:3;
		u_int16_t rcode:4;
        } u;
*/
	uint16_t q_count;
	uint16_t a_count;
	uint16_t rra_count;
	uint16_t ad_count;

	dnshdr() : id (0),
	           q_count(0), a_count(0), rra_count(0), ad_count(0)
	{
		qr = 0; opcode = 0; aa = 0; tc = 0; rd = 0; ra = 0; ad = 0; cd = 0;
		rcode = 0; unused = 0;
	}

	private: dnshdr(const dnshdr &) {};
};



enum dns_type : uint16_t {
	A	=	1,
	NS	=	2,
	CNAME	=	5,
	SOA	=	6,
	PTR	=	12,
	HINFO	=	13,
	MX	=	15,
	TXT	=	16,
	AAAA	=	28,
	SRV	=	33,
	DNAME	=	39,
	OPT	=	41,
	DNSKEY	=	48,
	EUI64	=	109,
};


} // namespace

} // namespace

#endif

