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

#include <string>
#include <cstring>
#include <limits>

namespace harddns {


// actually base64url alphabet
static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


using namespace std;

/* The base64 routines have been taken from the Samba 3 source (GPL)
 * and have been C++-ified
 */

string &b64url_encode(const string &src, string &dst)
{
	unsigned int bits = 0;
	int char_count = 0, i = 0;

	dst = "";
	if (src.size() >= numeric_limits<unsigned int>::max()/2)
		return dst;

	dst.reserve(src.size() + src.size()/3 + 10);
	string::size_type len = src.size();
	while (len--) {
		unsigned int c = (unsigned char)src[i++];
		bits += c;
		char_count++;
		if (char_count == 3) {
			dst += b64[bits >> 18];
			dst += b64[(bits >> 12) & 0x3f];
			dst += b64[(bits >> 6) & 0x3f];
	    		dst += b64[bits & 0x3f];
		    	bits = 0;
		    	char_count = 0;
		} else	{
	    		bits <<= 8;
		}
    	}
	if (char_count != 0) {
		bits <<= 16 - (8 * char_count);
		dst += b64[bits >> 18];
		dst += b64[(bits >> 12) & 0x3f];
		if (char_count == 1) {
			//dst += '=';
			//dst += '=';
		} else {
			dst += b64[(bits >> 6) & 0x3f];
			//dst += '=';
		}
	}
	return dst;
}


string &b64url_encode(const char *src, size_t srclen, string &dst)
{
	unsigned int bits = 0;
	int char_count = 0, i = 0;

	dst = "";
	if (srclen >= numeric_limits<unsigned int>::max()/2)
		return dst;

	dst.reserve(srclen + srclen/3 + 10);
	while (srclen--) {
		unsigned int c = (unsigned char)src[i++];
		bits += c;
		char_count++;
		if (char_count == 3) {
			dst += b64[bits >> 18];
			dst += b64[(bits >> 12) & 0x3f];
			dst += b64[(bits >> 6) & 0x3f];
	    		dst += b64[bits & 0x3f];
		    	bits = 0;
		    	char_count = 0;
		} else	{
	    		bits <<= 8;
		}
    	}
	if (char_count != 0) {
		bits <<= 16 - (8 * char_count);
		dst += b64[bits >> 18];
		dst += b64[(bits >> 12) & 0x3f];

		if (char_count == 1) {
			//dst += '=';
			//dst += '=';
		} else {
			dst += b64[(bits >> 6) & 0x3f];
			//dst += '=';
		}
	}
	return dst;
}

}

