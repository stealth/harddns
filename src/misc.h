/*
 * This file is part of harddns.
 *
 * (C) 2014 by Sebastian Krahmer, sebastian [dot] krahmer [at] gmail [dot] com
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

#ifndef harddns_misc_h
#define harddns_misc_h

#include <memory>
#include <string>

namespace harddns {

int host2qname(const std::string &, std::string &);

int qname2host(const std::string &, std::string &, std::string::size_type idx = 0);

bool valid_name(const std::string &);

std::string lcs(const std::string &);

template<typename T> using free_ptr = std::unique_ptr<T, void (*)(T *)>;

}


#endif

