/*
   Copyright 2017 Steven Hessing

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

 * DnsLogEntry_test.cxx
 *
 *  Created on: Mar 26, 2017
 *      Author: steven
 */

#include <string>

#include <json.hpp>
using nlohmann::json;

#include "DnsLogEntry.h"
#include "Host.h"

int main()
{
	// TODO
	Host h(MacAddress("aa:bb:cc:dd:ee:ff"), false);
	// DELETE DNSMASQ
	// h.DnsLogEntry_set("www.blah.com", "10.10.10.1");
	json l;
	h.DeviceStats(l, 3600);
	std::cout << l << std::endl;
	return 0;
}


