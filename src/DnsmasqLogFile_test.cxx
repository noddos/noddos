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

 * DnsmasqLogFile_test.cxx
 *
 *  Created on: Apr 1, 2017
 *      Author: steven
 */

#include <iostream>
#include <sstream>

#include "DnsmasqLogFile.h"
#include "HostCache.h"

int main () {
	openlog("DnsmasqLogFile_test", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
	bool testfail = false;
	HostCache hc(true);
	// To test we have to add dummy Host entries to make sure
	// the client IP address translates to a MAC address as
	// the client ip address in the test colleteral may no longer
	// be present.
	hc.AddByMac (MacAddress("00:00:00:00:00:01"), "192.168.1.232");
	hc.AddByMac (MacAddress("00:00:00:00:00:02"), "192.168.1.98");
	hc.AddByMac (MacAddress("00:00:00:00:00:03"), "192.168.1.99");
	hc.AddByMac (MacAddress("00:00:00:00:00:04"), "192.168.1.235");
	hc.AddByMac (MacAddress("00:00:00:00:00:05"), "192.168.1.241");
	hc.AddByMac (MacAddress("00:00:00:00:00:06"), "192.168.1.251");
	hc.AddByMac (MacAddress("00:00:00:00:00:07"), "192.168.1.234");
	hc.AddByMac (MacAddress("00:00:00:00:00:08"), "192.168.1.240");
	hc.AddByMac (MacAddress("00:00:00:00:00:09"), "192.168.1.238");
	hc.AddByMac (MacAddress("00:00:00:00:00:10"), "192.168.1.234");

	DnsmasqLogFile d ("tests/dnsmasqdnsdata.log", hc, 86400, true);
	auto lp = d.LinesParsed();
	if (lp != 214) {
		testfail = true;
    }

	auto c = hc.HostCount();
	if (c != 10) {
	    std::cout << "Hosts found: " << c << std::endl;
		testfail = true;
    }
	c = hc.HostDnsQueryCount ("192.168.1.232");
	if (c != 4) {
	    std::cout << "DNS queries by 192.168.1.232: " << c << std::endl;
		testfail = true;
    }
	c = hc.HostDnsQueryCount ("192.168.1.98");
	if (c != 4) {
	    std::cout << "DNS queries by 192.168.1.98: " << c << std::endl;
		testfail = true;
    }
	c = hc.HostDnsQueryCount ("192.168.1.241");
	if (c != 20) {
	    std::cout << "DNS queries by 192.168.1.241: " << c << std::endl;
		testfail = true;
    }
	c = hc.HostDnsQueryCount ("192.168.1.99");
	if (c != 1) {
	    std::cout << "DNS queries by 192.168.1.99: " << c << std::endl;
		testfail = true;
    }
	c = hc.HostDnsQueryCount ("192.168.1.234");
	if (c != 1) {
	    std::cout << "DNS queries by 192.168.1.234: " << c << std::endl;
		testfail = true;
    }
	c = hc.HostDnsQueryCount ("192.168.1.235");
	if (c != 3) {
	    std::cout << "DNS queries by 192.168.1.235: " << c << std::endl;
		testfail = true;
    }
	c = hc.HostDnsQueryCount ("192.168.1.251");
	if (c != 2) {
	    std::cout << "DNS queries by 192.168.1.251: " << c << std::endl;
		testfail = true;
    }
	if(testfail) {
	    std::cout << "Lines parsed: " << lp << std::endl;
		exit(1);
    }
	exit(0);
}



