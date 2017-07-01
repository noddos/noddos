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

 * DnsCache_test.cxx
 *
 *  Created on: Jul 1, 2017
 *      Author: steven
 */

#include <iostream>

#include "boost/asio.hpp"

#include "DnsCache.h"

int main () {
    bool testfailed = false;
    openlog("Host_test", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);

    DnsCnameCache c(true);
    DnsIpCache <boost::asio::ip::address> i(true);

    boost::asio::ip::address ip4 = boost::asio::ip::address::from_string("52.216.86.51");
    i.addorupdateResourceRecord("s3-1-w.amazonaws.com", ip4, 900);
    std::vector<std::string> fqdns = i.getAllFqdns(ip4);
    if (fqdns.size() != 1) {
        syslog (LOG_DEBUG,"Simple reverse lookup for 52.216.86.51 returned %lu fqdns", fqdns.size());
        testfailed = true;
    }
    c.addorupdateCname("ping.enphaseenergy.com.s3.amazonaws.com","s3-1-w.amazonaws.com", 300);
    c.addorupdateCname("ping.enphaseenergy.com", "ping.enphaseenergy.com.s3.amazonaws.com", 300);

    std::string rootfqdn = c.lookupCname(fqdns[0]);
    if (rootfqdn != "ping.enphaseenergy.com") {
        syslog(LOG_DEBUG, "Cname lookup failed");
        testfailed = true;
    }
    uint32_t prunecount = c.pruneCnames(true);
    if (prunecount != 2) {
        syslog (LOG_DEBUG, "Pruned %u DNS cnames", prunecount);
        testfailed = 1;
    }
    prunecount=i.pruneResourceRecords(true);
    if (prunecount != 1) {
        syslog (LOG_DEBUG, "Pruned %u DNS IP records", prunecount);
        testfailed = 1;
    }
    return testfailed;
}





