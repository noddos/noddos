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

#include <fstream>

int main () {
    bool testfailed = false;
    openlog("DnsCache_test", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);

    DnsCnameCache c(true);
    DnsIpCache <boost::asio::ip::address> i(true);

    std::string filename = "tests/DnsCache.json";
    std::ifstream ifs(filename);
    if (not ifs.is_open()) {
        syslog(LOG_WARNING, "Couldn't open %s", filename.c_str());
        testfailed = true;
    }
    json k;
    ifs >> k;
    size_t importedRecords = i.importJson(k);
    if (importedRecords != 288) {
        testfailed = true;
        syslog(LOG_WARNING, "Imported A/AAAA records %lu", importedRecords);

    }

    importedRecords = c.importJson(k);
    if (importedRecords != 284) {
        testfailed = true;
        syslog(LOG_WARNING, "Imported CNAME records %lu", importedRecords);

    }
    ifs.close();
    boost::asio::ip::address ip4 = boost::asio::ip::address::from_string("216.58.216.46");
    std::vector<std::string> fqdns = i.getAllFqdns(ip4);
    if (fqdns.size() != 5) {
        syslog (LOG_DEBUG,"Simple reverse lookup for 216.58.216.46 returned %lu fqdns", fqdns.size());
        testfailed = true;
    }

    std::string rootfqdn = c.lookupCname(fqdns[0]);
    if (rootfqdn != "clients3.google.com") {
        syslog(LOG_DEBUG, "Cname lookup failed %s", rootfqdn.c_str());
        testfailed = true;
    }
    std::ofstream ofs("/tmp/DnsCache.json");
    if (not ofs.is_open()) {
        syslog(LOG_WARNING, "Couldn't open %s", filename.c_str());
        return true;
    }
    json j;
    auto exportRecords = i.exportJson(j);
    if (exportRecords != 288) {
        testfailed = true;
        syslog(LOG_WARNING, "Exported A/AAAA records %lu", exportRecords);
    }
    exportRecords = c.exportJson(j);
    if (exportRecords != 284) {
        testfailed = true;
        syslog(LOG_WARNING, "Exported CNAME records %lu", exportRecords);
    }

    ofs << std::setw(4) << j << std::endl;
    ofs.close();
    unlink("/tmp/DnsCache.json");

    uint32_t prunecount = c.pruneCnames(true);
    if (prunecount != 284) {
        syslog (LOG_DEBUG, "Pruned %u DNS cnames", prunecount);
        testfailed = 1;
    }
    prunecount=i.pruneResourceRecords(true);
    if (prunecount != 2416) {
        syslog (LOG_DEBUG, "Pruned %u DNS IP records", prunecount);
        testfailed = 1;
    }
    return testfailed;
}





