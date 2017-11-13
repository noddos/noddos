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
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#include <iostream>
#include <fstream>
#include <set>

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include <unistd.h>

#include "DnsCache.h"
#include "DeviceProfile.h"

#include "MacAddress.h"
#include "Host.h"

bool do_cname_test();

int main () {
    bool testfailed = false;
    openlog("DnsCache_test", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);

    FqdnDeviceProfileMap fdpMap;
    DnsCnameCache c(true);
    DnsIpCache <Tins::IPv4Address> i(true);
    DnsIpCache <Tins::IPv6Address> isix(true);
    std::string filename = "../tests/DnsCache.json";
    std::ifstream ifs(filename);
    if (not ifs.is_open()) {
        syslog(LOG_WARNING, "Couldn't open %s", filename.c_str());
        testfailed = true;
    }
    json k;
    ifs >> k;
    size_t importedRecords = i.importJson(k, fdpMap);
    if (importedRecords != 564) {
        testfailed = true;
        syslog(LOG_WARNING, "Imported A records %zu", importedRecords);

    }

    importedRecords = isix.importJson(k, fdpMap);
    if (importedRecords != 7) {
        testfailed = true;
        syslog(LOG_WARNING, "Imported AAAA records %zu", importedRecords);

    }
    importedRecords = c.importJson(k,fdpMap);
    if (importedRecords != 85) {
        testfailed = true;
        syslog(LOG_WARNING, "Imported CNAME records %zu", importedRecords);

    }
    ifs.close();
    Tins::IPv4Address ip4("23.41.176.89");
    std::vector<std::string> fqdns = i.getAllFqdns(ip4);
    if (fqdns.size() != 1) {
        syslog (LOG_DEBUG,"Simple reverse lookup for 23.41.176.89 returned %lu fqdns", fqdns.size());
        testfailed = true;
    }

    if (fqdns.size() > 0) {
        std::string rootfqdn = c.getFqdn(fqdns[0]);
        if (rootfqdn != "www.cisco.com") {
            syslog(LOG_DEBUG, "Cname lookup failed %s", rootfqdn.c_str());
            testfailed = true;
        }
    }
    std::ofstream ofs("/tmp/DnsCache.json");
    if (not ofs.is_open()) {
        syslog(LOG_WARNING, "Couldn't open %s", filename.c_str());
        return true;
    }
    json j;
    auto exportRecords = i.exportJson(j);
    if (exportRecords != 74) {
        testfailed = true;
        syslog(LOG_WARNING, "Exported A/AAAA records %zu", exportRecords);
    }
    exportRecords = c.exportJson(j);
    if (exportRecords != 85) {
        testfailed = true;
        syslog(LOG_WARNING, "Exported CNAME records %zu", exportRecords);
    }

    ofs << std::setw(4) << j << std::endl;
    ofs.close();
    unlink("/tmp/DnsCache.json");

    std::set<std::string> PrunedCnames = c.pruneCnames(true);
    size_t pruned = PrunedCnames.size();
    if (pruned != 130) {
        syslog (LOG_DEBUG, "Pruned %zu DNS cnames", pruned);
        testfailed = 1;
    }
    std::set<std::string> PrunedFqdns =i.pruneResourceRecords(true);
    pruned = PrunedFqdns.size();
    if (pruned != 74) {
        syslog (LOG_DEBUG, "Pruned %zu DNS IP records", pruned);
        testfailed = 1;
    }
    testfailed |= do_cname_test();

    return testfailed;
}


bool do_cname_test() {
    MacAddress m("aa:bb:cc:dd:ee:ff");
    Host h(m, true);

    std::string fqdn = "ping.enphaseenergy.com";
    std::string cname1 = "ping.enphaseenergy.com.s3.amazonaws.com";
    std::string cname2 = "s3-1-w.amazonaws.com";
    Tins::IPv4Address ip("54.231.72.163");
    h.addorupdateDnsQueryList("ping.enphaseenergy.com");
    if (! h.inDnsQueryList("ping.enphaseenergy.com")) {
        syslog (LOG_DEBUG, "%s not in DnsQueryList", fqdn.c_str());
        return true;
    }
    syslog (LOG_DEBUG, "Found ping.enphaseenergy.com in DnsQueryList");

    DnsCnameCache c(true);
    DnsIpCache <Tins::IPv4Address> i(true);


    c.addorupdateCname(fqdn, cname1, 86400);
    if (c.getCname(fqdn) != cname1) {
        syslog (LOG_DEBUG, "%s does not have CNAME %s", fqdn.c_str(), cname1.c_str());
        return true;
    }
    syslog (LOG_DEBUG, "%s has CNAME %s", fqdn.c_str(), cname1.c_str());

    if (c.getFqdn(cname1) != fqdn) {
        syslog (LOG_DEBUG, "%s does not have FQDN %s", cname1.c_str(), fqdn.c_str());
        return true;
    }
    syslog (LOG_DEBUG, "%s has FQDN %s", cname1.c_str(), fqdn.c_str());

    c.addorupdateCname(cname1, cname2, 86400);
    if (c.getCname(cname1) != cname2) {
        syslog (LOG_DEBUG, "%s does not have CNAME %s", cname1.c_str(), cname2.c_str());
        return true;
    }
    syslog (LOG_DEBUG, "%s has CNAME %s", cname1.c_str(), cname2.c_str());

    if (c.getFqdn(cname2) != fqdn) {
        syslog (LOG_DEBUG, "%s does not have indirect FQDN %s", cname2.c_str(), fqdn.c_str());
        return true;
    }
    syslog (LOG_DEBUG, "%s has indirect FQDN %s", cname2.c_str(), fqdn.c_str());

    i.addorupdateResourceRecord(cname2, ip, 86400);
    std::vector<std::string> fqdns = i.getAllFqdns(ip);
    if (fqdns.size() > 1 || fqdns[0] != cname2) {
        syslog(LOG_DEBUG, "%s does not reverse in to FQDN %s", ip.to_string().c_str(), cname2.c_str());
        return true;
    }
    syslog(LOG_DEBUG, "%s reverses to FQDN %s", ip.to_string().c_str(), cname2.c_str());

    return false;
}
