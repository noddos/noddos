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

 * DnsCache.cxx
 *
 *  Created on: Dec 28, 2017
 *      Author: Steven Hessing
 */

#include <map>
#include <vector>
#include <unordered_set>
#include <set>
#include "syslog.h"

#include "DnsCache.h"

#include "json.hpp"
using nlohmann::json;

void DnsCnameCache::addorupdateCname (const std::string inFqdn, const std::string inCname,  time_t inTtl) {
    auto now = time(nullptr);
    if (inTtl < MinTtl) {
        inTtl = MinTtl;
    }
    time_t Expiration = now + inTtl;

    std::string fqdn = inFqdn;
    std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

    std::string cname = inCname;
    std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

    if (Debug == true) {
        syslog (LOG_DEBUG, "DnsCnameCache: Setting %s to CNAME %s with expiration %lu", fqdn.c_str(), cname.c_str(), Expiration);
    }
    DnsRevCache[cname][fqdn] = Expiration;
    DnsFwdCache[fqdn][cname] = Expiration;
}


void DnsCnameCache::addorupdateCname (const std::string inFqdn, const std::string inCname, FqdnDeviceProfileMap &fdpMap, const time_t inTtl) {
    std::string fqdn = inFqdn;
    std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

    std::string cname = inCname;
    std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

    auto it = fdpMap.find(fqdn);
    if (it != fdpMap.end()) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: Found FqdnDeviceProfileMap entry for %s with CNAME %s",
                    inFqdn.c_str(), inCname.c_str());
        } else {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsCnameCache: Didn't find FqdnDeviceProfileMap entry for %s with CNAME %s", inFqdn.c_str(), inCname.c_str() );
            }
        }
        fdpMap[cname].insert(it->second.begin(), it->second.end());
    }
    addorupdateCname(fqdn, cname, inTtl);
}



// Finds the FQDN for a CNAME record, that doesn't have a CNAME record pointing to it
std::set<std::string> DnsCnameCache::getFqdns (const std::string inCname, const uint8_t recdepth) const {
    if (recdepth > 5) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: Reached max recursion depth for CNAME %s", inCname.c_str());
        }
        throw std::runtime_error("DNS reverse CNAME recursion depth reached for " + inCname);
    }
    if (Debug == true) {
        syslog (LOG_DEBUG, "DnsCnameCache: Resolving CNAME %s ", inCname.c_str());
    }
    std::string cname = inCname;
    std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

    std::set<std::string> fqdns;
    auto it = DnsRevCache.find(cname);
    if (it != DnsRevCache.end()) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: Found one or more reverse CNAME for %s", cname.c_str());
        }
        for (auto fqdn_it: it->second) {
            std::set<std::string> additional_fqdns = getFqdns(fqdn_it.first, recdepth + 1);
            fqdns.insert(additional_fqdns.begin(),additional_fqdns.end());
        }
    }
    return fqdns;
}

// Find the CNAME for an FQDN
std::set<std::string> DnsCnameCache::getCnames (const std::string inFqdn, const uint8_t recdepth) {
    if (recdepth > 5) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: Reached max recursion depth for FQDN %s", inFqdn.c_str());
        }
        throw std::runtime_error("DNS CNAME recursion depth reached for " + inFqdn);
    }
    if (Debug == true) {
        syslog (LOG_DEBUG, "DnsCnameCache: Looking up CNAMEs for %s", inFqdn.c_str());
    }
    std::string fqdn = inFqdn;
    std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

    auto it = DnsFwdCache.find(fqdn);
    if (it == DnsFwdCache.end()) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: %s does not have a CNAME", inFqdn.c_str());
        }
        throw std::runtime_error("No CNAME found for " + inFqdn);
    }
    if (Debug == true) {
        syslog (LOG_DEBUG, "DnsCnameCache: Found one or more CNAME for %s", fqdn.c_str());
    }
    std::set<std::string> cnames;
    for (auto cname_it: it->second) {
            std::set<std::string> additional_cnames = getCnames(cname_it.first, recdepth + 1);
            cnames.insert(additional_cnames.begin(),additional_cnames.end());
    }
    return cnames;
}

size_t DnsCnameCache::importJson (json &j, FqdnDeviceProfileMap &fdpMap) {
    if (Debug == true) {
        syslog (LOG_DEBUG, "DnsCnameCache: importing json with cnames");
    }
    size_t dnsRecords = 0;
    auto cj = j.find("CnameRecords");
    if (cj == j.end()) {
        return true;
    }
    if (not cj->is_object()) {
        return true;
    }
    for (json::iterator it = cj->begin(); it != cj->end(); ++it) {
        std::string fqdn = it.key();
        json v = it.value();
        if (v.is_object() == true) {
            for (json::iterator c_it = it->begin(); c_it != it->end(); ++c_it) {
                dnsRecords++;
                std::string cname = c_it.key();
                time_t expiration = c_it.value();
                auto fdp_it = fdpMap.find(fqdn);
                if (fdp_it != fdpMap.end()) {
                    addorupdateCname (fqdn, cname, fdpMap, expiration);
                } else {
                    addorupdateCname (fqdn, cname, expiration);
                }
            }
        }
    }
    return dnsRecords;
}
size_t DnsCnameCache::exportJson (json &j) {
    if (Debug == true) {
        syslog (LOG_DEBUG, "DnsCnameCache: exporting cnames to json");
    }
    size_t dnsRecords = 0;
    j["CnameRecords"] = json::object();
    for (auto it_resource: DnsFwdCache) {
        dnsRecords++;
        j["CnameRecords"][it_resource.first]= json::object();
        for (auto it_cname: it_resource.second) {
            j["CnameRecords"][it_resource.first][it_cname.first] = it_cname.second;
        }
    }
    return dnsRecords;
}

std::set<std::string> DnsCnameCache::pruneCnames (const bool Force) {
    if (Debug == true) {
        syslog (LOG_DEBUG, "DnsCnameCache: pruning cnames");
    }
    std::set<std::string> PrunedFqdns;
    auto now = time(nullptr);
    {
        auto it = DnsFwdCache.begin();
        while (it != DnsFwdCache.end()) {
            std::string Fqdn = it->first;
            std::map <std::string,time_t> &CnameMap = it->second;
            bool RecordsKept = false;
            bool Pruned = false;
            auto cname_it = CnameMap.begin();
            while(cname_it != CnameMap.end()) {
                if (Force || now > cname_it->second) {
                    if (Debug == true) {
                        syslog (LOG_DEBUG, "Deleting CNAME for %s pointing to %s with TTL %lu", Fqdn.c_str(), cname_it->first.c_str(), cname_it->second);
                    }
                    Pruned = true;
                    cname_it = CnameMap.erase(cname_it);
                } else {
                    cname_it++;
                    RecordsKept = true;
                }
            }
            if (RecordsKept == false) {
                it = DnsFwdCache.erase(it);
            } else {
                it++;
            }
            if (Pruned == true) {
                PrunedFqdns.insert(it->first);
            }
        }
    }
    {
        auto it_rev = DnsRevCache.begin();
        while (it_rev != DnsRevCache.end()) {
            std::string Cname = it_rev->first;
            std::map <std::string,time_t> &FqdnMap = it_rev->second;
            bool RecordsKept = false;
            bool Pruned = false;
            auto fqdn_it = FqdnMap.begin();
            while(fqdn_it != FqdnMap.end()) {
                if (Force || now > fqdn_it->second) {
                    if (Debug == true) {
                        syslog (LOG_DEBUG, "Deleting reverse CNAME for %s pointing to %s with TTL %lu", Cname.c_str(), fqdn_it->first.c_str(), fqdn_it->second);
                    }
                    Pruned = true;
                    fqdn_it = FqdnMap.erase(fqdn_it);
                } else {
                    fqdn_it++;
                    RecordsKept = true;
                }
            }
            if (RecordsKept == false) {
                it_rev = DnsRevCache.erase(it_rev);
            } else {
                it_rev++;
            }
            if (Pruned == true) {
                PrunedFqdns.insert(it_rev->first);
                it_rev = DnsRevCache.erase(it_rev);
            } else {
                it_rev++;
            }
        }
    }
    return PrunedFqdns;
}




