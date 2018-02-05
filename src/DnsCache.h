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

 * DnsCache.h
 *
 *  Created on: Jun 3, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef DNSCACHE_H_
#define DNSCACHE_H_

#include <map>
#include <vector>
#include <unordered_set>
#include <set>
#include "syslog.h"

#include "json.hpp"
using nlohmann::json;

#include "DeviceProfile.h"

template <class T, class U>
std::set<std::string> pruneDnsCache (std::map<T, std::map<U, time_t>> &cache, bool Force = false, bool Debug = false) {
    std::set<std::string> PrunedFqdns;
    auto now = time(nullptr);
    auto it_resource = cache.begin();
    while (it_resource != cache.end()) {
        auto it_record = it_resource->second.begin();
        while (it_record != it_resource->second.end()) {
            if (Force || now > (it_record->second + 1)) {
                if (Debug == true) {
                    syslog(LOG_DEBUG, "pruneDnsCache: pruning %s pointing to %s with expiration %lu while now is %lu",
                            it_resource->first.c_str(), it_record->first.to_string().c_str(), it_record->second, now);
                }
                it_record = it_resource->second.erase(it_record);
            } else {
                it_record++;
            }
        }
        if (Force || it_resource->second.empty()) {
            if (Debug == true) {
                syslog(LOG_DEBUG, "pruneDnsCache: Removing record for %s as there is no data left", it_resource->first.c_str());
            }
            PrunedFqdns.insert(it_resource->first);
            it_resource = cache.erase(it_resource);
            if (Debug == true) {
                syslog(LOG_DEBUG, "pruneDnsCache: Deleted record");
            }
        } else {
            it_resource++;
        }
    }
}

template <class T>
class DnsCache {
private:
    std::map<std::string, std::map<T,time_t>> DnsFwdCache;
    std::map<T, std::map<std::string,time_t>> DnsRevCache;
    bool Debug;
    time_t MinTtl;

public:
    DnsCache(const time_t inMinTtl = 14400, const bool inDebug=false): MinTtl{inMinTtl}, Debug{inDebug} {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsIpCache: constructing instance");
        }
    };
    ~DnsCache() {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsIpCache: destructing instance");
        }
    };

    void setDebug (bool inDebug) {
        Debug = inDebug;
    }
    void setMinTtl (bool inMinTtl = 14400) {
        MinTtl = inMinTtl;
    }

    std::map<T, time_t> lookupResourceRecord (const std::string inFqdn) {
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        auto it = DnsFwdCache.find(fqdn);
        if (it == DnsFwdCache.end()) {
            throw std::runtime_error("No resource record found for " + inFqdn);
        }
        return it->second;
    }

    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, FqdnDeviceProfileMap &fdpMap, const time_t inTtl = 604800) {
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        auto fdp_it = fdpMap.find(fqdn);
        if (fdp_it != fdpMap.end()) {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsCache: Updating resource record with FqdnDeviceProfileMap entry for %s", inFqdn.c_str());
            }
            addorupdateResourceRecord (fqdn, inIpAddress, fdp_it, inTtl);
        } else {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsCache: Didn't find FqdnDeviceProfileMap entry for %s", inFqdn.c_str());
            }
            addorupdateResourceRecord (fqdn, inIpAddress, inTtl);
        }
    }

    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, FqdnDeviceProfileMap::iterator &fdp_it, const time_t inTtl) {
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        for (auto DeviceProfile_sharedpointer_it: fdp_it->second) {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsCache: Found FqdnDeviceProfileMap entry with UUID %s for %s with IP %s",
                        DeviceProfile_sharedpointer_it->getUuid().c_str(), inFqdn.c_str(), inIpAddress.to_string().c_str());
            }
            DeviceProfile_sharedpointer_it->addDestination(inIpAddress, inTtl);
        }
        addorupdateResourceRecord (fqdn, inIpAddress, inTtl);
    }

    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, time_t inTtl) {
        // We need to keep DNS records at least 4 hours as that is our maximum matching interval
        auto now = time(nullptr);
        if (inTtl < MinTtl) {
            inTtl = MinTtl;
        }
        time_t Expiration = now + inTtl;

        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        std::string ipstring = inIpAddress.to_string();
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCache: Setting %s to %s with TTL %lu", inFqdn.c_str(), ipstring.c_str(), Expiration);
        }
        DnsFwdCache[inFqdn].insert(std::make_pair(inIpAddress, Expiration));
        DnsRevCache[inIpAddress].insert(std::make_pair(inFqdn, Expiration));
    }

    size_t importJson (json &j, FqdnDeviceProfileMap &fdpMap) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCache: importing json");
        }
        size_t dnsRecords = 0;
        auto cj = j.find("AddressRecords");
        if (cj == j.end()) {
            return true;
        }
        if (not cj->is_object()) {
            return true;
        }
        for (json::iterator it = cj->begin(); it != cj->end(); ++it) {
            std::string fqdn = it.key();
            auto fdp_it = fdpMap.find(fqdn);
            json ipj = it.value();
            for (json::iterator ip_it = ipj.begin(); ip_it != ipj.end(); ++ip_it) {
                try {
                    T IpAddress = T(ip_it.key());
                    dnsRecords++;

                    time_t expiration = ip_it.value();
                    if (fdp_it != fdpMap.end()) {
                        addorupdateResourceRecord (fqdn, IpAddress, fdp_it, expiration);
                    } else {
                        addorupdateResourceRecord (fqdn, IpAddress, expiration);
                    }
                } catch (...) {
                    // Must be either IPv4 address while IPv6 template or vice versa
                }
            }
        }
        return dnsRecords;
    }

    size_t exportJson(json &j) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCache: export to json");
        }
        size_t dnsRecords = 0;
        j["AddressRecords"] = json::object();
        for (auto it_resource: DnsFwdCache) {
            dnsRecords++;
            j["AddressRecords"][it_resource.first] = json::object();
            for (auto it_record: it_resource.second) {
                std::string ip = it_record.first.to_string();
                time_t ttl = it_record.second;
                j["AddressRecords"][it_resource.first][ip] = ttl;
            }

        }

        return dnsRecords;
    }

    std::vector<std::string> getAllFqdns  (T const inIpAddress) const {
        std::vector<std::string> fqdns;
        std::string ipstring = inIpAddress.to_string();
        auto it = DnsRevCache.find(inIpAddress);
        if (it != DnsRevCache.end()) {
            const std::map<std::string,time_t> &m = it->second;
            for (auto itf : m) {
                if (Debug == true) {
                    syslog (LOG_DEBUG, "DnsCache: AllFqdns adding %s", itf.first.c_str());
                }
                fqdns.push_back(itf.first);
            }
        } else {
            if (Debug == true) {
                syslog(LOG_DEBUG, "DnsIpCache: couldn't find DNS mappings for %s", ipstring.c_str());
            }
        }
        return fqdns;
    }

    std::set<std::string> pruneResourceRecords (const bool Force) {
        std::set<std::string> PrunedFqdns;
        auto now = time(nullptr);
        {
            auto it_resource = DnsFwdCache.begin();
            while (it_resource != DnsFwdCache.end()) {
                auto it_record = it_resource->second.begin();
                while (it_record != it_resource->second.end()) {
                    if (Force || now > (it_record->second + 1)) {
                        if (Debug == true) {
                            syslog(LOG_DEBUG, "DnsCache: pruning %s pointing to %s with expiration %lu while now is %lu",
                                    it_resource->first.c_str(), it_record->first.to_string().c_str(), it_record->second, now);
                        }
                        it_record = it_resource->second.erase(it_record);
                    } else {
                        it_record++;
                    }
                }
                if (Force || it_resource->second.empty()) {
                    if (Debug == true) {
                        syslog(LOG_DEBUG, "DnsCache: Removing record for %s as there is no data left", it_resource->first.c_str());
                    }
                    PrunedFqdns.insert(it_resource->first);
                    it_resource = DnsFwdCache.erase(it_resource);
                    if (Debug == true) {
                        syslog(LOG_DEBUG, "DnsCache: Deleted record");
                    }
                } else {
                    it_resource++;
                }
            }
        }
        {
            auto it_resource = DnsRevCache.begin();
            while (it_resource != DnsRevCache.end()) {
                auto it_record = it_resource->second.begin();
                while (it_record != it_resource->second.end()) {
                    if (Force || now > (it_record->second + 1)) {
                        if (Debug == true) {
                            syslog(LOG_DEBUG, "DnsCache: pruning entry %s pointing to %s  with expiration %lu while now is %lu",
                                    it_resource->first.to_string().c_str(), it_record->first.c_str(), it_record->second, now);
                        }
                        it_record = it_resource->second.erase(it_record);
                    } else {
                        it_record++;
                    }
                }
                if (Force || it_resource->second.empty()) {
                    if (Debug == true) {
                        syslog(LOG_DEBUG, "DnsCache: Removing record as there is no data left");
                    }
                    it_resource = DnsRevCache.erase(it_resource);
                    if (Debug == true) {
                        syslog(LOG_DEBUG, "DnsCache: Deleted record");
                    }
                } else {
                    it_resource++;
                }
            }
        }
        return PrunedFqdns;
    }



};

template<>
class DnsCache <std::string> {
private:
    std::map<std::string,std::map<std::string,time_t>> DnsFwdCache;
    std::map<std::string,std::map<std::string,time_t>> DnsRevCache;
    time_t MinTtl;
    bool Debug;

public:
    DnsCache(const time_t inMinTtl = 14400, const bool inDebug=false): MinTtl{inMinTtl}, Debug{inDebug} {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: constructing instance");
        }
    };
    ~DnsCache() {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: deleting instance");
        }
    };

    void setDebug (bool inDebug) {
        Debug = inDebug;
    }
    void setMinTtl (bool inMinTtl = 14400) {
        MinTtl = inMinTtl;
    }

    /*
    void addorupdateCname (const std::string inFqdn, const std::string inCname, FqdnDeviceProfileMap &fdpMap, const time_t inTtl);
    void addorupdateCname (const std::string inFqdn, const std::string inCname,  time_t inTtl);
    std::set<std::string> getFqdns (const std::string inCname, const uint8_t recdepth = 0) const;
    std::set<std::string> getCnames (const std::string inFqdn, const uint8_t recdepth = 0);
    size_t importJson (json &j, FqdnDeviceProfileMap &fdpMap);
    size_t exportJson (json &j);
    std::set<std::string> pruneCnames (const bool Force = false);
    */
    void addorupdateCname (const std::string inFqdn, const std::string inCname,  time_t inTtl) {
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


    void addorupdateCname (const std::string inFqdn, const std::string inCname, FqdnDeviceProfileMap &fdpMap, const time_t inTtl) {
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
    std::set<std::string> getFqdns (const std::string inCname, const uint8_t recdepth = 0) const {
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
                fqdns.insert(fqdn_it.first);
                std::set<std::string> additional_fqdns = getFqdns(fqdn_it.first, recdepth + 1);
                fqdns.insert(additional_fqdns.begin(),additional_fqdns.end());
            }
        }
        return fqdns;
    }

    // Find the CNAME for an FQDN
    std::set<std::string> getCnames (const std::string inFqdn, const uint8_t recdepth = 0) {
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
                cnames.insert(cname_it.first);
                std::set<std::string> additional_cnames;
                try {
                    additional_cnames = getCnames(cname_it.first, recdepth + 1);
                }
                catch (const std::runtime_error &e) {

                }
                cnames.insert(additional_cnames.begin(),additional_cnames.end());
        }
        return cnames;
    }

    size_t importJson (json &j, FqdnDeviceProfileMap &fdpMap) {
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
    size_t exportJson (json &j) {
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

    std::set<std::string> pruneCnames (const bool Force) {
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
                if (Pruned == true) {
                    PrunedFqdns.insert(it->first);
                }
                if (RecordsKept == false) {
                    it = DnsFwdCache.erase(it);
                } else {
                    it++;
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
                if (Pruned == true) {
                    PrunedFqdns.insert(it_rev->first);
                }
                if (RecordsKept == false) {
                    it_rev = DnsRevCache.erase(it_rev);
                } else {
                    it_rev++;
                }
            }
        }
        return PrunedFqdns;
    }
};

#endif /* DNSCACHE_H_ */
