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

class DnsCnameCache {
private:
    std::map<std::string,std::map<std::string,time_t>> DnsFwdCache;
    std::map<std::string,std::map<std::string,time_t>> DnsRevCache;
    time_t MinTtl;
    bool Debug;

public:
    DnsCnameCache(const time_t inMinTtl = 14400, const bool inDebug=false): MinTtl{inMinTtl}, Debug{inDebug} {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: constructing instance");
        }
    };
    ~DnsCnameCache() {
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

    void addorupdateCname (const std::string inFqdn, const std::string inCname, FqdnDeviceProfileMap &fdpMap, const time_t inTtl);
    void addorupdateCname (const std::string inFqdn, const std::string inCname,  time_t inTtl);
    std::set<std::string> getFqdns (const std::string inCname, const uint8_t recdepth = 0) const;
    std::set<std::string> getCnames (const std::string inFqdn, const uint8_t recdepth = 0);
    size_t importJson (json &j, FqdnDeviceProfileMap &fdpMap);
    size_t exportJson (json &j);
    std::set<std::string> pruneCnames (const bool Force = false);

};

template <class T>
class DnsIpCache {
private:
    std::map<std::string, std::map<T,time_t>> DnsFwdCache;
    std::map<T, std::map<std::string,time_t>> DnsRevCache;
    bool Debug;
    time_t MinTtl;

public:
    DnsIpCache(const time_t inMinTtl = 14400, const bool inDebug=false): MinTtl{inMinTtl}, Debug{inDebug} {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsIpCache: constructing instance");
        }
    };
    ~DnsIpCache() {
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

    /* std::map<T, time_t> lookupResourceRecord (const std::string inFqdn);
    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, FqdnDeviceProfileMap &fdpMap, const time_t inTtl = 604800);
    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, FqdnDeviceProfileMap::iterator &fdp_it, const time_t inTtl);
    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, time_t inTtl);
    size_t importJson (json &j, FqdnDeviceProfileMap &fdpMap);
    size_t exportJson(json &j);
    std::vector<std::string>  getAllFqdns  (T const inIpAddress) const;
    std::set<std::string> pruneResourceRecords (const bool Force = false);
*/

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
                syslog (LOG_DEBUG, "DnsIpCache: Updating resource record with FqdnDeviceProfileMap entry for %s", inFqdn.c_str());
            }
            addorupdateResourceRecord (fqdn, inIpAddress, fdp_it, inTtl);
        } else {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsIpCache: Didn't find FqdnDeviceProfileMap entry for %s", inFqdn.c_str());
            }
            addorupdateResourceRecord (fqdn, inIpAddress, inTtl);
        }
    }

    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, FqdnDeviceProfileMap::iterator &fdp_it, const time_t inTtl) {
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        for (auto DeviceProfile_sharedpointer_it: fdp_it->second) {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsIpCache: Found FqdnDeviceProfileMap entry with UUID %s for %s with IP %s",
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
            syslog (LOG_DEBUG, "DnsIpCache: Setting %s to %s with TTL %lu", inFqdn.c_str(), ipstring.c_str(), Expiration);
        }
        DnsFwdCache[inFqdn].insert(std::make_pair(inIpAddress, Expiration));
        DnsRevCache[inIpAddress].insert(std::make_pair(inFqdn, Expiration));
    }


    size_t importJson (json &j, FqdnDeviceProfileMap &fdpMap) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsIpCache: importing json");
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
            syslog (LOG_DEBUG, "DnsIpCache: export to json");
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

        //     j["CnameRecords"][it_resource.first][it_resource.second.first] = it_resource.second.second;
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
                    syslog (LOG_DEBUG, "DnsIpCache: AllFqdns adding %s", itf.first.c_str());
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
                            syslog(LOG_DEBUG, "DnsIpCache: pruning %s pointing to %s with expiration %lu while now is %lu",
                                    it_resource->first.c_str(), it_record->first.to_string().c_str(), it_record->second, now);
                        }
                        it_record = it_resource->second.erase(it_record);
                    } else {
                        it_record++;
                    }
                }
                if (Force || it_resource->second.empty()) {
                    if (Debug == true) {
                        syslog(LOG_DEBUG, "DnsIpCache: Removing record for %s as there is no data left", it_resource->first.c_str());
                    }
                    PrunedFqdns.insert(it_resource->first);
                    it_resource = DnsFwdCache.erase(it_resource);
                    if (Debug == true) {
                        syslog(LOG_DEBUG, "DnsIpCache: Deleted record");
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
                            syslog(LOG_DEBUG, "DnsIpCache: pruning entry %s pointing to %s  with expiration %lu while now is %lu",
                                    it_resource->first.to_string().c_str(), it_record->first.c_str(), it_record->second, now);
                        }
                        it_record = it_resource->second.erase(it_record);
                    } else {
                        it_record++;
                    }
                }
                if (Force || it_resource->second.empty()) {
                    if (Debug == true) {
                        syslog(LOG_DEBUG, "DnsIpCache: Removing record as there is no data left");
                    }
                    it_resource = DnsRevCache.erase(it_resource);
                    if (Debug == true) {
                        syslog(LOG_DEBUG, "DnsIpCache: Deleted record");
                    }
                } else {
                    it_resource++;
                }
            }
        }
        return PrunedFqdns;
    }



};


#endif /* DNSCACHE_H_ */
