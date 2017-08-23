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
 *      Author: steven
 */

#ifndef DNSCACHE_H_
#define DNSCACHE_H_

#include <map>
#include <vector>
#include <unordered_set>
#include <set>
#include "syslog.h"
#include "boost/asio.hpp"

#include <json.hpp>
using nlohmann::json;

#include "DeviceProfile.h"

class DnsCnameCache {
private:
    // FIXME: there may be multiple CNAMEs for an FQDN
    std::map<std::string,std::pair<std::string,time_t>> DnsCache;
    bool Debug;
public:
    DnsCnameCache(const bool inDebug=false): Debug{inDebug} {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: constructing instance");
        }
    };
    ~DnsCnameCache() {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: deletinginstance");
        }
    };

    void setDebug (bool inDebug) {
        Debug = inDebug;
    }

    void addorupdateCname (const std::string inFqdn, const std::string inCname, FqdnDeviceProfileMap &fdpMap, const time_t inTtl=604800) {
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        std::string cname = inCname;
        std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

        auto it = fdpMap.find(fqdn);
        if (it != fdpMap.end()) {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsIpCache: Found FqdnDeviceProfileMap entry for %s with CNAME %s",
                        inFqdn.c_str(), inCname.c_str());
            } else {
                syslog (LOG_DEBUG, "DnsCache: Didn't find FqdnDeviceProfileMap entry for %s with CNAME %s", inFqdn.c_str(), inCname.c_str() );
            }
            fdpMap[cname].insert(it->second.begin(), it->second.end());
        }
        addorupdateCname(fqdn, cname, inTtl);
    }

    void addorupdateCname (const std::string inFqdn, const std::string inCname, const time_t inTtl=604800) {
        time_t Ttl = inTtl;
        // We need to keep DNS records at least 4 hours as that is our maximum matching interval
        if (Ttl < 4 * 3600) {
            Ttl = 4 * 3600;
        }
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        std::string cname = inCname;
        std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

        auto now = time(nullptr);
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: Setting %s to CNAME %s with TTL %lu", fqdn.c_str(), cname.c_str(), Ttl);
        }
        DnsCache[cname] = std::make_pair(fqdn, now + Ttl);
    }

    std::string resolveCname (const std::string inCname, const uint8_t recdepth = 0) const {
        if (recdepth > 5) {
            return inCname;
        }
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: Resolving CNAME %s ", inCname.c_str());
        }
        std::string cname = inCname;
        std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

        auto it = DnsCache.find(cname);
        if (it != DnsCache.end()) {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsCnameCache: Found reverse CNAME from %s to %s", cname.c_str(), it->second.first.c_str());
            }
            return resolveCname(it->second.first, recdepth + 1);
        } else {
            return inCname;
        }
    }

    std::string lookupCname (const std::string inCname) {
        std::string cname = inCname;
        std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

        auto it = DnsCache.find(cname);
        if (it == DnsCache.end()) {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsCnameCache: %s does not have a CNAME", cname.c_str());
            }
            throw std::runtime_error("No CNAME found for " + inCname);
        }
        return it->second.first;
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
            dnsRecords++;
            std::string cname = it.key();
            std::string fqdn = it.value();
            auto fdp_it = fdpMap.find(fqdn);
            if (fdp_it != fdpMap.end()) {
                addorupdateCname (fqdn, cname, fdpMap, 86400);
            } else {
                addorupdateCname (fqdn, cname, 86400);
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
        for (auto it_resource: DnsCache) {
            dnsRecords++;
            j["CnameRecords"][it_resource.first]= it_resource.second.first;
        }
        return dnsRecords;
    }
    std::set<std::string> pruneCnames (const bool Force = false) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCnameCache: pruning cnames");
        }
        std::set<std::string> PrunedFqdns;
        auto now = time(nullptr);
        auto it = DnsCache.begin();
        while (it != DnsCache.end()) {
            if (Force || now > it->second.second) {
                if (Debug == true) {
                    syslog (LOG_DEBUG, "Deleting CNAME for %s pointing to %s with TTL %lu", it->first.c_str(), it->second.first.c_str(), it->second.second);
                }
                PrunedFqdns.insert(it->first);
                it = DnsCache.erase(it);
            } else {
                it++;
            }
        }
        return PrunedFqdns;
    }
};

template <class T>
class DnsIpCache {
private:
	std::map<std::string, std::map<T,time_t>> DnsFwdCache;
    std::map<T, std::map<std::string,time_t>> DnsRevCache;
    bool Debug;

public:
	DnsIpCache(const bool inDebug=false): Debug{inDebug} {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsIpCache: constructing instance");
        }
	};
	~DnsIpCache() {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsIpCache: destructing instance");
        }
	};

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
            addorupdateResourceRecord (fqdn, inIpAddress, fdp_it, inTtl);
        } else {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsIpCache: Didn't find FqdnDeviceProfileMap entry for %s", inFqdn.c_str());
            }
            addorupdateResourceRecord (fqdn, inIpAddress, inTtl);
        }
    }

    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, FqdnDeviceProfileMap::iterator &fdp_it, const time_t inTtl = 604800) {
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

	void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, const time_t inTtl = 604800) {
		time_t Ttl = inTtl;
        // We need to keep DNS records at least 4 hours as that is our maximum matching interval
		if (Ttl < 4 * 3600) {
			Ttl = 4 * 3600;
		}

		std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        auto now = time(nullptr);
		std::string ipstring = inIpAddress.to_string();
		if (Debug == true) {
			syslog (LOG_DEBUG, "DnsIpCache: Setting %s to %s with TTL %lu", inFqdn.c_str(), ipstring.c_str(), Ttl);
		}
		DnsFwdCache[inFqdn].insert(std::make_pair(inIpAddress, now + Ttl));
		DnsRevCache[inIpAddress].insert(std::make_pair(inFqdn, now + Ttl));
	}

	void setDebug (bool inDebug) {
		Debug = inDebug;
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
            dnsRecords++;
            std::string fqdn = it.key();
            std::unordered_set<std::string> records = (*cj)[fqdn].get<std::unordered_set<std::string>>();
            auto fdp_it = fdpMap.find(fqdn);
            for (auto record: records) {
                T IpAddress = T::from_string(record);
                if (fdp_it != fdpMap.end()) {
                    addorupdateResourceRecord (fqdn, IpAddress, fdp_it, 86400);
                } else {
                    addorupdateResourceRecord (fqdn, IpAddress, 86400);
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
	    j["AddressRecords"] = json::object();;
	    for (auto it_resource: DnsFwdCache) {
            dnsRecords++;
	        j["AddressRecords"][it_resource.first] = json::array();
	        for (auto it_record: it_resource.second) {
	            j["AddressRecords"][it_resource.first].push_back(it_record.first.to_string());
	        }

	    }
	    return dnsRecords;
	}

	std::vector<std::string>  getAllFqdns  (T const inIpAddress) const {
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
	std::set<std::string> pruneResourceRecords (const bool Force = false) {
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
