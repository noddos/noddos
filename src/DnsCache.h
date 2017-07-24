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
#include "syslog.h"
#include "boost/asio.hpp"

#include <json.hpp>
using nlohmann::json;

class DnsCnameCache {
private:
    // FIXME: there may be multiple CNAMEs for an FQDN
    std::map<std::string,std::pair<std::string,time_t>> DnsCache;
    bool Debug;
public:
    DnsCnameCache(const bool inDebug=false): Debug{inDebug} {};
    ~DnsCnameCache() {};

    void debug_set (bool inDebug) {
        Debug = inDebug;
    }
    void addorupdateCname (const std::string inFqdn, const std::string inCname, const time_t inTtl=604800) {
        time_t Ttl = inTtl;
        if (Ttl < 4 * 3600) {
            Ttl = 4 * 3600;
        }
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        std::string cname = inCname;
        std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

        auto now = time(nullptr);
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCache: Setting %s to CNAME %s with TTL %lu", fqdn.c_str(), cname.c_str(), Ttl);
        }
        DnsCache[cname] = std::make_pair(fqdn, now + Ttl);
    }

    std::string lookupCname (const std::string inCname, const uint8_t recdepth = 0) const {
        if (recdepth > 5) {
            return inCname;
        }
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCache: Seeing if %s is a CNAME", inCname.c_str());
        }
        std::string cname = inCname;
        std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

        auto it = DnsCache.find(cname);
        if (it != DnsCache.end()) {
            if (Debug == true) {
                syslog (LOG_DEBUG, "DnsCache: Found reverse CNAME from %s to %s", cname.c_str(), it->second.first.c_str());
            }
            return lookupCname(it->second.first, recdepth + 1);
        } else {
            return inCname;
        }
    }

    size_t importJson (json &j) {
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
            addorupdateCname (fqdn, cname, 86400);
        }
        return dnsRecords;
    }
    size_t exportJson (json &j) {
        size_t dnsRecords = 0;
        j["CnameRecords"] = json::object();
        for (auto it_resource: DnsCache) {
            dnsRecords++;
            j["CnameRecords"][it_resource.first]= it_resource.second.first;
        }
        return dnsRecords;
    }
    size_t pruneCnames (const bool Force = false) {
        size_t deleted = 0;
        auto now = time(nullptr);
        auto it = DnsCache.begin();
        while (it != DnsCache.end()) {
            if (Force || now > it->second.second) {
                if (Debug == true) {
                    syslog (LOG_DEBUG, "Deleting CNAME for %s pointing to %s with TTL %lu", it->first.c_str(), it->second.first.c_str(), it->second.second);
                }
                it = DnsCache.erase(it);
                deleted++;
            } else {
                it++;
            }
        }
        return deleted;
    }
};

template <class T>
class DnsIpCache {
private:
	std::map<std::string, std::map<T,time_t>> DnsFwdCache;
    std::map<T, std::map<std::string,time_t>> DnsRevCache;
    bool Debug;

public:
	DnsIpCache(const bool inDebug=false): Debug{inDebug} {};
	~DnsIpCache() {};

	void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, const time_t inTtl = 604800) {
		time_t Ttl = inTtl;
		if (Ttl < 4 * 3600) {
			Ttl = 4 * 3600;
		}

		std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        auto now = time(nullptr);
		std::string ipstring = inIpAddress.to_string();
		if (Debug == true) {
			syslog (LOG_DEBUG, "DnsCache: Setting %s to %s with TTL %lu", inFqdn.c_str(), ipstring.c_str(), Ttl);
		}
		DnsFwdCache[inFqdn].insert(std::make_pair(inIpAddress, now + Ttl));
		DnsRevCache[inIpAddress].insert(std::make_pair(inFqdn, now + Ttl));
	}

	void debug_set (bool inDebug) {
		Debug = inDebug;
	}

    size_t importJson (json &j) {
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
            for (auto record: records) {
                T IpAddress = T::from_string(record);
                addorupdateResourceRecord (fqdn, IpAddress, 86400);
            }
        }
        return dnsRecords;
    }

	size_t exportJson(json &j) {
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
					syslog (LOG_DEBUG, "DnsCache: AllFqdns adding %s", itf.first.c_str());
				}
				fqdns.push_back(itf.first);
			}
		} else {
			if (Debug == true) {
				syslog(LOG_DEBUG, "DnsCache: couldn't find DNS mappings for %s", ipstring.c_str());
			}
		}
		return fqdns;
	}
	uint32_t pruneResourceRecords (const bool Force = false) {
		uint32_t deletecount = 0;
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
						deletecount++;
					} else {
						it_record++;
					}
				}
				if (Force || it_resource->second.empty()) {
					if (Debug == true) {
						syslog(LOG_DEBUG, "DnsCache: Removing record for %s as there is no data left", it_resource->first.c_str());
					}
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
						deletecount++;
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
		return deletecount;
	}

};

#endif /* DNSCACHE_H_ */
