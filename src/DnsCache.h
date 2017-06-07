/*
 * DnsCache.h
 *
 *  Created on: Jun 3, 2017
 *      Author: steven
 */

#ifndef DNSCACHE_H_
#define DNSCACHE_H_

#include <map>
#include "syslog.h"
#include "boost/asio.hpp"
/*
class Cname {
	std::string cname;
};
*/
template <class T>
class DnsCache {
private:
	std::map<T, std::map<std::string,time_t>> DnsRevCache;
	std::map<std::string, std::map<T,time_t>> DnsFwdCache;
	bool Debug;

public:
	DnsCache(bool inDebug=false): Debug{inDebug} {};
	~DnsCache() {};

	void addorupdateResourceRecord (std::string inFqdn, T inIpAddress, time_t Ttl = 86400) {
		auto now = time(nullptr);
		DnsFwdCache[inFqdn][inIpAddress] = now + Ttl;
		DnsRevCache[inIpAddress][inFqdn] = now + Ttl;
	}

	uint32_t pruneResourceRecords (bool Force = false) {
		uint32_t deletecount = 0;
		auto now = time(nullptr);
		{
			auto it_resource = DnsFwdCache.begin();
			while (it_resource != DnsFwdCache.end()) {
				auto it_record = it_resource->second.begin();
				while (it_record != it_resource->second.end()) {
					if (Force || now > (it_record->second + 1)) {
						it_record = it_resource->second.erase(it_record);
						deletecount++;
					}
				}
				if (Force || it_resource->second.empty()) {
					it_resource = DnsFwdCache.erase(it_resource);
				}
			}
		}
		{
			auto it_resource = DnsRevCache.begin();
			while (it_resource != DnsRevCache.end()) {
				auto it_record = it_resource->second.begin();
				while (it_record != it_resource->second.end()) {
					if (Force || now > (it_record->second + 1)) {
						it_record = it_resource->second.erase(it_record);
						deletecount++;
					}
				}
				if (Force || it_resource->second.empty()) {
					it_resource = DnsRevCache.erase(it_resource);
				}
			}
		}
		return deletecount;
	}

};

#endif /* DNSCACHE_H_ */
