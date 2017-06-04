/*
 * DnsCache.h
 *
 *  Created on: Jun 3, 2017
 *      Author: steven
 */

#ifndef DNSCACHE_H_
#define DNSCACHE_H_

#include <map>
#include <unordered_map>
#include "syslog.h"
#include "boost/asio.hpp"

/*
typedef std::map<std::string, time_t> QueryCache;
typedef std::map<boost::asio::ip::address_v4, std::unordered_set<std::map<std::string,time_t>>> Dnsv4RevCache;
typedef std::map<boost::asio::ip::address_v6, std::unordered_set<std::map<std::string,time_t>>> Dnsv6RevCache;
typedef std::map<std::string, std::unordered_set<std::map<boost::asio::ip::address_v6,time_t>>> Dnsv6Cache;
typedef std::map<std::string, std::unordered_set<std::map<boost::asio::ip::address_v4,time_t>>> Dnsv4Cache;
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
				auto it_record = it_resource->begin();
				while (it_record != it_resource->end()) {
					if (Force || now > (it_record->second + 1)) {
						it_record = it_resource->erase(it_record);
						deletecount++;
					}
				}
				if (Force || it_resource.empty()) {
					it_resource = DnsFwdCache.erase(it_resource);
				}
			}
		}
		{
			auto it_resource = DnsRevCache.begin();
			while (it_resource != DnsRevCache.end()) {
				auto it_record = it_resource->begin();
				while (it_record != it_resource->end()) {
					if (Force || now > (it_record->second + 1)) {
						it_record = it_resource->erase(it_record);
						deletecount++;
					}
				}
				if (Force || it_resource.empty()) {
					it_resource = DnsRevCache.erase(it_resource);
				}
			}
		}
		return deletecount;
	}

};

#endif /* DNSCACHE_H_ */
