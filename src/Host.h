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

 * Host.cxx
 *
 *  Created on: Mar 6, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef HOST_CXX_
#define HOST_CXX_

#include <string>
#include <ctime>
#include <map>
#include <list>
#include <memory>

#include <json.hpp>
using json = nlohmann::json;

#include "noddos.h"
#include "DhcpRequest.h"
#include "FlowEntry.h"
#include "iCache.h"
#include "SsdpHost.h"
#include "DeviceProfile.h"
#include "MatchCondition.h"
#include "MacAddress.h"
#include "DnsCache.h"
#include "boost/asio.hpp"

typedef std::list<std::shared_ptr<FlowEntry>> FlowEntryList;


#define HOSTDEFAULTEXPIRATION 604800

class Host : public iCache {
private:
    std::map<std::string,time_t> DnsQueryList;

 	// std::map<std::string, std::shared_ptr<DnsLogEntry>> DnsHostCache;
   	std::map<boost::asio::ip::address_v4, std::shared_ptr<FlowEntryList>> FlowCacheIpv4;
   	std::map<boost::asio::ip::address_v6, std::shared_ptr<FlowEntryList>> FlowCacheIpv6;
   	std::string Ipv4Address;
   	std::string Ipv6Address;
   	MacAddress Mac;
   	DhcpRequest Dhcp;
   	SsdpHost Ssdp;
   	std::string Uuid;
   	time_t matchversion;
   	ConfidenceLevel IdentifyConfidenceLevel;
   	ConfidenceLevel EnforceConfidenceLevel;
   	bool UploadStats;
   	bool Debug;

public:
	Host(const MacAddress inMac, const bool inDebug = false): Mac{inMac}, Debug{inDebug}  {
		iCache::FirstSeen = iCache::LastSeen = iCache::LastModified = time(nullptr);
		UploadStats = true;
		matchversion = 0;
		IdentifyConfidenceLevel = EnforceConfidenceLevel = ConfidenceLevel::None;
	}

	Host(const MacAddress inMac, const std::string inUuid, const bool inDebug = false):
			Mac{inMac}, Uuid{inUuid}, Debug{inDebug} {
		iCache::FirstSeen = iCache::LastSeen = iCache::LastModified = time(nullptr);
		UploadStats = true;
		matchversion = 0;
		IdentifyConfidenceLevel = EnforceConfidenceLevel = ConfidenceLevel::None;
	}
	virtual ~Host() {
	    if (Debug == true) {
	        syslog (LOG_DEBUG, "Destroying Host instance: %s", Ipv4Address.c_str());
	    }
	};
	bool Match(const DeviceProfileMap& dpMap);
	ConfidenceLevel Match(const DeviceProfile& dp);
	ConfidenceLevel Match(const Identifier& i);
	bool Match(const MatchCondition& mc);
	bool Match(const ContainCondition& cc);
	void IpAddress_set (const std::string inIpAddress) { Ipv4Address = inIpAddress; }
	bool FlowEntry_set(const uint16_t inSrcPort, const std::string inDstIp,
			const uint16_t inDstPort, const uint8_t inProtocol, const uint32_t inExpiration);
	uint32_t FlowCacheCount () { return FlowCacheIpv4.size() + FlowCacheIpv6.size(); }
    bool Dhcp_set (const std::string IpAddress, const MacAddress Mac, const std::string Hostname, const std::string DhcpVendor);
	bool SsdpInfo_set(const std::shared_ptr<SsdpHost> insHost);

	// This manipulates the DnsQueryCache
	void addorupdateDnsQueryList (std::string inFqdn) {
	    std::string fqdn = inFqdn;
	    std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);
        DnsQueryList[fqdn] = time(nullptr);
	}
	bool inDnsQueryList (std::string inFqdn) {
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);
	    if (DnsQueryList.find(inFqdn) == DnsQueryList.end()) {
	        return false;
	    }
	    return true;
	}
	uint32_t pruneDnsQueryList (time_t Expired = 14400, bool Force = false);

	bool isMatched () { return Uuid != ""; }
	bool UploadsEnabled ();
	std::string Uuid_get () { return Uuid; }
	std::string MacAddress_get () { return Mac.str(); }
	std::string Ipv4Address_get () { return Ipv4Address; }
	std::string Ipv6Address_get () { return Ipv6Address; }
	void ExportDeviceInfo (json &j, bool detailed = false);
	bool DeviceStats(json& j, const uint32_t interval, bool force = false, bool detailed = false);
	bool TrafficStats(json& j, const uint32_t interval, const bool ReportRfc1918, const std::unordered_set<std::string> & LocalIps,
	        const DnsIpCache <boost::asio::ip::address> &dCip, const DnsCnameCache &dCcname, bool force = false);
	bool inPrivateAddressRange(const std::string ip );

	// iCache interface methods.
	time_t setExpiration (time_t inExpiration = HOSTDEFAULTEXPIRATION) {
	  	iCache::Expires = time(nullptr) + inExpiration;
	   	return iCache::LastSeen + HOSTDEFAULTEXPIRATION;
	}
	time_t getExpiration () { return iCache::LastSeen + HOSTDEFAULTEXPIRATION; }
	bool isExpired() { return time(nullptr) >= iCache::LastSeen + HOSTDEFAULTEXPIRATION; }
	uint32_t Prune (bool Force = false);
};
#endif /* HOST_CXX_ */

