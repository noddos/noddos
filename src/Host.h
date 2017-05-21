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
 *      Author: steven
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
#include "DnsLogEntry.h"
#include "DhcpRequest.h"
#include "FlowEntry.h"
#include "iCache.h"
#include "SsdpHost.h"
#include "DeviceProfile.h"
#include "MatchCondition.h"

typedef std::map<std::string, std::shared_ptr<DnsLogEntry>> DnsCache;
typedef std::list<std::shared_ptr<FlowEntry>> FlowEntryList;


#define HOSTDEFAULTEXPIRATION 604800

class Host : public iCache {
	private:
    	std::map<std::string, std::shared_ptr<DnsLogEntry>> DnsCache;
    	std::map<std::string, std::shared_ptr<FlowEntryList>> FlowCache;
    	std::string Ipv4Address;
    	std::string Ipv6Address;
    	std::string MacAddress;
    	DhcpRequest Dhcp;
    	SsdpHost Ssdp;
    	std::string Uuid;
    	time_t matchtime;
    	ConfidenceLevel IdentifyConfidenceLevel;
    	ConfidenceLevel EnforceConfidenceLevel;
    	bool UploadStats;
    	bool Debug;

	public:
		Host(const std::string inMacAddress, const bool inDebug = false): MacAddress{inMacAddress}, Debug{inDebug}  {
			iCache::FirstSeen = iCache::LastSeen = iCache::LastModified = time(nullptr);
			UploadStats = true;
			matchtime = 0;
			IdentifyConfidenceLevel = EnforceConfidenceLevel = ConfidenceLevel::None;
		}

		Host(const std::string inMacAddress, const std::string inUuid, const bool inDebug = false):
				MacAddress{inMacAddress}, Uuid{inUuid}, Debug{inDebug} {
			iCache::FirstSeen = iCache::LastSeen = iCache::LastModified = time(nullptr);
			UploadStats = true;
			matchtime = 0;
			IdentifyConfidenceLevel = EnforceConfidenceLevel = ConfidenceLevel::None;
		}
		virtual ~Host() {
			syslog (LOG_DEBUG, "Destroying Host instance: %s", Ipv4Address.c_str());
		};

		bool Match(const DeviceProfileMap& dpMap);
		ConfidenceLevel Match(const DeviceProfile& dp);
		ConfidenceLevel Match(const Identifier& i);
		bool Match(const MatchCondition& mc);
		bool Match(const ContainCondition& cc);

		void IpAddress_set (const std::string IpAddress) { Ipv4Address = IpAddress; }
		bool FlowEntry_set(const uint16_t inSrcPort, const std::string &inDstIp, const uint16_t inDstPort, const uint8_t inProtocol, const uint32_t inExpiration);
		uint32_t FlowCacheCount () { return FlowCache.size(); }
		bool DnsLogEntry_set(const std::string fqdn, const std::string ipaddress, const uint32_t expiration = 86400);
		uint32_t DnsLogEntryCount () { return DnsCache.size(); }
		bool Dhcp_set (const std::shared_ptr<DhcpRequest> inDhcp_sptr);
		bool Dhcp_set (const std::string IpAddress, const std::string MacAddress, const std::string Hostname, const std::string DhcpHostname, const std::string DhcpVendor);
		bool SsdpInfo_set(const std::shared_ptr<SsdpHost> insHost);

		bool isMatched () { return Uuid != ""; }
		bool UploadsEnabled ();
		std::string Uuid_get () { return Uuid; }
		std::string MacAddress_get () { return MacAddress; }
		std::string Ipv4Address_get () { return Ipv4Address; }
		std::string Ipv6Address_get () { return Ipv6Address; }

		void ExportDeviceInfo (json &j, bool detailed = false);
		bool DeviceStats(json& j, const uint32_t interval, bool force = false, bool detailed = false);
		bool TrafficStats(json& j, const uint32_t interval, const bool ReportRfc1918, const std::unordered_set<std::string> & LocalIps, bool force = false);
		bool inPrivateAddressRange(const std::string ip );

	    // iCache interface methods.
	    time_t Expiration_set (time_t inExpiration = HOSTDEFAULTEXPIRATION) {
	    	iCache::Expires = time(nullptr) + inExpiration;
	    	return iCache::LastSeen + HOSTDEFAULTEXPIRATION;
	    }
	    time_t Expiration_get () { return iCache::LastSeen + HOSTDEFAULTEXPIRATION; }
	    bool isExpired() { return time(nullptr) >= iCache::LastSeen + HOSTDEFAULTEXPIRATION; }
	    uint32_t Prune (bool Force = false);
};
#endif /* HOST_CXX_ */

