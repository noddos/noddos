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

 * HostCache.h
 *
 *  Created on: Mar 11, 2017
 *      Author: steven
 */

#ifndef HOSTCACHE_H_
#define HOSTCACHE_H_

#include <regex>
#include <memory>
#include <unordered_set>

// #include "cpr/cpr.h"

#include "Host.h"
#include "DeviceProfile.h"
#include "Config.h"

#include "noddos.h"

class HostCache {
private:
	std::map<std::string, std::shared_ptr<Host>> hC; 	// map from Mac to Host
	std::map<std::string, std::string> Ip2MacMap; 	// map from IP to MaC
	DeviceProfileMap dpMap;
	std::regex arp_rx, dev_rx;
	std::unordered_set<std::string> WhitelistedNodes;
	bool Debug;
	std::unordered_set<std::string> LocalInterfaces;
	std::unordered_set<std::string> LocalIpAddresses;
	uint32_t FlowExpiration;




public:
	HostCache(const uint32_t inFlowExpiration = FLOWDEFAULTEXPIRATION, const bool inDebug = false): Debug{inDebug} {
		if (inFlowExpiration == 0) {
			// Stats upload is disabled so we set a reasonable default to expire the flow cache
			FlowExpiration = FLOWDEFAULTEXPIRATION;
		} else {
			FlowExpiration = inFlowExpiration;
		}
		dev_rx = std::regex(R"delim(^([^:]?):)delim",
				std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);

		arp_rx = std::regex(R"delim(^(\d\S+)\s+?\S+?\s+?\S+?\s+?\s+?(\S+)\s+?\S+?\W+?(\S+?)$)delim",
        	std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
		getInterfaceIpAddresses();
	}
	virtual ~HostCache() {
		if (Debug) {
			syslog (LOG_DEBUG, "Destroying HostCache instance");
		}
	}

	uint32_t DeviceProfiles_load(const std::string filename);

	uint32_t Whitelists_set (const std::unordered_set<std::string>& inIpv4Addresses, const std::unordered_set<std::string>& inIpv6Addresses, const std::unordered_set<std::string>& inMacAddresses);
	bool isWhitelisted(std::string inAddress) { return (WhitelistedNodes.find(inAddress) != WhitelistedNodes.end()); }
	bool isWhitelisted(Host &inHost) { return isWhitelisted(inHost.MacAddress_get()) || isWhitelisted(inHost.Ipv4Address_get()) || isWhitelisted(inHost.Ipv6Address_get()); }

	uint32_t Match();
	bool MatchByMac(const std::string inMacAddress);
	bool MatchByIpAddress(const std::string inIpAddress);

	bool AddByMac (const std::string inMacAddress, const std::string inIpAddress = "");
	bool AddFlow (const std::string srcip, const uint16_t srcport, const std::string dstip, const uint16_t dstport, const uint8_t protocol, const uint32_t expiration);
	bool AddDnsQueryIp (const std::string clientip, const std::string fqdn, const std::string ip, const uint32_t expire = 86400);
	bool AddDhcpRequest (const std::shared_ptr<DhcpRequest> inDhcpRequest_sptr);
	bool AddDhcpRequest (const DhcpRequest &inDhcpRequest);
	bool AddDhcpRequest (const std::string IpAddress, const std::string MacAddress, const std::string Hostname, const std::string DhcpHostname, const std::string DhcpVendor);
	bool AddSsdpInfo (const std::shared_ptr<SsdpHost> insHost);

	std::shared_ptr<Host> FindOrCreateHostByIp (const std::string ip, const std::string Uuid = "");
	std::shared_ptr<Host> FindOrCreateHostByMac (const std::string mac, const std::string Uuid = "", const std::string inIp = "");

	uint32_t Prune (bool Force = false);

	std::string MacLookup (const std::string inIpAddress, const int retries = 1);
	std::string MacLookup (const std::string inIpAddress, std::string inInterface, const int retries = 1);
	bool SendUdpPing (const std::string DstIpAddress, const uint16_t DstPort);
	uint32_t getInterfaceIpAddresses();

	uint32_t RestApiCall (const std::string api, const json &j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile);
	bool ExportDeviceProfileMatches(const std::string filename, const bool detailed = false);
	uint32_t UploadDeviceStats(const std::string ClientApiCertFile, const std::string ClientApiKeyFile);
	bool UploadTrafficStats(const time_t interval, const bool ReportRfc1918, const std::string ClientApiCertFile, const std::string ClientApiKeyFile);
	bool ImportDeviceProfileMatches(const std::string filename);
	bool ImportDeviceInfo (json &j);

	uint32_t HostCount() { return hC.size(); }
	uint32_t HostDnsQueryCount (std::string IpAddress);
	bool Debug_get() { return Debug; }
};

#endif /* HOSTCACHE_H_ */
