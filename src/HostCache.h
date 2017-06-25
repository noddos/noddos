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

#include "Host.h"
#include "DeviceProfile.h"
#include "MacAddress.h"
#include "Config.h"
#include "DnsCache.h"
#include "InterfaceMap.h"

#include "boost/asio.hpp"

#include "noddos.h"

class HostCache {
private:
	std::map<unsigned long long, std::shared_ptr<Host>> hC; 	// map from Mac to Host
	std::map<std::string, unsigned long long> Ip2MacMap; 	// map from IP to MaC

	// This map is used to validate that answers received correspond to queries sent out
	std::map<uint16_t, time_t> DnsQueryCache;

	DnsCache <boost::asio::ip::address_v4> dCv4;
	DnsCache <boost::asio::ip::address_v6> dCv6;
	DnsCache <std::string> dCcname;

	DeviceProfileMap dpMap;
	InterfaceMap *ifMap;
	std::regex arp_rx, dev_rx;
	std::unordered_set<std::string> WhitelistedNodes;
	bool Debug;
	std::unordered_set<std::string> LocalInterfaces;
	std::unordered_set<std::string> LocalIpAddresses;
	uint32_t FlowExpiration;

public:
	HostCache(InterfaceMap &inifMap, const uint32_t inFlowExpiration = FLOWDEFAULTEXPIRATION, const bool inDebug = false):
			ifMap{&inifMap}, Debug{inDebug} {
		if (Debug) {
			syslog (LOG_DEBUG, "Initializing HostCache instance");
		}
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
	const DeviceProfileMap & DeviceProfiles_getmap() { return dpMap; };

	uint32_t Whitelists_set (const std::unordered_set<std::string>& inIpv4Addresses, const std::unordered_set<std::string>& inIpv6Addresses, const std::unordered_set<std::string>& inMacAddresses);
	bool isWhitelisted(const std::string inAddress) { return (WhitelistedNodes.find(inAddress) != WhitelistedNodes.end()); }
	bool isWhitelisted(Host &inHost) { return isWhitelisted(inHost.MacAddress_get()) || isWhitelisted(inHost.Ipv4Address_get()) || isWhitelisted(inHost.Ipv6Address_get()); }

	uint32_t Match();
	bool MatchByMac(const MacAddress &inMacAddress);
	bool MatchByIpAddress(const std::string inIpAddress);

	bool AddByMac (const MacAddress inMacAddress, const std::string inIpAddress = "");
	bool AddFlow (const std::string srcip, const uint16_t srcport, const std::string dstip, const uint16_t dstport, const uint8_t protocol, const uint32_t expiration);
	bool AddDnsQueryIp (const std::string clientip, const std::string fqdn, const std::string ip, const uint32_t expire = 86400);
	bool AddDhcpRequest (const std::shared_ptr<DhcpRequest> inDhcpRequest_sptr);
	bool AddDhcpRequest (const DhcpRequest &inDhcpRequest);
	bool AddDhcpRequest (const std::string IpAddress, const MacAddress inMac, const std::string Hostname, const std::string DhcpHostname, const std::string DhcpVendor);
	bool AddSsdpInfo (const std::shared_ptr<SsdpHost> insHost);

	std::shared_ptr<Host> FindHostByIp (const std::string inIp);
	std::shared_ptr<Host> FindOrCreateHostByIp (const std::string ip, const std::string Uuid = "");
	std::shared_ptr<Host> FindHostByMac (const MacAddress &inMac);
	std::shared_ptr<Host> FindOrCreateHostByMac (const MacAddress inMac, const std::string Uuid = "", const std::string inIp = "");

	uint32_t Prune (bool Force = false);

	void addorupdateDnsQueryCache (uint16_t id);
	bool inDnsQueryCache (uint16_t id);
	uint32_t pruneDnsQueryCache (bool Force = false);

	// These functions are for the new DnsCache filled by the PacketSnoop class
	void addorupdateDnsCache(std::string inFqdn, boost::asio::ip::address_v4 inIp, time_t inTtl) { dCv4.addorupdateResourceRecord(inFqdn, inIp, inTtl); }
	void addorupdateDnsCache(std::string inFqdn, boost::asio::ip::address_v6 inIp, time_t inTtl) { dCv6.addorupdateResourceRecord(inFqdn, inIp, inTtl);	}
	void addorupdateDnsCache(std::string inFqdn, std::string inCname, time_t inTtl) { dCcname.addorupdateResourceRecord(inFqdn, inCname, inTtl);	}

	uint32_t pruneDnsCache(bool Force = false) {
		uint32_t deletecount = 0;
		deletecount = dCv4.pruneResourceRecords(Force) + dCv6.pruneResourceRecords(Force);
		return deletecount;
	}
	InterfaceMap * getInterfaceMap() { return ifMap; }
	MacAddress MacLookup (const std::string inIpAddress, const int retries = 1);
	MacAddress MacLookup (const std::string inIpAddress, const std::string inInterface, const int retries = 1);
	bool SendUdpPing (const std::string DstIpAddress, const uint16_t DstPort);
	uint32_t getInterfaceIpAddresses();

	uint32_t RestApiCall (const std::string api, const json &j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload = false);
	uint32_t UploadDeviceStats(const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload = false);
	bool UploadTrafficStats(const time_t interval, const bool ReportRfc1918, const std::string ClientApiCertFile, const std::string ClientApiKeyFile,
			bool doUpload = false);
	uint32_t ImportDeviceProfileMatches(const std::string filename);
	bool ExportDeviceProfileMatches(const std::string filename, const bool detailed = false);
	bool ImportDeviceInfo (json &j);

	uint32_t HostCount() { return hC.size(); }
	uint32_t HostDnsQueryCount (std::string IpAddress);
	bool Debug_get() { return Debug; }
};

#endif /* HOSTCACHE_H_ */
