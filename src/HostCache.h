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
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef HOSTCACHE_H_
#define HOSTCACHE_H_

#include <regex>
#include <memory>
#include <unordered_set>
#include <set>
#include <future>
#include <vector>
#include "Host.h"
#include "DeviceProfile.h"
#include "MacAddress.h"
#include "Config.h"
#include "InterfaceMap.h"

#include "boost/asio.hpp"
#include "DnsCache.h"
#include "noddos.h"

uint32_t RestApiCall (const std::string api, const json &j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload, bool Debug = false);

class HostCache {
private:
	std::map<unsigned long long, std::shared_ptr<Host>> hC; 	// map from Mac to Host
	std::map<std::string, unsigned long long> Ip2MacMap; 	// map from IP to MaC

	// This map is used to validate that answers received correspond to queries sent out. They are pruned after 30 seconds
	std::map<uint16_t, time_t> DnsQueryCache;
	// These maps cache IPv4 & IPv6 addresses and CNAMEs for at least the TrafficReport interval
	DnsIpCache <boost::asio::ip::address> dCip;
	DnsCnameCache dCcname;
	FqdnDeviceProfileMap fdpMap;

	DeviceProfileMap dpMap;
	InterfaceMap *ifMap;
	std::regex arp_rx, dev_rx;
	std::unordered_set<std::string> WhitelistedNodes;
	bool Debug;
	std::set<std::string> LocalInterfaces;
	std::set<std::string> LocalIpAddresses;
	uint32_t FlowExpiration;
	bool FirewallBlockTraffic;
	std::string FirewallRulesFile;

    void writeIptables();

public:
	HostCache(InterfaceMap &inifMap, const std::string inDnsCacheFilename,
	        const uint32_t inFlowExpiration, std::string inFirewallRulesFile,
	        const bool inFirewallBlockTraffic, const bool inDebug = false):
			ifMap{&inifMap}, FlowExpiration{inFlowExpiration}, Debug{inDebug},
			FirewallRulesFile{inFirewallRulesFile},
			FirewallBlockTraffic{inFirewallBlockTraffic} {
		if (Debug) {
			syslog (LOG_DEBUG, "HostCache: constructing instance");
		}
		dev_rx = std::regex(R"delim(^([^:]?):)delim",
				std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);

		arp_rx = std::regex(R"delim(^(\d\S+)\s+?\S+?\s+?\S+?\s+?\s+?(\S+)\s+?\S+?\W+?(\S+?)$)delim",
        	std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
		// FIXME: We don't really need the below anymore so should remove this call
		getInterfaceIpAddresses();
		dCip.setDebug(Debug);
		dCcname.setDebug(Debug);
		if (inDnsCacheFilename != "") {
		    importDnsCache(inDnsCacheFilename);
		}
	}
	virtual ~HostCache() {
		if (Debug) {
			syslog (LOG_DEBUG, "HostCache: destructing instance");
		}
	}

	uint32_t loadDeviceProfiles(const std::string filename);
	bool removeDeviceProfile(const std::string inUuid);
	const DeviceProfileMap & getDeviceProfilesMap() { return dpMap; };


	uint32_t Whitelists_set (const std::unordered_set<std::string>& inIpv4Addresses, const std::unordered_set<std::string>& inIpv6Addresses, const std::unordered_set<std::string>& inMacAddresses);
	bool isWhitelisted(const std::string inAddress) { return (WhitelistedNodes.find(inAddress) != WhitelistedNodes.end()); }
	bool isWhitelisted(Host &inHost) { return isWhitelisted(inHost.MacAddress_get()) || isWhitelisted(inHost.Ipv4Address_get()) || isWhitelisted(inHost.Ipv6Address_get()); }

	// Matching hosts with device profiles
	uint32_t Match();
	bool MatchByMac(const MacAddress &inMacAddress);
	bool MatchByIpAddress(const std::string inIpAddress);

    // Adding collected information to a Host instance
	bool AddByMac (const MacAddress inMacAddress, const std::string inIpAddress = "");
	bool AddFlow (const std::string srcip, const uint16_t srcport, const std::string dstip, const uint16_t dstport, const uint8_t protocol, const uint32_t expiration);
	bool AddDnsQueryIp (const std::string clientip, const std::string fqdn, const std::string ip, const uint32_t expire = 86400);
    bool AddDhcpRequest (const std::string IpAddress, const MacAddress inMac, const std::string Hostname, const std::string DhcpVendor);
	bool AddSsdpInfo (const std::shared_ptr<SsdpHost> insHost);

	std::shared_ptr<Host> FindHostByIp (const std::string inIp);
	std::shared_ptr<Host> FindOrCreateHostByIp (const std::string ip, const std::string Uuid = "");
	std::shared_ptr<Host> FindHostByMac (const MacAddress &inMac);
	std::shared_ptr<Host> FindOrCreateHostByMac (const MacAddress inMac, const std::string Uuid = "", const std::string inIp = "");

	// Prune Hosts, DnsCache etc
	uint32_t Prune (bool Force = false);

	// Manage short-lived cache entries needed for matching DNS answers to DNS queries
	void addorupdateDnsQueryCache (uint16_t id);
	bool inDnsQueryCache (uint16_t id);
	uint32_t pruneDnsQueryCache (bool Force = false);

	// These functions are for the new DnsCache filled by the PacketSnoop class
	void addorupdateDnsIpCache(const std::string inFqdn, const boost::asio::ip::address inIp, time_t inTtl = 604800);
	void addorupdateDnsCnameCache(const std::string inFqdn, const std::string inCname, time_t inTtl = 604800);
	void updateDeviceProfileMatchesDnsData ();

	// DnsCache persistence
	bool exportDnsCache (const std::string filename);
    bool importDnsCache (const std::string filename);
	uint32_t pruneDnsIpCache(bool Force = false) {
		std::set<std::string> PrunedFqdns = dCip.pruneResourceRecords(Force);
		for(auto Fqdn: PrunedFqdns) {
		    fdpMap.erase(Fqdn);
		}
		return PrunedFqdns.size();
	}
    uint32_t pruneDnsCnameCache(bool Force = false) {
        std::set<std::string> PrunedCnames = dCcname.pruneCnames(Force);
        for(auto Cname: PrunedCnames) {
            fdpMap.erase(Cname);
        }
        return PrunedCnames.size();
    }

	InterfaceMap * getInterfaceMap() { return ifMap; }
	MacAddress MacLookup (const std::string inIpAddress, const int retries = 1);
	MacAddress MacLookup (const std::string inIpAddress, const std::string inInterface, const int retries = 1);
	bool SendUdpPing (const std::string DstIpAddress, const uint16_t DstPort);
	uint32_t getInterfaceIpAddresses();
	std::set<std::string> getLocalIpAddresses() { return LocalIpAddresses; }

	void UploadDeviceStats(std::vector<std::future<uint32_t>> &futures, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload = false);
	void UploadTrafficStats(std::vector<std::future<uint32_t>> &futures, const time_t interval, const bool ReportRfc1918, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload = false);
    void RestApiCall_async (std::vector<std::future<uint32_t>> &futures, const std::string api, const json j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload = false);
    std::unique_ptr<std::future<uint32_t>> test_RestApiCall_async (const std::string api, const json j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload = false);

    uint32_t ImportDeviceProfileMatches(const std::string filename);
	bool ExportDeviceProfileMatches(const std::string filename, const bool detailed = false);
	bool ImportDeviceInfo (json &j);

	// uint32_t HostCount() { return hC.size(); }
	bool Debug_get() { return Debug; }
};

#endif /* HOSTCACHE_H_ */
