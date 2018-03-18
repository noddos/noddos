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

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include "DnsCache.h"
#include "noddos.h"

uint32_t RestApiCall (const std::string api, const json &j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload, bool Debug = false);

/*! \class HostCache
 *  \brief Store of all the hosts discovered on the network
 *
 *  The main data structure of Noddos. All hosts are stored in here, together with all DNS data. All listeners have a reference
 *  to this data structure and invoke the various methods to add data.
 */
class HostCache {
private:
	std::map<unsigned long long, std::shared_ptr<Host>> hC; //!< map from Mac to Host
	std::map<std::string, unsigned long long> Ip2MacMap; 	//!< map from IP to MaC

	std::map<uint16_t, time_t> DnsQueryCache; //!< validate that DNS answers received correspond to DNS queries previously sent out.
	// These maps cache IPv4 & IPv6 addresses and CNAMEs for at least the TrafficReport interval
	DnsCache <Tins::IPv4Address> dCipv4; //!< Cache for DNS A RRs
	DnsCache <Tins::IPv6Address> dCipv6; //!< Cache for DNS AAAA RRs
	DnsCache <std::string> dCcname; //!< Cache for DNS CNAME RRs
	FqdnDeviceProfileMap fdpMap; //!< Map maintained to check whether an FQDN (or a CNAME pointing to it) is listed as an allowed Destination in a Device Profile

	DeviceProfileMap dpMap; //!< Map of all device profiles, with key the UUID of the Device Profile
	InterfaceMap *ifMap; //!< map of all interfaces of the host on which Noddos is running
	std::unordered_set<std::string> WhitelistedNodes; //!< Set of hosts for which traffic will not be monitored or restricted
	bool Debug; //!< Should debug logging be enabled?
	std::set<std::string> LocalInterfaces;
	std::set<std::string> LocalIpAddresses;
	time_t MinFlowTtl; //!< Minimum TTL for flows
	time_t MinDnsTtl; //!< Minimum TTL for DNS records.
	bool FirewallBlockTraffic; //!< Should the firewall just log or also block traffic
	std::string FirewallRulesFile; //!< location to store the temporary rules file that will be read by ip(6)tables

    void writeIptables();

public:
    /*! \brief constructer for HostCache
     * \param [in] inifMap reference to InterfaceMap
     * \param [in] inDnsCacheFilename constant string with the filename containing cached DNS records
     * \param [in] inMinFlowTtl constant unsigned integer of 32 bits with the minium Time To Live for Flow entries, should match the traffic report interval
     * \param [in] inFirewallRulesFile
     * \param [in] inFirewallBlockTraffic contant bool of whether the host firewall should only log traffic or also block it
     * \param [in]
     */
	HostCache(InterfaceMap &inifMap, const std::string inDnsCacheFilename, const uint32_t inMinFlowTtl,
	        const time_t inMinDnsTtl, const std::string inFirewallRulesFile,
	        const bool inFirewallBlockTraffic, const bool inDebug = false):
			ifMap{&inifMap}, MinFlowTtl{inMinFlowTtl}, MinDnsTtl{inMinDnsTtl}, Debug{inDebug},
			FirewallRulesFile{inFirewallRulesFile},
			FirewallBlockTraffic{inFirewallBlockTraffic} {
		DLOG_IF(INFO, Debug) << "constructing instance";

		getInterfaceIpAddresses();
		dCipv4.setDebug(Debug);
        dCipv4.setMinTtl(MinDnsTtl);
        dCipv6.setDebug(Debug);
        dCipv6.setMinTtl(MinDnsTtl);
		dCcname.setDebug(Debug);
        dCcname.setMinTtl(MinDnsTtl);

		if (inDnsCacheFilename != "") {
		    importDnsCache(inDnsCacheFilename);
		}
	}
	//! \brief destructer for HostCache
	virtual ~HostCache() {
	    DLOG_IF(INFO, Debug) << "destructing instance";
	}

	uint32_t loadDeviceProfiles(const std::string filename);
	bool removeDeviceProfile(const std::string inUuid);
	const DeviceProfileMap & getDeviceProfilesMap() { return dpMap; };


	uint32_t Whitelists_set (const std::unordered_set<std::string>& inIpv4Addresses, const std::unordered_set<std::string>& inIpv6Addresses, const std::unordered_set<std::string>& inMacAddresses);
	bool isWhitelisted(const std::string inAddress) { return (WhitelistedNodes.find(inAddress) != WhitelistedNodes.end()); }
	bool isWhitelisted(Host &inHost) { return isWhitelisted(inHost.getMacAddress()) || isWhitelisted(inHost.getIpv4Address()) || isWhitelisted(inHost.getIpv6Address()); }

	// Matching hosts with device profiles
	uint32_t Match();
	bool MatchByMac(const MacAddress &inMacAddress);
	bool MatchByIpAddress(const std::string inIpAddress);

    // Adding collected information to a Host instance
	bool AddByMac (const MacAddress inMacAddress, const std::string inIpAddress = "");
	bool AddFlow (const std::string srcip, const uint16_t srcport, const std::string dstip, const uint16_t dstport, const uint8_t protocol, const uint32_t expiration);
	bool AddDnsQueryIp (const std::string clientip, const std::string fqdn, const std::string ip, const uint32_t inTtl = DNSQUERYDEFAULTTTL);
    bool AddDhcpRequest (const std::string IpAddress, const MacAddress inMac, const std::string Hostname, const std::string DhcpVendor);
	bool AddSsdpInfo (const std::shared_ptr<SsdpHost> insHost);
	bool AddWsDiscoveryInfo (std::shared_ptr<WsDiscoveryHost> inwsdHost);
    bool AddMdnsInfo (std::shared_ptr<MdnsHost> inmdnsHost);

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
	void addorupdateDnsIpCache(const std::string inFqdn, const Tins::IPv4Address inIp, time_t inTtl = 604800);
    void addorupdateDnsIpCache(const std::string inFqdn, const Tins::IPv6Address inIp, time_t inTtl = 604800);
	void addorupdateDnsCnameCache(const std::string inFqdn, const std::string inCname, time_t inTtl = 604800);
	void updateDeviceProfileMatchesDnsData ();

	// DnsCache persistence
	bool exportDnsCache (const std::string filename);
    bool importDnsCache (const std::string filename);
	uint32_t pruneDnsIpCache(bool Force = false) {
	    std::set<std::string> PrunedFqdns = dCipv4.pruneResourceRecords(Force);
        std::set<std::string> PrunedIpv6Fqdns = dCipv6.pruneResourceRecords(Force);
        PrunedFqdns.insert(PrunedIpv6Fqdns.begin(), PrunedIpv6Fqdns.end());
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
	MacAddress MacLookup (const std::string inIpAddress);
	MacAddress MacLookup (const std::string inIpAddress, const std::string inInterface, bool Retry = false);
	bool sendUdpPing (const std::string DstIpAddress, const uint16_t DstPort);
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
