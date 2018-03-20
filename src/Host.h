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
#include <regex>

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include "json.hpp"
using json = nlohmann::json;

#include <glog/logging.h>

#include "noddos.h"
#include "DhcpRequest.h"
#include "FlowEntry.h"
#include "iCache.h"
#include "DeviceProfile.h"
#include "MatchCondition.h"
#include "MacAddress.h"
#include "DnsCache.h"


typedef std::list<std::shared_ptr<FlowEntry>> FlowEntryList;




/*! \class Host
 *  \brief A host device on the network that may have been matched to a device profile
 *
 *  The Host class stores all information about a host/device on the network. The traffic of hosts
 *  is tracked to allow it to be matched to a list of Device Profiles to find out what the manufacter and model
 *  of the host is. Traffic policies may be assigned to all traffic coming from and destined for the host.
 */
class Host : public iCache {
private:

    std::map<std::string,time_t> DnsQueryList; //!< All DNS queries performed by the host
    uint32_t MinDnsTtl; //!< Mininum TTL for DNS data, as data must not be expired before the next Traffic Report interval
 	std::map<Tins::IPv4Address, std::shared_ptr<FlowEntryList>> FlowCacheIpv4; //!< Tracking of all IPv4 flows of the host
   	std::map<Tins::IPv6Address, std::shared_ptr<FlowEntryList>> FlowCacheIpv6; //!< Tracking of all IPv6 flows of the host

   	std::string Ipv4Address; //!< IPv4 address of the host TODO: support multiple IPv6 addresses
   	std::string Ipv6Address; //!< IPv6 address of the host TODO: support multiple IPv6 addresses
   	MacAddress Mac; //!< Ethernet MAC address of the host
   	DhcpRequest Dhcp; //!< Data on any DHCP request sent by the host
   	SsdpHost Ssdp; //!< Simple Service Discovery Protocol data sent by the host
   	WsDiscoveryHost Wsd; //!< Web Service Discovery data sent by the host
   	MdnsHost Mdns; //!< Multicast Domain Name Service data sent by the host
   	std::string Uuid; //!< UUID of the DeviceProfile that the host has been matched with
   	uint16_t matchversion; //!< The version of the DeviceProfile used to match the host with
   	ConfidenceLevel IdentifyConfidenceLevel; //!< Confidence level of the match
   	ConfidenceLevel EnforceConfidenceLevel; //!< Confidence level to restrict traffic of the host
   	bool UploadStats; //!< Should statistics of this host be uploaded to the cloud API?
   	bool Debug; //!< Should debug logging be generated for this host?

public:
   	/*! \brief Constructor for the Host class
   	 *  Creates a new host object
   	 *  \param [in] inMac the Ethernet MAC address of the host
   	 *  \param [in] inDebug optional flag to enable debug logging for this host
   	 */
	Host(const MacAddress inMac, const uint32_t inMinDnsTtl = DNSQUERYDEFAULTTTL, const bool inDebug = false):
	        Mac{inMac}, MinDnsTtl{inMinDnsTtl}, Debug{inDebug}  {
		iCache::FirstSeen = iCache::LastSeen = iCache::LastModified = time(nullptr);
		UploadStats = true;
		matchversion = 0;
		IdentifyConfidenceLevel = EnforceConfidenceLevel = ConfidenceLevel::None;
	}
    /*! \brief Constructor for the Host class
     *  Creates a new host object
     *  \param [in] inMac the Ethernet MAC address of the host
     *  \param [in] inUuid the UUID of the DeviceProfile to which the host has previously been matched
     *  \param [in] inDebug optional flag to enable debug logging for this host
     */
	Host(const MacAddress inMac, const std::string inUuid,
	        const uint32_t inMinDnsTtl = DNSQUERYDEFAULTTTL, const bool inDebug = false):
			Mac{inMac}, Uuid{inUuid}, MinDnsTtl{inMinDnsTtl}, Debug{inDebug} {
		iCache::FirstSeen = iCache::LastSeen = iCache::LastModified = time(nullptr);
		UploadStats = true;
		matchversion = 0;
		IdentifyConfidenceLevel = EnforceConfidenceLevel = ConfidenceLevel::None;
	}

    /*! \brief class destructor
     */
	virtual ~Host() {
	    DLOG_IF(INFO, Debug) << "Destroying Host instance: " << Ipv4Address;
	};

	uint32_t Prune (const bool Force = false);

	bool Match(const DeviceProfileMap& dpMap);
	ConfidenceLevel Match(const DeviceProfile& dp);
	ConfidenceLevel Match(const Identifier& i);
	bool Match(const MatchCondition& mc);
	bool Match(const ContainCondition& cc);


	bool setFlowEntry(const uint16_t inSrcPort, const std::string inDstIp,
			const uint16_t inDstPort, const uint8_t inProtocol, const uint32_t inTtl);

	/*! \brief Get the total number of destinations in the FlowCache for a host
	 *  \return Total number of IPv4 and IPv6 destinations to which a host has flows
	 */
	uint32_t FlowDestinationCount () { return FlowCacheIpv4.size() + FlowCacheIpv6.size(); }

	bool setDhcp (const std::string IpAddress, const MacAddress Mac, const std::string Hostname, const std::string DhcpVendor);
	bool setSsdpInfo(const std::shared_ptr<SsdpHost> insHost);
	bool setWsDiscoveryInfo(const std::shared_ptr<WsDiscoveryHost> inwsdHost);
    bool setMdnsInfo(const std::shared_ptr<MdnsHost> inmdnsHost);

    void addorupdateDnsQueryList (const std::string inFqdn, const time_t inTtl = DNSQUERYDEFAULTTTL);
    bool inDnsQueryList (const std::string inFqdn);
  	uint32_t pruneDnsQueryList (const bool Force = false);

  	/*! \brief Check whether a host has been matched to a Device Profile
  	 *  \return bool on whether the host has been matched to a Device Profile
  	 */
	bool isMatched () { return Uuid != ""; }

	/*! \brief Get the UUID of the DeviceProfile to which the host has been matched
	 *  \return string with UUID of the host or an empty string if the host has not been matched
	 */
	std::string getUuid () { return Uuid; }

	/*! \brief Get the MAC address of the host
	 *  \return string with the MAC address of the host
	 */
	std::string getMacAddress () { return Mac.str(); }

    /*! \brief Set the IPv4 address of the host
     *  \param [in] inIpAddress constant string with an IPv4 address
     */
    void setIpAddress (const std::string inIpAddress) { Ipv4Address = inIpAddress; }

    /*! \brief Get the IPv4 address of the host
	 *  \return string with the IPv4 address of the host or empty string if the host does not have an IPv4 address
	 */
	std::string getIpv4Address () { return Ipv4Address; }

    /*! \brief Get the IPv6 address of the host
     *  \return string with the IPv6 address of the host or empty string if the host does not have an IPv4 address
     */
	std::string getIpv6Address () { return Ipv6Address; }

	/*! \brief Check whether the upload of statistics is enabled for this host
     * \return bool whether uploads are enabled for the host
     */
    bool UploadsEnabled () { return UploadStats; }

	void exportDeviceInfo (json &j, const bool detailed = false);
	bool exportDeviceStats(json& j, const uint32_t interval, bool force = false, bool detailed = false);
	bool exportTrafficStats(json& j, const uint32_t interval, const bool ReportRfc1918,
	        const std::set<std::string> & LocalIps,
	        const DnsCache <Tins::IPv4Address> &dCipv4,
	        const DnsCache <Tins::IPv6Address> &dCipv6,
	        const DnsCache <std::string> &dCcname, const bool Force = false);

	/*
	 * iCache interface methods.
	 */

	/*! \brief Set the expiration of the host
	 * Hosts discovered on the network may eventually be expired if no traffic has been traffic to or from the host
	 * \param [in] inExpiration seconds after which a host with no inbound or outgoing traffic should be expired
	 * \return Timestamp of when host will be expired
	 */
	time_t setExpiration (const uint32_t inTtl = HOSTDEFAULTTTL) {return iCache::Expires = time(nullptr) + inTtl; }

	/*! \brief Get the expiration of the host
	 *  \return the timestamp of the expiration of the host
	 */
    time_t getExpiration () { return iCache::Expires; }

    /*! \brief is the host expired?
     *  \return bool on whether the host has expired
     */
	bool isExpired() { return time(nullptr) >= iCache::Expires;}
};
#endif /* HOST_CXX_ */

