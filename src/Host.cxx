/*

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

 * Host.cpp
 *
 *  Created on: Mar 6, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#include <cstring>
#include <ctime>
#include <string>
#include <set>
#include <forward_list>
#include <map>
#include <unordered_set>
#include <vector>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <syslog.h>
#include <glog/logging.h>

#include "json.hpp"
using json = nlohmann::json;

#include "Host.h"
#include "DhcpRequest.h"
#include "SsdpLocation.h"
#include "FlowEntry.h"
#include "DeviceProfile.h"

/*! \brief Create or update the list of DNS queries performed by the host
 * Keeps track of DNS lookups performed by the host so that they can be matched to a Device Profile. We expire these DNS lookups only after a week
 * as at the time of the DNS lookup, we do not know what the TTL of the response will be.
 * \param [in] inFqdn FQDN of the DNS lookup
 * \param [in] inTtl constant time_t of time to live for the DNS record
 */
void Host::addorupdateDnsQueryList (std::string inFqdn, const time_t inTtl) {
    std::string fqdn = inFqdn;
    std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);
    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address <<"): Setting DnsQueryList for " << fqdn << " to now";
    DnsQueryList[fqdn] = time(nullptr) + inTtl;
}

/*! \brief Check whether the host has performed a DNS lookup for an FQDN
 *  \param [in] FQDN of the DNS lookup
 *  \return [out] Boolean value whether the host has performed a DNS lookup for the FQDN that has not expired
 */
bool Host::inDnsQueryList (std::string inFqdn) {
    std::string fqdn = inFqdn;
    std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);
    if (DnsQueryList.find(fqdn) == DnsQueryList.end()) {
        DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): " << fqdn << " not in DnsQueryList";
        return false;
    }
    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): " << fqdn << " is in DnsQueryList";
    return true;
}

/*! \brief Match the host against a list of Device Profiles
 * \param [in] dpMap a reference to a std::map of Device Profiles
 * \return bool value whether the host was succesfully matched
 */
bool Host::Match(const DeviceProfileMap& dpMap) {
	// If no newer version of the DeviceProfile it previously matched to is available then no need to try to
	// match the device again
	if (isMatched()) {
		auto it = dpMap.find(Uuid);
		if (it != dpMap.end()) {
			if (matchversion > it->second->getDeviceProfileVersion()) {
				return true;
			}
		}
	}
	ConfidenceLevel bestmatch = ConfidenceLevel::None;
	std::string matcheduuid = "";
	for (auto &mapentry : dpMap) {
	    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Evaluating host " << Mac << " against device profile " << mapentry.first;
		auto &deviceProfile = *(mapentry.second);
		auto match = Match(deviceProfile);
		if (match > bestmatch) {
            bestmatch = match;
            matcheduuid = mapentry.first;
            UploadStats = deviceProfile.getUploadStats();
			matchversion = deviceProfile.getDeviceProfileVersion();
		}
	}
	if (bestmatch >= ConfidenceLevel::Low) {
		Uuid = matcheduuid;
		DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Host " << Mac << " matched " << Uuid;
		return true;
	}
	return false;
}

/*! \brief Match a host with a Device Profile
 * A Device Profile consists of one or more Identifiers and each Identifier consists of one or more Match Conditions
 * and/or Contain Conditions
 * \param [in] deviceProfile reference to Device Profile
 * \return Confidence Level of the match (ConfidenceLevel::None if the host doesn't match)
 */
ConfidenceLevel Host::Match(const DeviceProfile& deviceProfile) {
	ConfidenceLevel bestmatch = ConfidenceLevel::None;
	auto v = deviceProfile.getIdentifiers();
	for (auto& i : v) {
	    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Testing identifier";
		auto match = Match(*i);
		if (match >= ConfidenceLevel::High) {
		    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Host " << Mac << " matched with high confidence";
			return match;
        }
		if 	(match > bestmatch) {
			bestmatch = match;
        }
	}
	DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Host " << Mac << " match level " << static_cast<int>(bestmatch);
	return bestmatch;
}

/*! \brief Match a host to an Identifier of a Device Profile
 * Each Device Profile has one or more Identifiers. An Identier has one or more Match Conditions and/or Contain Conditions
 * \param [in] identifier reference to an Identifier, which is one of the ways for a Device Profile to identify a host
 * \return Confidence Level of the match (ConfidenceLevel::None if the host doesn't match)
 */
ConfidenceLevel Host::Match(const Identifier& identifier) {
	for (auto& matchCondition : identifier.MatchConditions_get()) {
			DLOG_IF(INFO, Debug) << "Host: Testing match condition " << (*matchCondition).Key;
		if(not Match (*matchCondition)) {
		    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Host " << Mac << " did not match condition " << (*matchCondition).Key;
			return ConfidenceLevel::None;
		}
	}
	for (auto& containCondition : identifier.ContainConditions_get()) {
	    DLOG_IF(INFO, Debug) << "Host: Testing contain condition " << (*containCondition).Key;
		if(not Match (*containCondition)) {
		    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Host " << Mac << " did not contain condition " << (*containCondition).Key;
			return ConfidenceLevel::None;
		}
	}
	DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Host " << Mac << " matched MustMatch and/or MustContain conditions";
	return identifier.IdentifyConfidenceLevel_get();
}

/*! \brief Compare a host with a Match Condition
 *  Each Identifier of a Device Profile has one or more Match Conditions. The match condition might be a string used in DHCP,
 *  SSDP, WsDicovery or mDNS protocol communication or it may be based on the MAC OID. Here we compare whether the host matches
 *  the specific Match Condition. The function supports wildcard matching (indicated by '*' at the beginning or the end of the string.
 *  Wildcards can't be both at the beginning and the end of the string or in the middle of the string.
 *  \param [in] matchCondition reference to a Match Condition
 *  \return bool whether the host matched the Match Condition
 *  \sa ContainCondition, Identifier, DeviceProfile, Host
 */
bool Host::Match(const MatchCondition& matchCondition) {
	std::string value;
	if (matchCondition.Key == "MacOid") {
		value = Mac.str().substr(0,8);
	} else if (matchCondition.Key == "DhcpVendor") {
		value = Dhcp.DhcpVendor;
	} else if (matchCondition.Key == "DhcpHostname") {
		value = Dhcp.Hostname ;
	} else if (matchCondition.Key == "SsdpFriendlyName" ) {
		value = Ssdp.FriendlyName;
	} else if (matchCondition.Key == "SsdpManufacturer") {
		value = Ssdp.Manufacturer;
    } else if (matchCondition.Key == "SsdpDeviceType") {
        value = Ssdp.DeviceType;
	} else if (matchCondition.Key == "SsdpManufacturerUrl") {
		value = Ssdp.ManufacturerUrl;
	} else if (matchCondition.Key == "SsdpModelName") {
		value = Ssdp.ModelName;
	} else if (matchCondition.Key == "SsdpModelUrl") {
		value = Ssdp.ModelUrl;
	} else if (matchCondition.Key == "SsdpSerialNumber") {
		value = Ssdp.SerialNumber;
	} else if (matchCondition.Key == "SsdpUserAgent") {
		value = Ssdp.UserAgent;
	} else if (matchCondition.Key == "SsdpServer") {
		value = Ssdp.Server;
	} else if (matchCondition.Key == "SsdpLocation") {
		value = Ssdp.Location;
	} else if (matchCondition.Key == "WsDiscoveryXAddrs") {
	    value = Wsd.wsdXAddrs;
	} else if (matchCondition.Key == "WsDiscoveryTypes") {
	    value = Wsd.wsdTypes;
    } else if (matchCondition.Key == "MdnsHostname") {
        value = Mdns.Hostname;
	} else if (matchCondition.Key == "MdnsOs") {
	    value = Mdns.Os;
	} else if (matchCondition.Key == "MdnsHw") {
	    value = Mdns.Hw;
    } else if (matchCondition.Key == "MdnsDeviceUrl") {
        value = Mdns.DeviceUrl;
    } else if (matchCondition.Key == "MdnsManufacturer") {
        value = Mdns.Manufacturer;
    } else if (matchCondition.Key == "MdnsModelName") {
        value = Mdns.ModelName;
	}
	if (value == "" || std::all_of(value.begin(),value.end(),isspace)) {
	    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Host " << Mac << "has no value for MustMatch condition " << matchCondition.Key;
	}
	size_t startpos = 0;
	size_t mcvaluelength = matchCondition.Value.length();
	size_t datavaluelength = value.length();
	std::string mcvalue = matchCondition.Value;
	if (matchCondition.Value[0] == '*') {
		mcvalue = mcvalue.substr(1);
		startpos = datavaluelength - mcvalue.length();
	} else if (matchCondition.Value[mcvaluelength-1] == '*') {
		mcvalue = mcvalue.substr(0,mcvaluelength-1);
		startpos = 0;
	}
    if (value.length() < mcvalue.length()) {
        return false;
    }
    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): comparing " << value << " with " << mcvalue <<
            " start position " << startpos << ", length " << mcvalue.length()-startpos;
	if (value.compare(startpos, mcvalue.length() - startpos, mcvalue) == 0) {
	    DLOG_IF(INFO, Debug) <<"Host: Host " << Mac << " matched MustMatch condition";
		return true;
    }
	DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Host " << value << " did not match condition " << matchCondition.Key << " with value " << mcvalue <<
	        " from position" << startpos;
	return false;
}

/*! \brief Match a host against a Contain Condition
 *  A Contain Condition consits of one or more values that must all be in a list. At this only the 'DnsQueries'
 *  ContainCondition is supported where the values are FQDNs and the host must have made non-expired DNS lookups
 *  for all of them.
 *  \param [in]containCondition reference to a constant ContainCondition
 *  \return bool whether the host matched the Match Condition
 *  \sa MatchCondition, Identifier, DeviceProfile, Host, Match()
 */
bool Host::Match(const ContainCondition& containCondition) {
	if(containCondition.Key == "DnsQueries") {
		for (auto fqdn: containCondition.Values) {
		    if (inDnsQueryList(fqdn) == true) {
		        DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Found DnsQuery for " << fqdn << " from host " << Mac;
			} else {
			    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Didn't find DnsQuery for " << fqdn << " from host " << Mac;
				return false;
			}
		}
	} else {
	    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Unsupported MustContain key " << containCondition.Key;
		return false;
	}
	DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Host " << Mac << " matched MustContain condition";
	return true;
}

/*! \brief Upload attributes for unmatched devices
 * Update json object with attributes for a device that has not been matched to a Device Profile
 * \param [out] j reference to json object where the data will be stored
 * \param [in] time_interval constant unsigned int of 32 bits with the time interval between calling the REST API for DeviceStats
 * \param [in] force constant boolean whether only devices of unmatched devices that have last been modified
 * within the time_interval should be provided or data for any device should be stored in the json object
 * \param [in] detailed constant boolean whether the unexpired DNS queries performed by the host should be stored in the json object
 * \return boolean on whether data was stored in the json object
 */
bool Host::DeviceStats(json& j, const uint32_t time_interval, const bool force, const bool detailed) {
	if (not force && (isMatched() || LastModified < (time(nullptr) - time_interval))) {
		return false;
	}
	j["MacOid"] = Mac.str().substr(0,8);
	j["DhcpVendor"] = Dhcp.DhcpVendor;
	j["DhcpHostname"] = Dhcp.Hostname;
	j["SsdpFriendlyName"] = Ssdp.FriendlyName;
	j["SsdpManufacturer"] = Ssdp.Manufacturer;
	j["SsdpManufacturerUrl"] = Ssdp.ManufacturerUrl;
	j["SsdpModelName"] = Ssdp.ModelName;
	j["SsdpModelUrl"] = Ssdp.ModelUrl;
	j["SsdpDeviceType"] = Ssdp.DeviceType;
	j["SsdpSerialNumber"] = Ssdp.SerialNumber;
	j["SsdpUserAgent"] = Ssdp.UserAgent;
	j["SsdpServer"] = Ssdp.Server;
    j["WsDiscoveryXaddrs"] = Wsd.wsdXAddrs;
    j["WsDiscoveryTypes"] = Wsd.wsdTypes;
    j["MdnsHostname"] = Mdns.Hostname;
    j["MdnsOs"] = Mdns.Os;
    j["MdnsHw"] = Mdns.Hw;
    j["MdnsDeviceUrl"] = Mdns.DeviceUrl;
    j["MdnsManufacturer"] = Mdns.Manufacturer;
    j["MdnsModelName"] = Mdns.ModelName;

    // We don't want to upload any IP addresses, even if they are RFC1918 so we replace them with 'a.b.c.d'
    if (Ssdp.Location != "" || Mdns.DeviceUrl != "") {
        std::regex location_rx = std::regex(R"delim((https?://)\d+\.\d+\.\d+\.\d+(.*)$)delim",
                std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
        std::string location = Ssdp.Location;
        // Anonimize the SSDP Location parameter as we don't want to upload detailed information
        // about home networks
        if (Ssdp.Location != "") {
            std::smatch m;
            std::regex_search(Ssdp.Location, m, location_rx);
            if (not m.empty()) {
                location = m.str(1) + "a.b.c.d" + m.str(2);
            }
        }
        j["SsdpLocation"] = location;

        // Anonimize the MDNS DeviceUrl parameter as we don't want to upload detailed information
        // about home networks
        location = Mdns.DeviceUrl;
        if (Mdns.DeviceUrl != "") {
            std::smatch m;
            std::regex_search(Mdns.DeviceUrl, m, location_rx);
            if (not m.empty()) {
                location = m.str(1) + "a.b.c.d" + m.str(2);
            }
        }
        j["MdnsDeviceUrl"] = location;
    }

	std::string fqdns = "";
	DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Adding items from DnsQueryList to list of fqdns";
	for (auto &dq: DnsQueryList) {
		if (detailed == true) {
		    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Adding FQDN " << dq.first
		            << " from DnsQueryList to list of fqdns";
			fqdns += dq.first + " ";
		}
	}

	if (detailed == true && not fqdns.empty()) {
		j["DnsQueries"] = fqdns;
    }

	return true;
}

/*! \brief Store traffic statistics for a host in a json object
 * Store all the traffic destination of the host in a json object if the host has been matched to a Device Profile. The
 * destination IP could be reverse resolved to an FQDN, the FQDN is stored instead of the IP address.
 * \param [out] j Json object to store traffic statistics
 * \param [in] interval constant unsigned int of 32 bits of the interval between reports. Hosts that have not been modified
 * in this interval will not be reported unless the 'Force' parameter is true
 * \param [in] ReportPrivateAddresses constant bool whether traffic destinations to RFC1918 IPv4 and equivalent IPv6 addresses should be reported on
 * \param [in] LocalIps constant set of strings with local IP addresses (not used anywhere?!?)
 * \param [in] dCipv4 constant DnsCache of IPv4 addresses to which the host has sent traffic
 * \param [in] dCipv6 constant DnsCache of IPv6 addresses to which the host has sent traffic
 * \param [in] dCcname constant DnsCache of FQDNs that the host has performed DNS lookups for that resulted in a CNAME record
 * \param [in] Force boolean constant boolean whether the matched host should always be reported on, regardless or whether traffic
 * for the host has been seen since the last report interval
 */
bool Host::TrafficStats(json& j, const uint32_t report_interval, const bool ReportPrivateAddresses, const std::set<std::string> &LocalIps,
		const DnsCache <Tins::IPv4Address> &dCipv4, const DnsCache <Tins::IPv6Address> &dCipv6,
		const DnsCache <std::string> &dCcname, const bool Force) {
	// We only report traffic for hosts that have been matched to a Device Profile
    if (not isMatched()) {
		return false;
	}
	if (not Force && LastSeen < (time(nullptr) - report_interval)) {
		return false;
	}

	// List of endpoints (fqdns & IPv4/v6's) that the host communicated with
	std::unordered_set<std::string> endpoints;
	{
	    std::unordered_set<Tins::IPv4Address> allIps;
	    for (auto &fc: FlowCacheIpv4) {
	        Tins::IPv4Address  ip(fc.first);

	        if (ReportPrivateAddresses == false && ip.is_private()) {
	            continue;
	        }
	        // Did we already process a FlowCache entry with the same destination,
	        // ie. with different destination port?
	        if (allIps.find(ip) != allIps.end()) {
	            continue;
	        }

	        // Here it gets a bit challenging. We want to see if the host has performed a DNS lookup for an FQDN
	        // that resolved in the IP address that it has a traffic flow with. But many FQDNs can have an A
	        // record to the same IP address and perhaps there are FQDNS that have CNAMEs that have the A record
	        // pointing to the IP address. So we want to get a list of all FQDNs in our cache that point to the
	        // IP address and then we want to see for which of these FQDNs the host has actually performed a DNS
	        // lookup for. We only want to report that / those FQDNs as traffic destinations for the host
            DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Getting all DNS lookups for " << ip;
            std::vector<std::string> fqdns = dCipv4.getAllFqdns(ip);
            DLOG_IF(INFO, Debug) << "The DNS A record cache has " << fqdns.size() << " A records for " << ip;
	        std::set<std::string> allFqdns;
	        allFqdns.insert (fqdns.begin(), fqdns.end());

	        for (auto itf : fqdns) {
	            std::set<std::string> cname_fqdns = dCcname.getFqdns(itf);
	            DLOG_IF(INFO, Debug) << "The DNS CNAME cache has " << cname_fqdns.size() << " CNAME records for " << itf;
	            allFqdns.insert(cname_fqdns.begin(), cname_fqdns.end());
	        }
            bool foundDestination = false;
	        for (auto fqdn: allFqdns) {
	            if (inDnsQueryList(fqdn)) {
	                DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): performed a DNS lookup for " << fqdn;
	                endpoints.insert(fqdn);
	                foundDestination = true;
	            } else {
                    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): did not perform a DNS lookup for " << fqdn;
	            }
	        }
            if (foundDestination == false) {
                DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): No destination found for " << ip;
                endpoints.insert(ip.to_string());
            }
            allIps.insert(ip);
	    }
	}
    {
        std::unordered_set<Tins::IPv6Address> allIps;
        for (auto &fc: FlowCacheIpv6) {
            Tins::IPv6Address  ip(fc.first);

            // BUG: implement test on IPv6 ULA address.
            // if (ReportPrivateAddresses == false && ip.is_private()) {
            //    continue;
            // }
            // Did we already process a FlowCache entry with the same destination,
            // ie. with different destination port?
            if (allIps.find(ip) != allIps.end()) {
                continue;
            }

            // Here it gets a bit challenging. We want to see if the host has performed a DNS lookup for an FQDN
            // that resolved in the IP address that it has a traffic flow with. But many FQDNs can have an A
            // record to the same IP address and perhaps there are FQDNS that have CNAMEs that have the A record
            // pointing to the IP address. So we want to get a list of all FQDNs in our cache that point to the
            // IP address and then we want to see for which of these FQDNs the host has actually performed a DNS
            // lookup for. We only want to report that / those FQDNs as traffic destinations for the host
            DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Getting all DNS lookups for " << ip;
            std::vector<std::string> fqdns = dCipv6.getAllFqdns(ip);
            DLOG_IF(INFO, Debug) << "The DNS A record cache has " << fqdns.size() << " A records for " << ip;
            std::set<std::string> allFqdns;
            allFqdns.insert (fqdns.begin(), fqdns.end());

            for (auto itf : fqdns) {
                std::set<std::string> cname_fqdns = dCcname.getFqdns(itf);
                DLOG_IF(INFO, Debug) << "The DNS CNAME cache has " << cname_fqdns.size() << " CNAME records for " << itf;
                allFqdns.insert(cname_fqdns.begin(), cname_fqdns.end());
            }
            bool foundDestination = false;
            for (auto fqdn: allFqdns) {
                if (inDnsQueryList(fqdn)) {
                    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): performed a DNS lookup for " << fqdn;
                    endpoints.insert(fqdn);
                    foundDestination = true;
                } else {
                    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): did not perform a DNS lookup for " << fqdn;
                }
            }
            if (foundDestination == false) {
                DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): No destination found for " << ip;
                endpoints.insert(ip.to_string());
            }
            allIps.insert(ip);
        }
    }
	if (endpoints.size() > 0) {
		j = { {"DeviceProfileUuid", Uuid } };
		j["TrafficStats"] = endpoints;
		return true;
	}
	return false;
}

/*! \brief Write data collected on host to a json object
 *  \param [out] j reference to json object
 *  \param [in] detailed bool on whether to write detailed data or just the basics
 */
void Host::ExportDeviceInfo (json &j, const bool detailed) {
	json h{{"MacAddress", Mac.str()},
			{"DeviceProfileUuid", Uuid},
			{"Ipv4Address", Ipv4Address},
			{"Ipv6Address", Ipv6Address},
			{"SsdpManufacturer", Ssdp.Manufacturer},
			{"SsdpModelName", Ssdp.ModelName}
	};
	if (detailed) {
		DeviceStats(h, 604800, true, true);
	}
	j.push_back(h);
}

/*! \brief create or update a Flow for the host
 *  Adds or updates the list of flows from the host to a remote host
 *  \param [in] inSrcPort constant unsigned integer of 16 bits with the source port of the flow
 *  \param [in] inDstIp constant string with the destination IP address of the flow
 *  \param [in] inDstPort constant unsigned integer of 16 bits with the destination port of the flow
 *  \param [in] inProtocol constant unsigned integer of 8 bits with the protocol of the flow (ie UDP=6, TCP=17)
 *  \param [in] inTtl constant unsigned integer of 32 bits with the time to live in seconds of the flow
 *  \return boolean whether a flow was added
 */
bool Host::setFlowEntry(const uint16_t inSrcPort, const std::string inDstIp,
			const uint16_t inDstPort, const uint8_t inProtocol, const uint32_t inTtl) {
	iCache::LastSeen = time(nullptr);
	setExpiration();
	if (inDstIp == "239.255.255.250") {
	    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Ignoring flow to 239.255.255.0";
		return false;
	}
	auto f = std::make_shared<FlowEntry>();
	DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Creating new Flow Entry for src port " <<
	        inSrcPort << ", dest ip " << inDstIp << ", dest port " << inDstPort << ", protocol " << inProtocol;
	iCache::LastModified = time(nullptr);
	f->SrcPort = inSrcPort;
	f->DstPort = inDstPort;
	f->Protocol = inProtocol;
	f->setExpiration(inTtl);

	try {
		Tins::IPv4Address dstIpv4Address(inDstIp);

		if (FlowCacheIpv4.find(dstIpv4Address) == FlowCacheIpv4.end()) {
			FlowCacheIpv4[dstIpv4Address] = std::make_shared<FlowEntryList>();
			FlowCacheIpv4[dstIpv4Address]->push_back(f);
			DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Adding to IPv4 FlowCache with destination "
			        << inDstIp << " : " << inDstPort << " Protocol " << inProtocol;
			return true;
		}
		// Create or update existing flow to destination IP
		for(FlowEntryList::iterator existingflow = FlowCacheIpv4[dstIpv4Address]->begin();
				existingflow != FlowCacheIpv4[dstIpv4Address]->end(); ++existingflow) {
			// Update existing flow it it matches incoming flow (ignoring Expiration)
			if (**existingflow == *f) {
			    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address <<
			            "): Updating expiration of existing FlowEntry in IPv4 FlowCache for destination " << inDstIp;
				(*existingflow)->setExpiration(inTtl);
				return false;
			}
		}
		// This flow doesn't match any of the existing flows
		DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Adding FlowEntry to IPv4 FlowCache for destination " << inDstIp;
		FlowCacheIpv4[dstIpv4Address]->push_back(f);
		return true;
	} catch (...) {
		try {
		    Tins::IPv6Address dstIpv6Address(inDstIp);

		    if (FlowCacheIpv6.find(dstIpv6Address) == FlowCacheIpv6.end()) {
		        FlowCacheIpv6[dstIpv6Address] = std::make_shared<FlowEntryList>();
		        FlowCacheIpv6[dstIpv6Address]->push_back(f);
		        DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Adding to IPv6 FlowCache with destination " << inDstIp <<
		                ": " << inDstPort << " Protocol " << inProtocol;
		        return true;
		    }
		    // Create or update existing flow to destination IP
		    for(FlowEntryList::iterator existingflow = FlowCacheIpv6[dstIpv6Address]->begin();
		            existingflow != FlowCacheIpv6[dstIpv6Address]->end(); ++existingflow) {
		        // Update existing flow it it matches incoming flow (ignoring Expiration)
		        if (**existingflow == *f) {
		            DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address <<
		                    "): Updating expiration of existing FlowEntry in IPv6 FlowCache for destination " << inDstIp;
		            (*existingflow)->setExpiration(inTtl);
		            return false;
		        }
		    }
		    // This flow doesn't match any of the existing flows
		    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Adding FlowEntry to IPv6 FlowCache for destination " << inDstIp;
		    FlowCacheIpv6[dstIpv6Address]->push_back(f);
		    return true;
        } catch (...) {
            LOG(WARNING) << "Host(" << Ipv4Address << "): IP address " << inDstIp << " is neither v4 or v6";
        }
	}
	return false;
}

/*! \brief Set the DHCP values for the host
 * \param [in] inIpAddress constant string with the IP address of the host
 * \param [in] inMac constant MacAddress object
 * \param [in] inHostname constant string with the hostname for the host
 * \param [in] inDhcpVendor constant string with the value of the Vendor field in the DHCP packet
 * \retun bool on whether DHCP information for the host was set
 */
bool Host::setDhcp (const std::string inIpAddress, const MacAddress inMac, const std::string inHostname, const std::string inDhcpVendor) {
    if (not inMac.isValid()) {
            return false;
    }
    iCache::LastSeen = time(nullptr);
    setExpiration();
    bool modified = false;
    if (Mac != Dhcp.Mac) {
        Dhcp.Mac = Mac;
        modified = true;
    }
    // We only set the IP addres if the DHCP packet contains a real IP address
    if (inIpAddress != "" && inIpAddress != "0.0.0.0" && Dhcp.IpAddress != inIpAddress) {
        Dhcp.IpAddress = inIpAddress;
        modified = true;
    }
	if (inHostname != "" && Dhcp.Hostname != inHostname) {
	    Dhcp.Hostname = inHostname;
        modified = true;
	}
	if (inDhcpVendor != "" && Dhcp.DhcpVendor != inDhcpVendor) {
	    Dhcp.DhcpVendor = inDhcpVendor;
        modified = true;
	}
	if (modified == true) {
        iCache::LastModified = time(nullptr);
        DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Creating DHCP data for " << Dhcp.Mac <<
                " with expiration " << Dhcp.getExpiration() << " with ipaddress " << Dhcp.IpAddress <<
                ", hostname " << Dhcp.Hostname << ", vendor " << Dhcp.DhcpVendor;
        return true;
    }
	return false;
}

/*! \brief Set SSDP info of a host
 *  \param [in] insHost constant shared pointer to a SsdpHost object
 *  \return boolean on whether information was modified
 */
bool Host::setSsdpInfo(const std::shared_ptr<SsdpHost> insHost) {
	iCache::LastSeen = time(nullptr);
	setExpiration();
	if (Ssdp == *insHost) {
	    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): not setting Ssdp info as same info is already known";
        return false;
	}
	bool modifiedLocation = false;
	if (insHost->Location != Ssdp.Location && insHost->Location != "") {
	    modifiedLocation = true;
	}
	iCache::LastModified = iCache::LastSeen;
	Ssdp = *insHost;
	DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): SSDP info has been set";

	// Information in the SSDP multicast message has changed so if the Location field contains a URL, we query it
	if (modifiedLocation) {
		auto resp = SsdpLocation::Get(Ssdp);
	}
	return true;
}

/*! \brief Set WsDiscovery info of a host
 *  \param [in] inwsdHost constant shared pointer to a WsDiscoveryHost object
 *  \return bool on whether info was modified
 */

bool Host::setWsDiscoveryInfo(const std::shared_ptr<WsDiscoveryHost> inwsdHost) {
    iCache::LastSeen = time(nullptr);
    setExpiration();
    if (Wsd == *inwsdHost) {
        DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): not setting WS-Discovery info as same info is already known";
        return false;
    }
    iCache::LastModified = iCache::LastSeen;
    Wsd = *inwsdHost;
    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): WS-Discovery info has been set";
    return true;
}

/*! \brief Set MDNS info of a host
 *  \param [in] inmdnsHost constant shared pointer to a MdnsHost object
 *  \return bool on whether info was modified
 */
bool Host::setMdnsInfo(const std::shared_ptr<MdnsHost> inmdnsHost) {
    iCache::LastSeen = time(nullptr);
    setExpiration();
    if (Mdns == *inmdnsHost) {
        DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): not setting mDNS info as same info is already known";
        return false;
    }
    iCache::LastModified = iCache::LastSeen;
    Mdns = *inmdnsHost;
    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): mDNS info has been set";
    return true;
}

/*! \brief Prune information of the host
 *  \param [in] Force bool on whether all information should be pruned (true) or just the expired information (false)
 *  \return unsigned integer of 32 bits with the number of flows to a destination host pruned
 */
uint32_t Host::Prune (const bool Force) {
	bool pruned = false;
	DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Pruning host " << Mac;
	pruneDnsQueryList(Force);


	uint32_t pruned_flowentries = 0;
	uint32_t pruned_flows = 0;
	// FlowCache is a map, so iterate over it
	{
		auto fc = FlowCacheIpv4.begin();
		while (fc != FlowCacheIpv4.end()) {
			// fc is an iterator to pair{std::string,shared_ptr<FlowEntryList>}
			// fc.second a shared_ptr<FlowEntryList>
			// *(fc.second) is a FlowEntryList
			// fel is a reference to FlowEntryList
			auto & fel = *(fc->second);
			// FlowEntryList is std::list<std::shared_ptr<FlowEntry>>
			auto it = fel.begin();
			while (it != fel.end()) {
				if (Force || (*it)->isExpired()) {
				    std::string dstIp = (fc->first).to_string();
				    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Pruning IPv4 FlowEntry to " << fc->first <<
				            "for DstPort " << (*it)->DstPort << " with expiration " <<  (*it)->getExpiration() <<
				            "while now is " << time(nullptr);
					// Remove element from list
					it = fel.erase(it);
					pruned_flowentries++;
					pruned = true;
				} else {
					++it;
				}
			}
			// If the list of Flow Entry pointers is empty, delete it
			if (Force || fel.empty()) {
			    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Pruning FlowEntryList for " << fc->first <<
			            " as it is now empty";
				fc = FlowCacheIpv4.erase(fc);
				pruned = true;
				pruned_flows++;
			} else {
				++fc;
			}
		}
	}
	{
		auto fc = FlowCacheIpv6.begin();
		while (fc != FlowCacheIpv6.end()) {
			// fc is an iterator to pair{std::string,shared_ptr<FlowEntryList>}
			// fc.second a shared_ptr<FlowEntryList>
			// *(fc.second) is a FlowEntryList
			// fel is a reference to FlowEntryList
			auto & fel = *(fc->second);
			// FlowEntryList is std::list<std::shared_ptr<FlowEntry>>
			auto it = fel.begin();
			while (it != fel.end()) {
				if (Force || (*it)->isExpired()) {
				    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Pruning IPv6 FlowEntry to " << fc->first <<
				            " for DstPort " << (*it)->DstPort << " with expiration " << (*it)->getExpiration() <<
				            " while now is " << time(nullptr);
					// Remove element from list
					it = fel.erase(it);
					pruned_flowentries++;
					pruned = true;
				} else {
					++it;
				}
			}
			// If the list of Flow Entry pointers is empty, delete it
			if (Force || fel.empty()) {
			    DLOG_IF(INFO, Debug) <<"Host(" << Ipv4Address << "): Pruning FlowEntryList for " << fc->first << " as it is now empty",
				fc = FlowCacheIpv6.erase(fc);
				pruned = true;
				pruned_flows++;
			} else {
				++fc;
			}
		}
		DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Pruned " << pruned_flowentries << " Flow Entries and " <<
		        pruned_flows << " flows";
	}
	return pruned_flows;
}

/*! \brief Prune the DNS Query list
 *  \param [in] Force constant boolean on whether all DNS queries should be pruned (true) or only expired DNS queries (false)
 *  \return unsigned integer of 32 bits with the number of DNS queries pruned
 */
uint32_t Host::pruneDnsQueryList (const bool Force) {
	uint32_t deletecount;
	time_t now = time(nullptr);
	auto i = DnsQueryList.begin();
	while (i != DnsQueryList.end()) {
		if (Force || i->second <= now) {
		    DLOG_IF(INFO, Debug) << "Host(" << Ipv4Address << "): Deleting " << i->first << " from DnsQueryList as " <<
		            i->second << " is earlier than " << now;
			i = DnsQueryList.erase(i);
			deletecount++;
		} else {
			++i;
		}
	}
	return deletecount;
}


