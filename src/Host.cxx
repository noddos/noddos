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
#include <forward_list>
#include <map>
#include <unordered_set>
#include <vector>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <syslog.h>



#include <json.hpp>
using json = nlohmann::json;
#include "Host.h"
#include "DhcpRequest.h"
#include "SsdpLocation.h"
#include "FlowEntry.h"
#include "SsdpHost.h"
#include "DeviceProfile.h"

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
	for (auto &kv : dpMap) {
		if(Debug) {
			syslog(LOG_DEBUG, "Evaluating host %s against device profile %s", Mac.c_str(), kv.first.c_str());
		}
		auto &dp = *(kv.second);
		auto match = Match(dp);
		if (match > bestmatch) {
			UploadStats = kv.second->getUploadStats();
			bestmatch = match;
			matcheduuid = kv.first;
			matchversion = time(nullptr);
		}

	}
	if (bestmatch >= ConfidenceLevel::Low) {
		Uuid = matcheduuid;
		syslog(LOG_DEBUG, "Host %s matched %s", Mac.c_str(), Uuid.c_str());
		return true;
	}
	return false;
}

ConfidenceLevel Host::Match(const DeviceProfile& dp) {
	ConfidenceLevel bestmatch = ConfidenceLevel::None;
	auto v = dp.getIdentifiers();
	for (auto& i : v) {
		if(Debug) {
			syslog (LOG_DEBUG, "Testing identifier");
		}
		auto match = Match(*i);
		if (match >= ConfidenceLevel::High) {
			if(Debug) {
				syslog(LOG_DEBUG, "Host %s matched with high confidence", Mac.c_str());
			}
			return match;
        }
		if 	(match > bestmatch) {
			bestmatch = match;
        }
	}
	if(Debug) {
		syslog(LOG_DEBUG, "Host %s match level %d", Mac.c_str(), static_cast<int>(bestmatch));
	}
	return bestmatch;
}

ConfidenceLevel Host::Match(const Identifier& i) {
	for (auto& mc : i.MatchConditions_get()) {
		if(Debug) {
			syslog (LOG_DEBUG, "Testing match condition %s", (*mc).Key.c_str());
		}
		if(not Match (*mc)) {
			if(Debug) {
				syslog (LOG_DEBUG, "Host %s did not match condition %s", Mac.c_str(), (*mc).Key.c_str());
			}
			return ConfidenceLevel::None;
		}
	}
	for (auto& cc : i.ContainConditions_get()) {
		if(Debug) {
			syslog (LOG_DEBUG, "Testing contain condition %s", (*cc).Key.c_str());
		}
		if(not Match (*cc)) {
			if(Debug) {
				syslog (LOG_DEBUG, "Host %s did not contain condition %s", Mac.c_str(), (*cc).Key.c_str());
			}
			return ConfidenceLevel::None;
		}
	}
	if(Debug) {
		syslog(LOG_DEBUG, "Host %s matched MustMatch and/or MustContain conditions", Mac.c_str());
	}
	return i.IdentifyConfidenceLevel_get();
}

bool Host::Match(const MatchCondition& mc) {
	std::string value;
	if (mc.Key == "MacOid") {
		value = Mac.str().substr(0,8);
	} else if (mc.Key == "DhcpVendor") {
		value = Dhcp.DhcpVendor;
	} else if (mc.Key == "Hostname") {
		value = Dhcp.Hostname ;
	} else if (mc.Key == "SsdpFriendlyName" ) {
		value = Ssdp.FriendlyName;
	} else if (mc.Key == "SsdpManufacturer") {
		value = Ssdp.Manufacturer;
	} else if (mc.Key == "SsdpManufacturerUrl") {
		value = Ssdp.ManufacturerUrl;
	} else if (mc.Key == "SsdpModelName") {
		value = Ssdp.ModelName;
	} else if (mc.Key == "SsdpModelUrl") {
		value = Ssdp.ModelUrl;
	} else if (mc.Key == "SsdpSerialNumber") {
		value = Ssdp.SerialNumber;
	} else if (mc.Key == "SsdpUserAgent") {
		value = Ssdp.UserAgent;
	} else if (mc.Key == "SsdpServer") {
		value = Ssdp.Server;
	} else if (mc.Key == "SsdpLocation") {
		value = Ssdp.Location;
	}
	if (value == "") {
		if(Debug) {
			syslog(LOG_DEBUG, "Host %s has no value for MustMatch condition %s", Mac.c_str(), mc.Key.c_str());
		}
	}
	size_t startpos = 0;
	size_t mcvaluelength = mc.Value.length();
	size_t datavaluelength = value.length();
	std::string mcvalue = mc.Value;
	if (mc.Key[0] == '*') {
		mcvalue = mcvalue.substr(1);
		startpos = datavaluelength - mcvalue.length();
	} else if (mc.Value[mcvaluelength-1] == '*') {
		mcvalue = mcvalue.substr(0,mcvaluelength-1);
		startpos = 0;
	}
	if (value.compare(startpos, mcvalue.length() - startpos, mcvalue) == 0) {
		if(Debug) {
			syslog(LOG_DEBUG, "Host %s matched MustMatch condition", Mac.c_str());
		}
		return true;
    }
	if(Debug) {
		syslog (LOG_DEBUG, "Host %s did not match condition %s with value %s from position %zu", value.c_str(), mc.Key.c_str(), mcvalue.c_str(), startpos);
	}
	return false;
}

bool Host::Match(const ContainCondition& cc) {
	if(cc.Key == "DnsQueries") {
		for (auto fqdn: cc.Values) {
		    if (DnsQueryList.find(fqdn) != DnsQueryList.end()) {
				if(Debug) {
					syslog(LOG_DEBUG, "Found DnsQuery for %s from host %s", fqdn.c_str(), Mac.c_str());
				}
			} else {
				if(Debug) {
					syslog(LOG_DEBUG, "Didn't find DnsQuery for %s from host %s", fqdn.c_str(), Mac.c_str());
				}
				return false;
			}
		}
	} else {
		if(Debug) {
			syslog(LOG_DEBUG, "Unsupported MustContain key %s", cc.Key.c_str());
		}
		return false;
	}
	if(Debug) {
		syslog(LOG_DEBUG, "Host %s matched MustContain condition", Mac.c_str());
	}
	return true;
}

bool Host::DeviceStats(json& j, const uint32_t time_interval, bool force, bool detailed) {
	// Don't report info if device has been matched
	// or if device hasn't been modified since last reporting run
	if (not force && (isMatched() || LastModified < (time(nullptr) - time_interval))) {
		return false;
	}
	j["MacOid"] = Mac.str().substr(0,8);
	j["DhcpVendor"] = Dhcp.DhcpVendor;
	j["Hostname"] = Dhcp.Hostname;
	j["SsdpFriendlyName"] = Ssdp.FriendlyName;
	j["SsdpManufacturer"] = Ssdp.Manufacturer;
	j["SsdpManufacturerUrl"] = Ssdp.ManufacturerUrl;
	j["SsdpModelName"] = Ssdp.ModelName;
	j["SsdpModelUrl"] = Ssdp.ModelUrl;
	j["SsdpSerialNumber"] = Ssdp.SerialNumber;
	j["SsdpUserAgent"] = Ssdp.UserAgent;
	j["SsdpServer"] = Ssdp.Server;
	j["SsdpLocation"] = Ssdp.Location;

	std::string fqdns = "";
	if (Debug == true) {
		syslog (LOG_DEBUG, "Adding items from DnsQueryList to list of fqdns");
	}
	for (auto &dq: DnsQueryList) {
		if (detailed == false) {
			if (Debug == true) {
				syslog (LOG_DEBUG, "Adding FQDN %s from DnsQueryList to list of fqdns", dq.first.c_str());
			}
			fqdns += dq.first + " ";
		}
	}

	if (detailed == false && not fqdns.empty()) {
		j["DnsQueries"] = fqdns;
    }

	return true;
}

bool Host::TrafficStats(json& j, const uint32_t interval, const bool ReportPrivateAddresses, const std::unordered_set<std::string> &LocalIps,
		const DnsIpCache <boost::asio::ip::address> &dCip, const DnsCnameCache &dCcname, bool force) {
	if (not isMatched()) {
		return false;
	}
	if (not force && LastSeen < (time(nullptr) - interval)) {
		return false;
	}
	// This holds reverse lookup table from an IP address to one or more FQDNs.
	std::map<std::string,std::shared_ptr<std::unordered_set<std::string>>> allIps;

	std::unordered_set<std::string> endpoints;
	for (auto &fc: FlowCacheIpv4) {
		const boost::asio::ip::address_v4  &ip = fc.first;
		if (ReportPrivateAddresses || not inPrivateAddressRange(ip.to_string())) {
			auto it = allIps.find(ip.to_string());
			if (it != allIps.end()) {
				for (auto &fqdn: *(it->second)) {
					endpoints.insert(fqdn);
				}
			}
			if (Debug == true) {
				syslog (LOG_DEBUG, "Getting all DNS lookups for %s", ip.to_string().c_str());
			}
			std::vector<std::string> fqdns = dCip.getAllFqdns(ip);
			for (auto &itf : fqdns) {
				std::string fqdn = dCcname.getFqdn(itf);
                if (Debug) {
                    syslog (LOG_DEBUG, "Reverse resolved %s to %s, might have CNAME %s", ip.to_string().c_str(), itf.c_str(), fqdn.c_str());
                }
				if (inDnsQueryList(fqdn)) {
				    endpoints.insert(fqdn);
				}
			}
			if (endpoints.size() == 0) {
				endpoints.insert(ip.to_string());
			}
		}
	}

	if (endpoints.size() > 0) {
		j = { {"DeviceProfileUuid", Uuid } };
		j["TrafficStats"] = endpoints;
		return true;
	}
	return false;
}

bool Host::inPrivateAddressRange(const std::string inIp ) {
	if (inIp.find(':') != std::string::npos) {
		// IPv6 address
		std::string ip = inIp;
		std::transform(ip.begin(), ip.end(), ip.begin(), ::tolower);
		return ip.substr(0,2) == "fd";
	}
	// IPv4 Address
	uint32_t Rfc1918_10start = ntohl(10);
	uint32_t Rfc1918_10end = ntohl(4294967050);
	uint32_t Rfc1918_172start = ntohl(4268);
	uint32_t Rfc1918_172end = ntohl(4294907820);
	uint32_t Rfc1918_192start = ntohl(43200);
	uint32_t Rfc1918_192end = ntohl(4294944960);
	struct sockaddr_in sa;
	char str[INET_ADDRSTRLEN];
	inet_pton(AF_INET, inIp.c_str(), &(sa.sin_addr));
	uint32_t ip_int = ntohl(sa.sin_addr.s_addr);

	return
		(Rfc1918_10start <= ip_int && ip_int <= Rfc1918_10end) ||
		(Rfc1918_172start <= ip_int && ip_int <= Rfc1918_172end) ||
		(Rfc1918_192start <= ip_int && ip_int <= Rfc1918_192end);
}

void Host::ExportDeviceInfo (json &j, bool detailed) {
	json h{{"MacAddress", Mac.str()},
			{"DeviceProfileUuid", Uuid},
			{"Ipv4Address", Ipv4Address},
			{"SsdpManufacturer", Ssdp.Manufacturer},
			{"SsdpModelName", Ssdp.ModelName}
	};
	if (detailed) {
		DeviceStats(h, 604800, true);
	}
	j.push_back(h);
}

/*
 *  Host::FlowEntry_set
 *  Adds or updates the list of flows from a host to a remote host
 *  Returns true if flow was added, false if existing flow was updated
 */
bool Host::FlowEntry_set(const uint16_t inSrcPort, const std::string inDstIp,
			const uint16_t inDstPort, const uint8_t inProtocol, const uint32_t inExpiration) {
	iCache::LastSeen = time(nullptr);
	if (inDstIp == "239.255.255.250") {
		if(Debug) {
			syslog(LOG_DEBUG, "Ignoring flow to 239.255.255.0");
		}
		return false;
	}
	auto f = std::make_shared<FlowEntry>();
	if(Debug) {
		syslog(LOG_DEBUG, "Creating new Flow Entry for src port %u, dest ip %s, dest port %u, protocol %u", inSrcPort,
				inDstIp.c_str(), inDstPort, inProtocol);
	}
	iCache::LastModified = time(nullptr);
	f->SrcPort = inSrcPort;
	f->DstPort = inDstPort;
	f->Protocol = inProtocol;
	f->setExpiration(inExpiration);

	boost::asio::ip::address dstIpAddress = boost::asio::ip::address::from_string(inDstIp);

	// Is there already at least one flow from the Host to the destination IP?
	if (dstIpAddress.is_v4()) {
		boost::asio::ip::address_v4 dstIpv4Address = dstIpAddress.to_v4();

		if (FlowCacheIpv4.find(dstIpv4Address) == FlowCacheIpv4.end()) {
			FlowCacheIpv4[dstIpv4Address] = std::make_shared<FlowEntryList>();
			FlowCacheIpv4[dstIpv4Address]->push_back(f);
			if(Debug) {
				syslog(LOG_DEBUG, "Adding to IPv4 FlowCache with destination %s : %u Protocol %u", inDstIp.c_str(),
					inDstPort, inProtocol);
			}
			return true;
		}
		// Create or update existing flow to destination IP
		for(FlowEntryList::iterator existingflow = FlowCacheIpv4[dstIpv4Address]->begin();
				existingflow != FlowCacheIpv4[dstIpv4Address]->end(); ++existingflow) {
			// Update existing flow it it matches incoming flow (ignoring Expiration)
			if (**existingflow == *f) {
				if(Debug) {
					syslog(LOG_DEBUG, "Updating expiration of existing FlowEntry in IPv4 FlowCache for destination %s",
						inDstIp.c_str());
				}
				(*existingflow)->setExpiration(inExpiration);
				return false;
			}
		}
		// This flow doesn't match any of the existing flows
		if(Debug) {
			syslog(LOG_DEBUG, "Adding FlowEntry to IPv4 FlowCache for destination %s", inDstIp.c_str());
		}
		FlowCacheIpv4[dstIpv4Address]->push_back(f);
		return true;
	} else if (dstIpAddress.is_v6()) {
		boost::asio::ip::address_v6 dstIpv6Address = dstIpAddress.to_v6();

		if (FlowCacheIpv6.find(dstIpv6Address) == FlowCacheIpv6.end()) {
			FlowCacheIpv6[dstIpv6Address] = std::make_shared<FlowEntryList>();
			FlowCacheIpv6[dstIpv6Address]->push_back(f);
			if(Debug) {
				syslog(LOG_DEBUG, "Adding to IPv6 FlowCache with destination %s : %u Protocol %u", inDstIp.c_str(),
					inDstPort, inProtocol);
			}
			return true;
		}
		// Create or update existing flow to destination IP
		for(FlowEntryList::iterator existingflow = FlowCacheIpv6[dstIpv6Address]->begin();
				existingflow != FlowCacheIpv6[dstIpv6Address]->end(); ++existingflow) {
			// Update existing flow it it matches incoming flow (ignoring Expiration)
			if (**existingflow == *f) {
				if(Debug) {
					syslog(LOG_DEBUG, "Updating expiration of existing FlowEntry in IPv6 FlowCache for destination %s",
						inDstIp.c_str());
				}
				(*existingflow)->setExpiration(inExpiration);
				return false;
			}
		}
		// This flow doesn't match any of the existing flows
		if(Debug) {
			syslog(LOG_DEBUG, "Adding FlowEntry to IPv6 FlowCache for destination %s", inDstIp.c_str());
		}
		FlowCacheIpv6[dstIpv6Address]->push_back(f);
		return true;
	}
	syslog(LOG_NOTICE, "IP address %s is neither v4 or v6", inDstIp.c_str());
	return false;
}

bool Host::Dhcp_set (const std::string inIpAddress, const MacAddress inMac, const std::string inHostname, const std::string inDhcpVendor) {
    if (not inMac.isValid()) {
            return false;
    }
    Dhcp.Mac = Mac;
    if (inIpAddress != "" && inIpAddress != "0.0.0.0") {
        Dhcp.IpAddress = inIpAddress;
    }
	if (inHostname != "") {
	    Dhcp.Hostname = inHostname;
	}
	if (inDhcpVendor != "") {
	    Dhcp.DhcpVendor = inDhcpVendor;
	}

	iCache::FirstSeen = iCache::LastModified = iCache::LastSeen = time(nullptr);
	Dhcp.setExpiration();
	if(Debug) {
		syslog(LOG_DEBUG, "Creating DHCP data for %s with expiration %lu with ipaddress %s, hostname %s, vendor %s ",
		        Dhcp.Mac.c_str(), Dhcp.getExpiration(), Dhcp.IpAddress.c_str(), Dhcp.Hostname.c_str(), Dhcp.DhcpVendor.c_str());
	}
	return true;
}

bool Host::SsdpInfo_set(const std::shared_ptr<SsdpHost> insHost) {
	iCache::LastSeen = time(nullptr);
	if (Ssdp == *insHost) {
		return false;
	}

	iCache::LastModified = iCache::LastSeen;
	Ssdp = *insHost;

	// Information in the SSDP multicast message has changed so if the Location field contains a URL, we query it
	if (Ssdp.Location != "") {
		auto resp = SsdpLocation::Get(Ssdp);
	}
	return true;
}

bool Host::UploadsEnabled() {
	return UploadStats;
}

uint32_t Host::Prune (bool Force) {
	bool pruned = false;
	if(Debug) {
		syslog(LOG_DEBUG, "Pruning host %s", Mac.c_str());
	}
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
					if (Debug) {
						std::string dstIp = (fc->first).to_string();
						syslog(LOG_DEBUG, "Pruning IPv4 FlowEntry to %s for DstPort %u with expiration %ld while now is %ld",
								dstIp.c_str(), (*it)->DstPort, (*it)->getExpiration (), time(nullptr));
					}
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
				if (Debug) {
					syslog(LOG_DEBUG, "Pruning FlowEntryList for %s as it is now empty", fc->first.to_string().c_str());
				}
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
					if (Debug) {
						syslog(LOG_DEBUG, "Pruning IPv6 FlowEntry to %s for DstPort %u with expiration %ld while now is %ld",
								fc->first.to_string().c_str(), (*it)->DstPort, (*it)->getExpiration (), time(nullptr));
					}
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
				if (Debug) {
					syslog(LOG_DEBUG, "Pruning FlowEntryList for %s as it is now empty", fc->first.to_string().c_str());
				}
				fc = FlowCacheIpv6.erase(fc);
				pruned = true;
				pruned_flows++;
			} else {
				++fc;
			}
		}
		if(Debug) {
			syslog (LOG_DEBUG, "Pruned %u Flow Entries and %u flows", pruned_flowentries, pruned_flows);
		}
	}
	return pruned;
}

uint32_t Host::pruneDnsQueryList (time_t Expired, bool Force) {
	uint32_t deletecount;
	time_t now = time(nullptr);
	auto i = DnsQueryList.begin();
	while (i != DnsQueryList.end()) {
		if (Force || i->second > (now - Expired)) {
			if (Debug == true) {
				syslog (LOG_DEBUG, "Deleting %s from DnsQueryList as %lu is later than %lu", i->first.c_str(), i->second, now - Expired);
			}
			i = DnsQueryList.erase(i);
			deletecount++;
		} else {
			++i;
		}
	}
	return deletecount;
}


