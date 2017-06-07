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
 *      Author: steven
 */

#include <cstring>
#include <ctime>
#include <string>
#include <forward_list>
#include <map>
#include <unordered_set>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <syslog.h>


// #include <curl/curl.h>
// #include "log/Log.h"
#include <json.hpp>
using json = nlohmann::json;
#include "Host.h"
#include "DhcpRequest.h"
#include "SsdpLocation.h"
#include "FlowEntry.h"
#include "SsdpHost.h"
#include "DeviceProfile.h"

bool Host::Match(const DeviceProfileMap& dpMap) {
	// If already matched and time of match is more recent as last update in Device Profiles then keep
	// keep current match, accepting that there may be a better match available. I'm assuming that
	// matching will be expensive process on HGWs so if we really want to force certain devices to
	// re-match then update the LastUpdated value of the correspondign DeviceProfile
	if (isMatched()) {
		auto it = dpMap.find(Uuid);
		if (it != dpMap.end()) {
			if (matchtime > it->second->LastUpdated_get()) {
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
			UploadStats = kv.second->UploadStats_get();
			bestmatch = match;
			matcheduuid = kv.first;
			matchtime = time(nullptr);
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
	auto v = dp.Identifiers_get();
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
	} else if (mc.Key == "DhcpHostname") {
		value = Dhcp.DhcpHostname;
	} else if (mc.Key == "DhcpVendor") {
		value = Dhcp.DhcpVendor;
	} else if (mc.Key == "DhcpHostname") {
		value = Dhcp.DhcpHostname ;
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
			if (DnsHostCache.find(fqdn) != DnsHostCache.end()) {
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
	j["DhcpHostname"] = Dhcp.DhcpHostname;
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
	for (auto &dq: DnsHostCache) {
		if (detailed) {
			dq.second->DnsStats(j, time_interval);
		} else {
			fqdns += dq.second->Fqdn_get() + " ";
        }
	}
	if (not detailed && not fqdns.empty()) {
		j["DnsQueries"] = fqdns;
    }

	return true;
}

bool Host::TrafficStats(json& j, const uint32_t interval, const bool ReportPrivateAddresses, const std::unordered_set<std::string> &LocalIps, bool force) {
	if (not isMatched()) {
		return false;
	}
	if (not force && LastSeen < (time(nullptr) - interval)) {
		return false;
	}
	// This holds reverse lookup table from an IP address to one or more FQDNs.
	std::map<std::string,std::shared_ptr<std::unordered_set<std::string>>> allIps;
	for (auto &dq: DnsHostCache) {
		dq.second->Ips_get(allIps);
	}

	std::unordered_set<std::string> endpoints;
	for (auto &fc: FlowCacheIpv4) {
		boost::asio::ip::address ip = fc.first;
		if (ReportPrivateAddresses || not inPrivateAddressRange(ip.to_string())) {
			for (auto &fe : *(fc.second)) {
				if(fe->Fresh(interval)) {
					auto it = allIps.find(ip.to_string());
					if (it == allIps.end()) {
						endpoints.insert(ip.to_string());
					} else {
						for (auto &fqdn: *(it->second)) {
							endpoints.insert(fqdn);
						}
					}
				}
			}
		}
	}
	for (auto &fc: FlowCacheIpv6) {
		boost::asio::ip::address ip = fc.first;
		if (ReportPrivateAddresses || not inPrivateAddressRange(ip.to_string())) {
			for (auto &fe : *(fc.second)) {
				if(fe->Fresh(interval)) {
					auto it = allIps.find(ip.to_string());
					if (it == allIps.end()) {
						endpoints.insert(ip.to_string());
					} else {
						for (auto &fqdn: *(it->second)) {
							endpoints.insert(fqdn);
						}
					}
				}
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
	f->Expiration_set(inExpiration);

	boost::asio::ip::address dstIpAddress;
	dstIpAddress.from_string(inDstIp);

	// Is there already at least one flow from the Host to the destination IP?
	if (dstIpAddress.is_v4()) {
		boost::asio::ip::address_v4 dstIpv4Address = dstIpAddress.to_v4();

		if (FlowCacheIpv4.find(dstIpv4Address) == FlowCacheIpv4.end()) {
			FlowCacheIpv4[dstIpv4Address] = std::make_shared<FlowEntryList>();
			FlowCacheIpv4[dstIpv4Address]->push_back(f);
			if(Debug) {
				syslog(LOG_DEBUG, "Adding to FlowCache with destination %s : %u Protocol %u", inDstIp.c_str(),
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
					syslog(LOG_DEBUG, "Updating expiration of existing FlowEntry in FlowCache for destination %s",
						inDstIp.c_str());
				}
				(*existingflow)->Expiration_set(inExpiration);
				return false;
			}
		}
		// This flow doesn't match any of the existing flows
		if(Debug) {
			syslog(LOG_DEBUG, "Adding FlowEntry to FlowCache for destination %s", inDstIp.c_str());
		}
		FlowCacheIpv4[dstIpv4Address]->push_back(f);
		return true;
	} else if (dstIpAddress.is_v6()) {
		boost::asio::ip::address_v6 dstIpv6Address = dstIpAddress.to_v6();

		if (FlowCacheIpv6.find(dstIpv6Address) == FlowCacheIpv6.end()) {
			FlowCacheIpv6[dstIpv6Address] = std::make_shared<FlowEntryList>();
			FlowCacheIpv6[dstIpv6Address]->push_back(f);
			if(Debug) {
				syslog(LOG_DEBUG, "Adding to FlowCache with destination %s : %u Protocol %u", inDstIp.c_str(),
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
					syslog(LOG_DEBUG, "Updating expiration of existing FlowEntry in FlowCache for destination %s",
						inDstIp.c_str());
				}
				(*existingflow)->Expiration_set(inExpiration);
				return false;
			}
		}
		// This flow doesn't match any of the existing flows
		if(Debug) {
			syslog(LOG_DEBUG, "Adding FlowEntry to FlowCache for destination %s", inDstIp.c_str());
		}
		FlowCacheIpv6[dstIpv6Address]->push_back(f);
		return true;
	}
	syslog(LOG_NOTICE, "IP address %s is neither v4 or v6", inDstIp.c_str());
	return false;
}

// DELETE DNSMASQ
/*
 *  Host::DnsLogwEntry_set
 *  Adds or updates the list of dns log entries for lookups of a FQDN
 *  Returns true if a DnsLogEntry was added, false if existing DnsLogEntry was updated
 */
/*
bool Host::DnsLogEntry_set(const std::string inFqdn, const std::string inIpAddress, const uint32_t inExpiration) {
	iCache::LastSeen = iCache::LastModified = time(nullptr);
	bool newentry = false;
	if(DnsHostCache.find(inFqdn) == DnsHostCache.end()) {
		DnsHostCache[inFqdn] = std::make_shared<DnsLogEntry>(inFqdn);
		newentry = true;
		if(Debug) {
			syslog(LOG_DEBUG, "Creating DnsLogEntry for %s with expiration %lu", inFqdn.c_str(), DnsHostCache[inFqdn]->Expiration_get());
		}
	}

	DnsHostCache[inFqdn]->Ips_set(inIpAddress, inExpiration);
	return newentry;
}
*/

bool Host::Dhcp_set (const std::shared_ptr<DhcpRequest> inDhcp_sptr) {
	iCache::LastSeen = time(nullptr);
	if (Dhcp == *(inDhcp_sptr)) {
		return false;
    }
	iCache::FirstSeen = iCache::LastModified = iCache::LastSeen;

	Dhcp = *inDhcp_sptr;
	Dhcp.Expiration_set();
	if(Debug) {
		syslog(LOG_DEBUG, "Creating DHCP data for %s with expiration %lu", Dhcp.Mac.c_str(), Dhcp.Expiration_get());
	}
	return true;
}

bool Host::Dhcp_set (const std::string IpAddress, const MacAddress Mac, const std::string Hostname, const std::string DhcpHostname, const std::string DhcpVendor) {
	Dhcp.IpAddress = IpAddress;
	Dhcp.Mac = Mac;
	Dhcp.Hostname = Hostname;
	Dhcp.DhcpHostname = DhcpHostname;
	Dhcp.DhcpVendor = DhcpVendor;

	iCache::FirstSeen = iCache::LastModified = iCache::LastSeen = time(nullptr);
	Dhcp.Expiration_set();
	if(Debug) {
		syslog(LOG_DEBUG, "Creating DHCP data for %s with expiration %lu", Dhcp.Mac.c_str(), Dhcp.Expiration_get());
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
						syslog(LOG_DEBUG, "Pruning FlowEntry to %s for DstPort %u with expiration %ld while now is %ld",
								fc->first.to_string().c_str(), (*it)->DstPort, (*it)->Expiration_get (), time(nullptr));
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
						syslog(LOG_DEBUG, "Pruning FlowEntry to %s for DstPort %u with expiration %ld while now is %ld",
								fc->first.to_string().c_str(), (*it)->DstPort, (*it)->Expiration_get (), time(nullptr));
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
	uint32_t pruned_dnsqueries = 0;
	for(auto const& dc: DnsHostCache) {
		if (Force || dc.second->isExpired()) {
			if (Debug) {
				syslog(LOG_DEBUG, "Pruning DNS for %s with expiration %ld while now is %ld", dc.first.c_str(), dc.second->Expiration_get (), time(nullptr));
			}
			DnsHostCache.erase(dc.first);
			pruned_dnsqueries++;
			pruned = true;
		}
	}
	if(Debug) {
		syslog (LOG_DEBUG, "Pruned %u DNS queries", pruned_dnsqueries);
	}
	return pruned;
}


