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



#include "json.hpp"
using json = nlohmann::json;

#include "Host.h"
#include "DhcpRequest.h"
#include "SsdpLocation.h"
#include "FlowEntry.h"
#include "DeviceProfile.h"

// Keep track of DNS queries performed by a host
void Host::addorupdateDnsQueryList (std::string inFqdn) {
    std::string fqdn = inFqdn;
    std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);
    if (Debug == true) {
        syslog (LOG_DEBUG, "Host(%s): Setting DnsQueryList for %s to now", Ipv4Address.c_str(), fqdn.c_str());
    }
    DnsQueryList[fqdn] = time(nullptr);
}

bool Host::inDnsQueryList (std::string inFqdn) {
    std::string fqdn = inFqdn;
    std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);
    if (DnsQueryList.find(fqdn) == DnsQueryList.end()) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Host(%s): %s not in DnsQueryList", Ipv4Address.c_str(), fqdn.c_str());
        }
        return false;
    }
    if (Debug == true) {
        syslog (LOG_DEBUG, "Host(%s): %s is in DnsQueryList", Ipv4Address.c_str(), fqdn.c_str());
    }
    return true;
}

time_t Host::setExpiration (time_t inExpiration) {
    iCache::Expires = time(nullptr) + inExpiration;
    return iCache::LastSeen + HOSTDEFAULTEXPIRATION;
}

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
		if(Debug == true) {
			syslog(LOG_DEBUG, "Host(%s): Evaluating host %s against device profile %s", 
                    Ipv4Address.c_str(), Mac.c_str(), kv.first.c_str());
		}
		auto &dp = *(kv.second);
		auto match = Match(dp);
		if (match > bestmatch) {
			UploadStats = kv.second->getUploadStats();
			bestmatch = match;
			matcheduuid = kv.first;
			matchversion = dp.getDeviceProfileVersion();
		}

	}
	if (bestmatch >= ConfidenceLevel::Low) {
		Uuid = matcheduuid;
		if (Debug == true) {
		    syslog(LOG_DEBUG, "Host(%s): Host %s matched %s", Ipv4Address.c_str(), Mac.c_str(), Uuid.c_str());
		}
		return true;
	}
	return false;
}

ConfidenceLevel Host::Match(const DeviceProfile& dp) {
	ConfidenceLevel bestmatch = ConfidenceLevel::None;
	auto v = dp.getIdentifiers();
	for (auto& i : v) {
		if(Debug) {
			syslog (LOG_DEBUG, "Host(%s): Testing identifier", Ipv4Address.c_str());
		}
		auto match = Match(*i);
		if (match >= ConfidenceLevel::High) {
			if(Debug) {
				syslog(LOG_DEBUG, "Host(%s): Host %s matched with high confidence", Ipv4Address.c_str(), Mac.c_str());
			}
			return match;
        }
		if 	(match > bestmatch) {
			bestmatch = match;
        }
	}
	if(Debug) {
		syslog(LOG_DEBUG, "Host(%s): Host %s match level %d", Ipv4Address.c_str(), Mac.c_str(), static_cast<int>(bestmatch));
	}
	return bestmatch;
}

ConfidenceLevel Host::Match(const Identifier& i) {
	for (auto& mc : i.MatchConditions_get()) {
		if(Debug) {
			syslog (LOG_DEBUG, "Host: Testing match condition %s", (*mc).Key.c_str());
		}
		if(not Match (*mc)) {
			if(Debug) {
				syslog (LOG_DEBUG, "Host(%s): Host %s did not match condition %s", Ipv4Address.c_str(), Mac.c_str(), (*mc).Key.c_str());
			}
			return ConfidenceLevel::None;
		}
	}
	for (auto& cc : i.ContainConditions_get()) {
		if(Debug) {
			syslog (LOG_DEBUG, "Host: Testing contain condition %s", (*cc).Key.c_str());
		}
		if(not Match (*cc)) {
			if(Debug) {
				syslog (LOG_DEBUG, "Host(%s): Host %s did not contain condition %s", Ipv4Address.c_str(), Mac.c_str(), (*cc).Key.c_str());
			}
			return ConfidenceLevel::None;
		}
	}
	if(Debug) {
		syslog(LOG_DEBUG, "Host(%s): Host %s matched MustMatch and/or MustContain conditions", Ipv4Address.c_str(), Mac.c_str());
	}
	return i.IdentifyConfidenceLevel_get();
}

bool Host::Match(const MatchCondition& mc) {
	std::string value;
	if (mc.Key == "MacOid") {
		value = Mac.str().substr(0,8);
	} else if (mc.Key == "DhcpVendor") {
		value = Dhcp.DhcpVendor;
	} else if (mc.Key == "DhcpHostname") {
		value = Dhcp.Hostname ;
	} else if (mc.Key == "SsdpFriendlyName" ) {
		value = Ssdp.FriendlyName;
	} else if (mc.Key == "SsdpManufacturer") {
		value = Ssdp.Manufacturer;
    } else if (mc.Key == "SsdpDeviceType") {
        value = Ssdp.DeviceType;
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
	} else if (mc.Key == "WsDiscoveryXAddrs") {
	    value = Wsd.wsdXAddrs;
	} else if (mc.Key == "WsDiscoveryTypes") {
	    value = Wsd.wsdTypes;
    } else if (mc.Key == "MdnsHostname") {
        value = Mdns.Hostname;
	} else if (mc.Key == "MdnsOs") {
	    value = Mdns.Os;
	} else if (mc.Key == "MdnsHw") {
	    value = Mdns.Hw;
    } else if (mc.Key == "MdnsDeviceUrl") {
        value = Mdns.DeviceUrl;
    } else if (mc.Key == "MdnsManufacturer") {
        value = Mdns.Manufacturer;
    } else if (mc.Key == "MdnsModelName") {
        value = Mdns.ModelName;
	}
	if (value == "" || std::all_of(value.begin(),value.end(),isspace)) {
		if(Debug == true) {
			syslog(LOG_DEBUG, "Host(%s): Host %s has no value for MustMatch condition %s",
                    Ipv4Address.c_str(), Mac.c_str(), mc.Key.c_str());
		}
	}
	size_t startpos = 0;
	size_t mcvaluelength = mc.Value.length();
	size_t datavaluelength = value.length();
	std::string mcvalue = mc.Value;
	if (mc.Value[0] == '*') {
		mcvalue = mcvalue.substr(1);
		startpos = datavaluelength - mcvalue.length();
	} else if (mc.Value[mcvaluelength-1] == '*') {
		mcvalue = mcvalue.substr(0,mcvaluelength-1);
		startpos = 0;
	}
    if (value.length() < mcvalue.length()) {
        return false;
    }
	if (Debug == true) {
	    syslog(LOG_DEBUG, "Host(%s): comparing %s with %s, start position %zu, length %zu",
                Ipv4Address.c_str(), value.c_str(), mcvalue.c_str(), startpos, mcvalue.length()-startpos);
	}
	if (value.compare(startpos, mcvalue.length() - startpos, mcvalue) == 0) {
		if(Debug) {
			syslog(LOG_DEBUG, "Host: Host %s matched MustMatch condition", Mac.c_str());
		}
		return true;
    }
	if(Debug) {
		syslog (LOG_DEBUG, "Host(%s): Host %s did not match condition %s with value %s from position %zu", 
                Ipv4Address.c_str(), value.c_str(), mc.Key.c_str(), mcvalue.c_str(), startpos);
	}
	return false;
}

bool Host::Match(const ContainCondition& cc) {
	if(cc.Key == "DnsQueries") {
		for (auto fqdn: cc.Values) {
		    if (DnsQueryList.find(fqdn) != DnsQueryList.end()) {
				if(Debug) {
					syslog(LOG_DEBUG, "Host(%s): Found DnsQuery for %s from host %s", 
                            Ipv4Address.c_str(), fqdn.c_str(), Mac.c_str());
				}
			} else {
				if(Debug) {
					syslog(LOG_DEBUG, "Host(%s): Didn't find DnsQuery for %s from host %s",
                            Ipv4Address.c_str(), fqdn.c_str(), Mac.c_str());
				}
				return false;
			}
		}
	} else {
		if(Debug) {
			syslog(LOG_DEBUG, "Host(%s): Unsupported MustContain key %s", Ipv4Address.c_str(), cc.Key.c_str());
		}
		return false;
	}
	if(Debug) {
		syslog(LOG_DEBUG, "Host(%s): Host %s matched MustContain condition", Ipv4Address.c_str(), Mac.c_str());
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
        if (Ssdp.Location != "") {
            std::smatch m;
            std::regex_search(Ssdp.Location, m, location_rx);
            if (not m.empty()) {
                location = m.str(1) + "a.b.c.d" + m.str(2);
            }
        }
        j["SsdpLocation"] = location;
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
	if (Debug == true) {
		syslog (LOG_DEBUG, "Host(%s): Adding items from DnsQueryList to list of fqdns", Ipv4Address.c_str());
	}
	for (auto &dq: DnsQueryList) {
		if (detailed == false) {
			if (Debug == true) {
				syslog (LOG_DEBUG, "Host(%s): Adding FQDN %s from DnsQueryList to list of fqdns", Ipv4Address.c_str(), dq.first.c_str());
			}
			fqdns += dq.first + " ";
		}
	}

	if (detailed == false && not fqdns.empty()) {
		j["DnsQueries"] = fqdns;
    }

	return true;
}

bool Host::TrafficStats(json& j, const uint32_t interval, const bool ReportPrivateAddresses, const std::set<std::string> &LocalIps,
		const DnsCache <Tins::IPv4Address> &dCipv4, const DnsCache <Tins::IPv6Address> &dCipv6,
		const DnsCache <std::string> &dCcname, bool force) {
	if (not isMatched()) {
		return false;
	}
	if (not force && LastSeen < (time(nullptr) - interval)) {
		return false;
	}

	// List of endpoints (fqdns & IPv4/v6's) that the host communicated with
	std::unordered_set<std::string> endpoints;
	{
	    std::unordered_set<Tins::IPv4Address> allIps;
	    for (auto &fc: FlowCacheIpv4) {
	        bool foundFqdn = false;
	        Tins::IPv4Address  ip(fc.first);

	        if (ReportPrivateAddresses == false && ip.is_private()) {
	            continue;
	        }
	        // Did we already process a FlowCache entry with the same destination,
	        // ie. with different destination port?
	        auto it = allIps.find(ip);
	        if (it != allIps.end()) {
	            foundFqdn = true;
	        } else {
	            if (Debug == true) {
	                syslog (LOG_DEBUG, "Host(%s): Getting all DNS lookups for %s", Ipv4Address.c_str(), ip.to_string().c_str());
	            }
	            std::vector<std::string> fqdns = dCipv4.getAllFqdns(ip);
                if (Debug == true) {
                    syslog (LOG_DEBUG, "Host(%s): got %zu FQDNs for %s", Ipv4Address.c_str(), fqdns.size(), ip.to_string().c_str());
                }
	            for (auto itf : fqdns) {
	                std::set<std::string> cname_fqdns = dCcname.getFqdns(itf);
	                for(auto fqdn: cname_fqdns) {
	                    if (Debug) {
	                        if (itf != fqdn) {
	                            syslog (LOG_DEBUG, "Host(%s): Reverse resolved %s to %s, might have CNAME %s",
	                                    Ipv4Address.c_str(), ip.to_string().c_str(), itf.c_str(), fqdn.c_str());
	                        } else {
	                            syslog (LOG_DEBUG, "Host(%s): Reverse resolved %s to %s, with no CNAME",
	                                    Ipv4Address.c_str(), ip.to_string().c_str(), fqdn.c_str());
	                        }
	                    }
	                    if (inDnsQueryList(fqdn)) {
	                        endpoints.insert(fqdn);
	                        foundFqdn = true;
	                    }
	                }
	            }
	            if (foundFqdn == false) {
	                if (Debug) {
	                    syslog (LOG_DEBUG, "Host(%s): No FQDN found for %s", 
	                            Ipv4Address.c_str(), ip.to_string().c_str());
	                }
	                endpoints.insert(ip.to_string());
	            }
	            allIps.insert(ip);
	        }
	    }
	}
    {
        std::unordered_set<Tins::IPv6Address> allIps;
        for (auto &fc: FlowCacheIpv6) {
            bool foundFqdn = false;
            const Tins::IPv6Address ip(fc.first);
            // Did we already process a FlowCache entry with the same destination,
            // ie. with different destination port?
            auto it = allIps.find(ip);
            if (it != allIps.end()) {
                foundFqdn = true;
            } else {
                if (Debug == true) {
                    syslog (LOG_DEBUG, "Host(%s): Getting all DNS lookups for %s", Ipv4Address.c_str(), ip.to_string().c_str());
                }
                std::vector<std::string> fqdns = dCipv6.getAllFqdns(ip);
                for (auto &itf : fqdns) {
                    std::set<std::string> cname_fqdns = dCcname.getFqdns(itf);
                    for(auto fqdn: cname_fqdns) {
                        if (Debug) {
                            if (itf != fqdn) {
                                syslog (LOG_DEBUG, "Host(%s): Reverse resolved %s to %s, might have CNAME %s",
                                        Ipv4Address.c_str(), ip.to_string().c_str(), itf.c_str(), fqdn.c_str());
                            } else {
                                syslog (LOG_DEBUG, "Host(%s): Reverse resolved %s to %s, with no CNAME",
                                        Ipv4Address.c_str(), ip.to_string().c_str(), fqdn.c_str());
                            }                    }
                        if (inDnsQueryList(fqdn)) {
                            endpoints.insert(fqdn);
                            foundFqdn = true;
                        }
                    }
                }
                if (foundFqdn == false) {
                    endpoints.insert(ip.to_string());
                }
                allIps.insert(ip);
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
			{"Ipv6Address", Ipv6Address},
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
bool Host::setFlowEntry(const uint16_t inSrcPort, const std::string inDstIp,
			const uint16_t inDstPort, const uint8_t inProtocol, const uint32_t inExpiration) {
	iCache::LastSeen = time(nullptr);
	if (inDstIp == "239.255.255.250") {
		if(Debug) {
			syslog(LOG_DEBUG, "Host(%s): Ignoring flow to 239.255.255.0", Ipv4Address.c_str());
		}
		return false;
	}
	auto f = std::make_shared<FlowEntry>();
	if(Debug) {
		syslog(LOG_DEBUG, "Host(%s): Creating new Flow Entry for src port %u, dest ip %s, dest port %u, protocol %u",
				Ipv4Address.c_str(), inSrcPort,	inDstIp.c_str(), inDstPort, inProtocol);
	}
	iCache::LastModified = time(nullptr);
	f->SrcPort = inSrcPort;
	f->DstPort = inDstPort;
	f->Protocol = inProtocol;
	f->setExpiration(inExpiration);

	try {
		Tins::IPv4Address dstIpv4Address(inDstIp);

		if (FlowCacheIpv4.find(dstIpv4Address) == FlowCacheIpv4.end()) {
			FlowCacheIpv4[dstIpv4Address] = std::make_shared<FlowEntryList>();
			FlowCacheIpv4[dstIpv4Address]->push_back(f);
			if(Debug) {
				syslog(LOG_DEBUG, "Host(%s): Adding to IPv4 FlowCache with destination %s : %u Protocol %u",
						Ipv4Address.c_str(), inDstIp.c_str(), inDstPort, inProtocol);
			}
			return true;
		}
		// Create or update existing flow to destination IP
		for(FlowEntryList::iterator existingflow = FlowCacheIpv4[dstIpv4Address]->begin();
				existingflow != FlowCacheIpv4[dstIpv4Address]->end(); ++existingflow) {
			// Update existing flow it it matches incoming flow (ignoring Expiration)
			if (**existingflow == *f) {
				if(Debug) {
					syslog(LOG_DEBUG, "Host(%s): Updating expiration of existing FlowEntry in IPv4 FlowCache for destination %s",
							Ipv4Address.c_str(), inDstIp.c_str());
				}
				(*existingflow)->setExpiration(inExpiration);
				return false;
			}
		}
		// This flow doesn't match any of the existing flows
		if(Debug) {
			syslog(LOG_DEBUG, "Host(%s): Adding FlowEntry to IPv4 FlowCache for destination %s",
					Ipv4Address.c_str(), inDstIp.c_str());
		}
		FlowCacheIpv4[dstIpv4Address]->push_back(f);
		return true;
	} catch (...) {
		Tins::IPv6Address dstIpv6Address(inDstIp);

		if (FlowCacheIpv6.find(dstIpv6Address) == FlowCacheIpv6.end()) {
			FlowCacheIpv6[dstIpv6Address] = std::make_shared<FlowEntryList>();
			FlowCacheIpv6[dstIpv6Address]->push_back(f);
			if(Debug) {
				syslog(LOG_DEBUG, "Host(%s): Adding to IPv6 FlowCache with destination %s : %u Protocol %u",
						Ipv4Address.c_str(), inDstIp.c_str(),
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
					syslog(LOG_DEBUG, "Host(%s): Updating expiration of existing FlowEntry in IPv6 FlowCache for destination %s",
							Ipv4Address.c_str(), inDstIp.c_str());
				}
				(*existingflow)->setExpiration(inExpiration);
				return false;
			}
		}
		// This flow doesn't match any of the existing flows
		if(Debug) {
			syslog(LOG_DEBUG, "Host(%s): Adding FlowEntry to IPv6 FlowCache for destination %s", Ipv4Address.c_str(), inDstIp.c_str());
		}
		FlowCacheIpv6[dstIpv6Address]->push_back(f);
		return true;
	}
	syslog(LOG_NOTICE, "Host(%s): IP address %s is neither v4 or v6", Ipv4Address.c_str(), inDstIp.c_str());
	return false;
}

bool Host::setDhcp (const std::string inIpAddress, const MacAddress inMac, const std::string inHostname, const std::string inDhcpVendor) {
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
		syslog(LOG_DEBUG, "Host(%s): Creating DHCP data for %s with expiration %lu with ipaddress %s, hostname %s, vendor %s ",
				Ipv4Address.c_str(), Dhcp.Mac.c_str(), Dhcp.getExpiration(), Dhcp.IpAddress.c_str(), Dhcp.Hostname.c_str(),
				Dhcp.DhcpVendor.c_str());
	}
	return true;
}

bool Host::setSsdpInfo(const std::shared_ptr<SsdpHost> insHost) {
	iCache::LastSeen = time(nullptr);
	if (Ssdp == *insHost) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Host(%s): not setting Ssdp info as same info is already known", Ipv4Address.c_str());
        }
        return false;
	}

	iCache::LastModified = iCache::LastSeen;
	Ssdp = *insHost;
    if (Debug == true) {
        syslog (LOG_DEBUG, "Host(%s): SSDP info has been set", Ipv4Address.c_str());
    }

	// Information in the SSDP multicast message has changed so if the Location field contains a URL, we query it
	if (Ssdp.Location != "") {
		auto resp = SsdpLocation::Get(Ssdp);
	}
	return true;
}

bool Host::setWsDiscoveryInfo(const std::shared_ptr<WsDiscoveryHost> inwsdHost) {
    iCache::LastSeen = time(nullptr);
    if (Wsd == *inwsdHost) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Host(%s): not setting WS-Discovery info as same info is already known", Ipv4Address.c_str());
        }
        return false;
    }
    iCache::LastModified = iCache::LastSeen;
    Wsd = *inwsdHost;
    if (Debug == true) {
        syslog (LOG_DEBUG, "Host(%s): WS-Discovery info has been set", Ipv4Address.c_str());
    }
    return true;
}

bool Host::setMdnsInfo(const std::shared_ptr<MdnsHost> inmdnsHost) {
    iCache::LastSeen = time(nullptr);
    if (Mdns == *inmdnsHost) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Host(%s): not setting mDNS info as same info is already known", Ipv4Address.c_str());
        }
        return false;
    }
    iCache::LastModified = iCache::LastSeen;
    Mdns = *inmdnsHost;
    if (Debug == true) {
        syslog (LOG_DEBUG, "Host(%s): mDNS info has been set", Ipv4Address.c_str());
    }
    return true;
}

bool Host::UploadsEnabled() {
	return UploadStats;
}

uint32_t Host::Prune (bool Force) {
	bool pruned = false;
	if(Debug) {
		syslog(LOG_DEBUG, "Host(%s): Pruning host %s", Ipv4Address.c_str(), Mac.c_str());
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
						syslog(LOG_DEBUG, "Host(%s): Pruning IPv4 FlowEntry to %s for DstPort %u with expiration %ld while now is %ld",
								Ipv4Address.c_str(), dstIp.c_str(), (*it)->DstPort, (*it)->getExpiration (), time(nullptr));
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
					syslog(LOG_DEBUG, "Host(%s): Pruning FlowEntryList for %s as it is now empty", Ipv4Address.c_str(), fc->first.to_string().c_str());
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
						syslog(LOG_DEBUG, "Host(%s): Pruning IPv6 FlowEntry to %s for DstPort %u with expiration %ld while now is %ld",
								Ipv4Address.c_str(), fc->first.to_string().c_str(), (*it)->DstPort, (*it)->getExpiration (), time(nullptr));
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
					syslog(LOG_DEBUG, "Host(%s): Pruning FlowEntryList for %s as it is now empty",
							Ipv4Address.c_str(), fc->first.to_string().c_str());
				}
				fc = FlowCacheIpv6.erase(fc);
				pruned = true;
				pruned_flows++;
			} else {
				++fc;
			}
		}
		if(Debug) {
			syslog (LOG_DEBUG, "Host(%s): Pruned %u Flow Entries and %u flows", Ipv4Address.c_str(), pruned_flowentries, pruned_flows);
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
				syslog (LOG_DEBUG, "Host(%s): Deleting %s from DnsQueryList as %lu is later than %lu",
						Ipv4Address.c_str(), i->first.c_str(), i->second, now - Expired);
			}
			i = DnsQueryList.erase(i);
			deletecount++;
		} else {
			++i;
		}
	}
	return deletecount;
}


