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

 */
#include <string>
#include <cstring>
#include <syslog.h>
#include <forward_list>


#include <json.hpp>
using json = nlohmann::json;

#include "DnsLogEntry.h"

uint32_t DnsLogEntry::DnsStats (json & j, const uint32_t time_interval) {
	auto dnsentries = 0;
	if (not Fresh(time_interval)) {
		return dnsentries;
    }

	j["DnsQueries"][Fqdn] = json::array();
	for (auto &ip: Ipv4s) {
		dnsentries++;
		j.push_back(ip.first.to_string());
	}
	for (auto &ip: Ipv6s) {
		dnsentries++;
		j.push_back(ip.first.to_string());
	}

	return dnsentries;
}

//! Deletes expired (or all is Force is true) records from DnsLogEntry for a FQDN
uint32_t DnsLogEntry::Prune(bool Force) {
	uint32_t deletecount = 0;
	auto now = time(nullptr);
	for (auto i = Ipv4s.begin(); i != Ipv4s.end(); ++i) {
		if (Force || now > i->second ) {
			Ipv4s.erase(i);
			if(Debug) {
				syslog(LOG_DEBUG, "Pruning DnsLogEntry for IPv4 %s from %s", i->first.to_string().c_str(), Fqdn.c_str());
			}
			deletecount++;
		}
    }
	for (auto i = Ipv6s.begin(); i != Ipv6s.end(); ++i) {
		if (Force || now > i->second ) {
			Ipv6s.erase(i);
			if(Debug) {
				syslog(LOG_DEBUG, "Pruning DnsLogEntry for IPv6 %s from %s", i->first.to_string().c_str(), Fqdn.c_str());
			}
			deletecount++;
		}
    }
	return deletecount;
}

//! Gets the list of IP addresses for an FQDN

uint32_t DnsLogEntry::Ips_get(std::map<std::string,std::shared_ptr<std::unordered_set<std::string>>> &outIps) {
	uint32_t ipcount = 0;
	for (auto const &i: Ipv4s) {
		ipcount++;
		if (outIps.find(i.first.to_string()) == outIps.end()) {
			outIps[i.first.to_string()] = std::make_shared<std::unordered_set<std::string>>();
		}
		outIps[i.first.to_string()]->insert(Fqdn);
	}
	for (auto const &i: Ipv6s) {
		ipcount++;
		if (outIps.find(i.first.to_string()) == outIps.end()) {
			outIps[i.first.to_string()] = std::make_shared<std::unordered_set<std::string>>();
		}
		outIps[i.first.to_string()]->insert(Fqdn);
	}
	return ipcount;
}

//! Adds an IP address with expiration to the DnsLogEntry for a FQDN
bool DnsLogEntry::Ips_set(const std::string i, uint32_t inExpirationSeconds) {
	// DNS record expires at now (in epoch seconds) + seconds after which record must be expired
	time_t exp = time(nullptr) + inExpirationSeconds;
	boost::asio::ip::address IpAddress;
	IpAddress.from_string(i);
	if (IpAddress.is_v4() == true) {
		boost::asio::ip::address_v4 IpAddressV4 = IpAddress.to_v4();
		auto it = Ipv4s.find(IpAddressV4);
		if (it == Ipv4s.end()) {
			if(Debug) {
				syslog(LOG_DEBUG, "Adding %s with expiration %lu for %s", i.c_str(), exp, Fqdn.c_str());
			}
			Ipv4s[IpAddressV4] = exp;
		} else {
			if (it->second == exp) {
				return false;
			}
			if(Debug) {
				syslog(LOG_DEBUG, "Updating expiration for %s %s", i.c_str(), Fqdn.c_str());
			}
			Ipv4s[IpAddressV4] = exp;
		}
	} else if (IpAddress.is_v6() == true){
		boost::asio::ip::address_v6 IpAddressV6 = IpAddress.to_v6();
		auto it = Ipv6s.find(IpAddressV6);
		if (it == Ipv6s.end()) {
			if(Debug) {
				syslog(LOG_DEBUG, "Adding %s with expiration %lu for %s", i.c_str(), exp, Fqdn.c_str());
			}
			Ipv6s[IpAddressV6] = exp;
		} else {
			if (it->second == exp) {
				return false;
			}
			if(Debug) {
				syslog(LOG_DEBUG, "Updating expiration for %s %s", i.c_str(), Fqdn.c_str());
			}
			Ipv6s[IpAddressV6] = exp;
		}
	} else {
		syslog(LOG_NOTICE, "Ips_set: IP Address %s is neither IPv4 or IPv6", i.c_str());
	}
	return true;
}

