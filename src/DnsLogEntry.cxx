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

	std::forward_list<std::string> l;
	for (auto &ip: Ips) {
		dnsentries++;
		l.push_front(ip.first);
	}

	j["DnsQueries"][Fqdn] = l;
	return dnsentries;
}

//! Deletes expired (or all is Force is true) records from DnsLogEntry for a FQDN
uint32_t DnsLogEntry::Prune(bool Force) {
	uint32_t deletecount = 0;
	auto now = time(nullptr);
	for (auto i = Ips.begin(); i != Ips.end(); ++i) {
		if (Force || now > i->second ) {
			Ips.erase(i);
			if(Debug) {
				syslog(LOG_DEBUG, "Pruning %s from %s", i->first.c_str(), Fqdn.c_str());
			}
			deletecount++;
		}
    }
	return deletecount;
}

//! Gets the list of IP addresses for an FQDN

uint32_t DnsLogEntry::Ips_get(std::map<std::string,std::shared_ptr<std::unordered_set<std::string>>> &outIps) {
	uint32_t ipcount = 0;
	for (auto const &i: Ips) {
		ipcount++;
		if (outIps.find(i.first) == outIps.end()) {
			outIps[i.first] = std::make_shared<std::unordered_set<std::string>>();
			// outIps[i.first] = std::make_unique<std::string>();
		}
		outIps[i.first]->insert(Fqdn);
	}
	return ipcount;
}

//! Adds an IP address with expiration to the DnsLogEntry for a FQDN
bool DnsLogEntry::Ips_set(const std::string i, uint32_t inExpirationSeconds) {
	// DNS record expires at now (in epoch seconds) + seconds after which record must be expired
	time_t exp = time(nullptr) + inExpirationSeconds;

	auto it = Ips.find(i);
	if (it == Ips.end()) {
		if(Debug) {
			syslog(LOG_DEBUG, "Adding %s with expiration %lu for %s", i.c_str(), exp, Fqdn.c_str());
		}
		Ips[i] = exp;
	} else {
		if (it->second == exp) {
			return false;
		}
		if(Debug) {
			syslog(LOG_DEBUG, "Updating expiration for %s %s", i.c_str(), Fqdn.c_str());
		}
		Ips[i] = exp;
	}
	return true;
}

