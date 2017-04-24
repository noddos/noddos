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

 * DnsLogEntry.h
 *
 *  Created on: Mar 4, 2017
 *      Author: steven
 */

#ifndef DNSLOGENTRY_H_
#define DNSLOGENTRY_H_

#include <string>
#include <map>
#include <ctime>
#include <vector>
#include <unordered_set>

#include <json.hpp>
using json = nlohmann::json;

#include "iCache.h"

#define DNSLOGENTRYDEFAULTEXPIRATION 86400

class DnsLogEntry : public iCache {
    private:
        std::string Fqdn;
        std::map<std::string, uint32_t> Ips;
        bool Debug;

    public:
        DnsLogEntry(const std::string inFqdn, const bool inDebug = false): Fqdn{inFqdn}, Debug{inDebug}
        	{ Expiration_set(); iCache::FirstSeen = iCache::LastSeen = iCache::LastModified = time(nullptr); };
        DnsLogEntry(const std::string inFqdn, const std::map<std::string, uint32_t> inIps, const bool inDebug = false):
        	Fqdn{inFqdn}, Ips{inIps}, Debug{inDebug}
        	{ Expiration_set(); iCache::FirstSeen = iCache::LastSeen = iCache::LastModified = time(nullptr); };

        uint32_t Ips_get(std::unordered_set<std::string> &outIps);
        bool Ips_set(const std::string i, uint32_t exp = DNSLOGENTRYDEFAULTEXPIRATION);

        std::string Fqdn_get() { return this->Fqdn; }
        std::string Fqdn_set(std::string inFqdn) { return (this->Fqdn = inFqdn); }

        uint32_t DnsStats (json & j, const uint32_t time_interval);

        // iCache interface methods.
        time_t Expiration_set (time_t inExpiration = DNSLOGENTRYDEFAULTEXPIRATION) {
        	return iCache::Expires = time(nullptr) + inExpiration;
        }
        time_t Expiration_get () { return iCache::Expires; }
        bool isExpired() { return time(nullptr) >= iCache::Expires; }
        uint32_t Prune (bool Force = false);

        DnsLogEntry& operator=(DnsLogEntry &rhs) {
        	if (this == &rhs)
        		return *this;
        	this->Fqdn = rhs.Fqdn;
        	this->Ips = rhs.Ips;
        	return *this;
        }
};


#endif /* DNSLOGENTRY_H_ */
