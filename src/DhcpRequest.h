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

 * DhcpRequest.h
 *
 *  Created on: Mar 22, 2017
 *      Author: steven
 */

#ifndef DHCPREQUEST_H_
#define DHCPREQUEST_H_

#include <ctime>
#include "iCache.h"

#define DHCPDEFAULTEXPIRATION 604800

class  DhcpRequest : public iCache {
public:
	std::string DhcpHostname;	// Hostname provided by DHCP server to the client
	std::string DhcpVendor;
	std::string Hostname;		// Hostname provided by the client to DHCP server
	std::string MacAddress;
	std::string IpAddress;

	DhcpRequest(const time_t inExpiration = DHCPDEFAULTEXPIRATION) { Expiration_set(inExpiration); }

	// iCache interface methods.
    time_t Expiration_set (time_t inExpiration = DHCPDEFAULTEXPIRATION) {
    	return iCache::Expiration = time(nullptr) + inExpiration;
    }
    time_t Expiration_get () { return iCache::Expiration; }
    bool isExpired() { return time(nullptr) >= iCache::Expiration; }
    uint32_t Prune (bool Force = false) {}

	void operator = (const DhcpRequest &rhs) {
		DhcpHostname = rhs.DhcpHostname;
		DhcpVendor = rhs.DhcpVendor;
		Hostname = rhs.Hostname;
		MacAddress = rhs.MacAddress;
		IpAddress = rhs.IpAddress;
		iCache::LastModified = time(nullptr);
		iCache::LastSeen = time(nullptr);
		iCache::FirstSeen = time(nullptr);
	}
    bool operator == (const DhcpRequest &rhs) const {
		return DhcpHostname == rhs.DhcpHostname &&
			DhcpVendor == rhs.DhcpVendor &&
			Hostname == rhs.Hostname &&
			MacAddress == rhs.MacAddress &&
			IpAddress == rhs.IpAddress;
	}
};
#endif /* DHCPREQUEST_H_ */
