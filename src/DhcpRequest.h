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
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef DHCPREQUEST_H_
#define DHCPREQUEST_H_

#include <ctime>
#include "iCache.h"
#include "MacAddress.h"

#define DHCPDEFAULTEXPIRATION 604800

class  DhcpRequest : public iCache {
public:
	std::string DhcpVendor;
	std::string Hostname;		// Hostname provided by the client to DHCP server
	MacAddress Mac;
	std::string IpAddress;

	DhcpRequest(const time_t inExpiration = DHCPDEFAULTEXPIRATION) { setExpiration(inExpiration); }

	// iCache interface methods.
    time_t setExpiration (time_t inExpiration = DHCPDEFAULTEXPIRATION) {
    	return iCache::Expires = time(nullptr) + inExpiration;
    }
    time_t getExpiration () { return iCache::Expires; }
    bool isExpired() { return time(nullptr) >= iCache::Expires; }
    uint32_t Prune (bool Force = false) { return 0; }

	void operator = (const DhcpRequest &rhs) {
		DhcpVendor = rhs.DhcpVendor;
		Hostname = rhs.Hostname;
		Mac = rhs.Mac;
		IpAddress = rhs.IpAddress;
		iCache::LastModified = time(nullptr);
		iCache::LastSeen = time(nullptr);
		iCache::FirstSeen = time(nullptr);
	}
    bool operator == (const DhcpRequest &rhs) const {
		return DhcpVendor == rhs.DhcpVendor &&
			Hostname == rhs.Hostname &&
			Mac == rhs.Mac &&
			IpAddress == rhs.IpAddress;
	}
};
#endif /* DHCPREQUEST_H_ */
