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
    	return iCache::Expires = time(nullptr) + inExpiration;
    }
    time_t Expiration_get () { return iCache::Expires; }
    bool isExpired() { return time(nullptr) >= iCache::Expires; }
    uint32_t Prune (bool Force = false) { return 0; }

	void operator = (const DhcpRequest &rhs) {
		std::string rhsMac = rhs.MacAddress;
		std::transform(rhsMac.begin(), rhsMac.end(), rhsMac.begin(), ::tolower);
		DhcpHostname = rhs.DhcpHostname;
		DhcpVendor = rhs.DhcpVendor;
		Hostname = rhs.Hostname;
		MacAddress = rhsMac;
		IpAddress = rhs.IpAddress;
		iCache::LastModified = time(nullptr);
		iCache::LastSeen = time(nullptr);
		iCache::FirstSeen = time(nullptr);
	}
    bool operator == (const DhcpRequest &rhs) const {
		std::string lhsMac = MacAddress;
		std::transform(lhsMac.begin(), lhsMac.end(), lhsMac.begin(), ::tolower);
		std::string rhsMac = rhs.MacAddress;
		std::transform(rhsMac.begin(), rhsMac.end(), rhsMac.begin(), ::tolower);
		return DhcpHostname == rhs.DhcpHostname &&
			DhcpVendor == rhs.DhcpVendor &&
			Hostname == rhs.Hostname &&
			lhsMac == rhsMac &&
			IpAddress == rhs.IpAddress;
	}
};
#endif /* DHCPREQUEST_H_ */
