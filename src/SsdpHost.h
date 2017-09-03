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

 * SsdpHost.h
 *
 *  Created on: Mar 25, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef SSDPHOST_H_
#define SSDPHOST_H_

#include <string>

struct SsdpHost {
	std::string IpAddress;
	std::string FriendlyName;
	std::string Manufacturer;
	std::string ManufacturerUrl;
	std::string ModelName;
	std::string ModelUrl;
	std::string SerialNumber;
	std::string UserAgent;
	std::string Server;
	std::string Location;

	//! SsdpHost comparison only compares info from the SSDP multicast messages, not the host info.
	bool operator == (const SsdpHost &rhs) const {
		return IpAddress == rhs.IpAddress &&
				UserAgent == rhs.UserAgent &&
				Server == rhs.Server &&
				Location == rhs.Location &&
				FriendlyName == rhs.FriendlyName &&
				Manufacturer == rhs.Manufacturer &&
				ManufacturerUrl == rhs.ManufacturerUrl &&
				ModelName == rhs.ModelName &&
				ModelUrl == rhs.ModelUrl &&
				SerialNumber == rhs.SerialNumber;
	}
};

#endif /* SSDPHOST_H_ */
