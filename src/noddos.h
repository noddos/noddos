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

 * noddos.h
 *
 *  Created on: Mar 11, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef NODDOS_H_
#define NODDOS_H_

#define FLOWDEFAULTEXPIRATION 14400

#include <iostream>
#include <unordered_map>
#include <set>
#include <string>
#include <map>

enum struct ConfidenceLevel : int { None, none, NONE, Low, low, LOW, Medium, medium, MEDIUM, High, high, HIGH };

struct WsDiscoveryHost {
    std::string IpAddress;
    std::string wsdTypes;
    std::string wsdXAddrs;

    bool operator == (const WsDiscoveryHost &rhs) const {
        return IpAddress == rhs.IpAddress &&
                wsdXAddrs == rhs.wsdXAddrs &&
                wsdTypes == rhs.wsdTypes;
    }
};

struct MdnsHost {
    std::string Hostname;
    std::string IpAddress;
    // PTR RRs can be send by mDNS caches so do not reflect the source IP address of the mDNS packet
    // std::set<std::string> PtrRrs;
    std::string Os;
    std::string Hw;
    std::string DeviceUrl;
    std::string Manufacturer;
    std::string ModelName;

    bool operator == (const MdnsHost &rhs) const {
        return IpAddress == rhs.IpAddress &&
                Hostname == rhs.Hostname &&
                Os == rhs.Os && Hw == rhs.Hw &&
                DeviceUrl == rhs.DeviceUrl &&
                Manufacturer == rhs.Manufacturer &&
                ModelName == rhs.ModelName;
    }
};

struct SsdpHost {
    std::string IpAddress;
    std::string FriendlyName;
    std::string Manufacturer;
    std::string ManufacturerUrl;
    std::string ModelName;
    std::string ModelUrl;
    std::string DeviceType;
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

size_t curlwriteFunction(void *ptr, size_t size, size_t nmemb, std::string* data);


#endif /* NODDOS_H_ */
