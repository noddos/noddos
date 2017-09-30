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

 * DeviceProfile.h
 *
 *  Created on: Mar 25, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef DEVICEPROFILE_H_
#define DEVICEPROFILE_H_

#include <string>
#include <vector>
#include <set>
#include <utility>
#include <memory>

#include <json.hpp>
using json = nlohmann::json;

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include <syslog.h>
#include <ctime>
#include <cstring>

#include "Identifier.h"
#include "MatchCondition.h"
#include "Ipset.h"



class DeviceProfile {
private:
	std::string DeviceProfileUuid;
	time_t DeviceProfileVersion;
	std::vector<std::shared_ptr<Identifier>> Identifiers;
	bool UploadStats;
	bool Valid;
	bool withAllowedEndpoints;
	std::string DeviceDescription;
	bool Debug;
	Ipset srcIpset, dstv4Ipset, dstv6Ipset;
	std::set<std::string> Hosts;
	std::set<std::string> AllowedFqdns;
	std::set<Tins::IPv4Address> AllowedIpv4s;
    std::set<Tins::IPv6Address> AllowedIpv6s;

public:
	DeviceProfile(const json &j, const bool inDebug = false): Debug{inDebug}, withAllowedEndpoints{false} {
		if (Debug == true) {
		    syslog (LOG_DEBUG, "DeviceProfile: constructing instance");
		}
        DeviceProfileVersion = 0;
        UploadStats = false;
		Valid = false;
		if (j.find("DeviceProfileUuid") == j.end()) {
			syslog(LOG_ERR, "No DeviceProfileUuid set, ignoring this Object");
		} else {
			if (! j["DeviceProfileUuid"].is_string()) {
				syslog(LOG_ERR, "DeviceProfileUuid is not a string, ignoring this Object");
			} else {
				DeviceProfileUuid = j["DeviceProfileUuid"].get<std::string>();
				Valid = from_json(j);
			}
		}
	}
	~DeviceProfile() {
		syslog (LOG_DEBUG, "DeviceProfile: Deleting instance");
	}
    bool from_json(const json &j);
	std::string getUuid () const { return DeviceProfileUuid; }
	time_t getDeviceProfileVersion ()  const { return DeviceProfileVersion; }
	bool isValid() const { return Valid; }
	bool getUploadStats() const { return UploadStats; }
	std::string getDeviceDescription () const { return DeviceDescription; }

	void createorupdateIpsets (bool inForce = false);

	bool hasHosts() { return Hosts.size() > 0; }
	bool hasAllowedEndpoints() { return withAllowedEndpoints; }

	// We only add/remove hosts to the std::set as adding removing hosts only happen
	// when we import DeviceProfileMatches at noddos startup time or when
	// we run the matching algorithm. In both cases we run 'createorupdateIpsets'
	void addHost (const MacAddress &inMac) {
	    Hosts.insert(inMac.str());
	    // return srcIpset.Add(inMac);
	}
    void removeHost (const MacAddress inMac) {
        Hosts.erase(inMac.str());
        // return srcIpset.Remove(inMac.str());
    }
    void removeHost (const std::string inMac) {
        Hosts.erase(inMac);
        // return srcIpset.Remove(inMac);
    }

    // Adding destinations we do immediately as it is based on DNS lookups.
    // We also add the IP to the list of AllowedEndpoints in case we don't have any
    // matched hosts yet but need the data if later on we match a host to the device profile
    void addDestination (const Tins::IPv4Address &inIpAddress, const time_t inTtl = 604800) {
	    AllowedIpv4s.insert(inIpAddress);
	    if (withAllowedEndpoints == true && Hosts.size() > 0) {
	        dstv4Ipset.Add(inIpAddress, inTtl);
	    }
	}
    void addDestination (const Tins::IPv6Address &inIpAddress, const time_t inTtl = 604800) {
        AllowedIpv6s.insert(inIpAddress);
        if (withAllowedEndpoints == true && Hosts.size() > 0) {
            dstv6Ipset.Add(inIpAddress, inTtl);
        }
    }
	void addDestination (const std::string inFqdn) {
	    AllowedFqdns.insert(inFqdn);
	}
    std::set<std::string> getDestinations() {
        return AllowedFqdns;
    }

	const std::vector<std::shared_ptr<Identifier>> & getIdentifiers() const { return Identifiers; }

};



typedef std::map<std::string, std::shared_ptr<DeviceProfile>> DeviceProfileMap;
typedef std::map<std::string,std::set<std::shared_ptr<DeviceProfile>>> FqdnDeviceProfileMap;

#endif /* DEVICEPROFILE_H_ */
