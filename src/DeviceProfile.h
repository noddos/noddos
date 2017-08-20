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
 *      Author: steven
 */

#ifndef DEVICEPROFILE_H_
#define DEVICEPROFILE_H_

#include <string>
#include <vector>
#include <set>
#include <utility>
#include <memory>
#include <set>

#include <json.hpp>
using json = nlohmann::json;

#include "boost/asio.hpp"

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
	bool Debug;
	Ipset srcIpset, dstv4Ipset, dstv6Ipset;
	std::set<std::string> AllowedFqdns;
	std::set<std::string> Hosts;

public:
	DeviceProfile(const json &j, const bool inDebug = false): Debug{inDebug} {
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
		        try {
		            srcIpset.Open(getIpsetName(DeviceProfileUuid, true), "hash:mac", false, true);
		            dstv4Ipset.Open(getIpsetName(DeviceProfileUuid, false), "hash:ip", true, true);
		            dstv6Ipset.Open(getIpsetName(DeviceProfileUuid, false), "hash:ip", false, true);
		        } catch (...) {
		        }
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

	bool addHost (const MacAddress &inMac) {
	    Hosts.insert(inMac.str());
	    return srcIpset.Add(inMac);
	}
	void addDestination (const boost::asio::ip::address &inIpAddress, const time_t inTtl = 604800) {
	    if(inIpAddress.is_v4()) {
	        dstv4Ipset.Add(inIpAddress, inTtl);
	    } else {
            dstv6Ipset.Add(inIpAddress, inTtl);
	    }
	}
	void addDestination (const std::string inFqdn) {
	    AllowedFqdns.insert(inFqdn);
	}

	std::set<std::string> getDestinations() {
	    return AllowedFqdns;
	}
	bool removeHost (const MacAddress inMac) {
	    Hosts.erase(inMac.str());
	    return srcIpset.Remove(inMac.str());
	}
    bool removeHost (const std::string inMac) {
        Hosts.erase(inMac);
        return srcIpset.Remove(inMac);
    }

	const std::vector<std::shared_ptr<Identifier>> & getIdentifiers() const { return Identifiers; }

};



typedef std::map<std::string, std::shared_ptr<DeviceProfile>> DeviceProfileMap;


#endif /* DEVICEPROFILE_H_ */
