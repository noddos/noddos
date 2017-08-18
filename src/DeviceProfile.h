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
using nlohmann::json;

#include <json.hpp>

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
				Valid = from_json(j);
			}
		}
		try {
		    srcIpset.Open(getIpsetName(DeviceProfileUuid, true), "hash:mac", false, true);
		    dstv4Ipset.Open(getIpsetName(DeviceProfileUuid, false), "hash:ip", true, true);
		    dstv6Ipset.Open(getIpsetName(DeviceProfileUuid, false), "hash:ip", false, true);
		} catch (...) {
		}
	}
	~DeviceProfile() {
		syslog (LOG_DEBUG, "DeviceProfile: Deleting instance");
	}

	std::string Uuid_get () const { return DeviceProfileUuid; }
	time_t DeviceProfileVersion_get ()  const { return DeviceProfileVersion; }
	bool isValid() const { return Valid; }
	bool UploadStats_get() const { return UploadStats; }

	bool addHost (MacAddress &inMac) {
	    return srcIpset.Add(inMac);
	}
	void addDestination (boost::asio::ip::address &inIpAddress, time_t inTtl = 604800) {
	    if(inIpAddress.is_v4()) {
	        dstv4Ipset.Add(inIpAddress, inTtl);
	    } else {
            dstv6Ipset.Add(inIpAddress, inTtl);
	    }
	}
	void addDestination (std::string inFqdn) {
	    AllowedFqdns.insert(inFqdn);
	}
	bool removeHost (MacAddress inMac);

	const std::vector<std::shared_ptr<Identifier>> & Identifiers_get() const { return Identifiers; }
	bool from_json(const json &j) {
		if (j.find("DeviceProfileUuid") == j.end()) {
			syslog(LOG_ERR, "No DeviceProfileUuid set, ignoring this Object");
			return false;
		}
		if (! j["DeviceProfileUuid"].is_string()) {
			syslog(LOG_ERR, "DeviceProfileUuid is not a string, ignoring this Object");
			return false;
		}
		if (DeviceProfileUuid != j["DeviceProfileUuid"].get<std::string>())
			return false;

        if (Debug == true) {
            syslog(LOG_DEBUG, "Read Device Profile for UUID %s", DeviceProfileUuid.c_str());
        }

		if (j.find("DeviceProfileVersion") == j.end()) {
			syslog(LOG_ERR, "No DeviceProfileVersion value set, ignoring this Object");
			return false;
		}
		if (! j["DeviceProfileVersion"].is_number()) {
			syslog(LOG_ERR, "DeviceProfile:DeviceProfileVersion is not a number, ignoring this Object");
			return false;
		}
		DeviceProfileVersion = j["DeviceProfileVersion"].get<uint32_t>();

		if (j.find("UploadStats") == j.end()) {
			syslog(LOG_DEBUG, "DeviceProfile:No UploadStats value set, defaulting to false");
			UploadStats = false;
		} else if (! j["UploadStats"].is_boolean()) {
			syslog(LOG_DEBUG, "UDeviceProfile:ploadStats is not a bool, defaulting to false");
			UploadStats = false;
		} else {
			UploadStats = j["UploadStats"].get<bool>();
		}

		Identifiers.clear();

		if (j.find("Identifiers") == j.end()) {
			syslog(LOG_WARNING, "DeviceProfile:No Identifiers for profile %s so all devices would match this profile, ignoring this Profile", DeviceProfileUuid.c_str());
			return false;
		}
		json ijson = j["Identifiers"];
		if (! ijson.is_array()) {
			syslog(LOG_ERR, "DeviceProfile:Identifiers is not an array so ignoring this profile %s", DeviceProfileUuid.c_str());
			return false;
		}
		for (json::iterator it = ijson.begin(); it != ijson.end(); ++it ) {
			syslog(LOG_ERR, "Adding Identifier");
			auto i = std::make_shared<Identifier>(*it);
			Identifiers.push_back(i);
		}

        if (j.find("AllowedEndpoints") == j.end()) {
            syslog(LOG_DEBUG, "DeviceProfile: No whitelist found for profile %s", DeviceProfileUuid.c_str());
        } else {
            json ajson = j["AllowedEndpoints"];
            if (! ijson.is_array()) {
                syslog(LOG_ERR, "DeviceProfile:AllowedEndpoints is not an array so ignoring this profile %s", DeviceProfileUuid.c_str());
                return false;
            }
            for (json::iterator it = ajson.begin(); it != ajson.end(); ++it ) {
                std::string endpoint = it->get<std::string>();
                if (Debug == true) {
                    syslog(LOG_DEBUG, "DeviceProfile: Adding allowed endpoint %s", endpoint.c_str());
                }
                try {
                    boost::asio::ip::address ip = boost::asio::ip::address::from_string(endpoint);
                    if (ip.is_v4()) {
                        dstv4Ipset.Add(ip);
                    } else {
                        dstv6Ipset.Add(ip);
                    }
                } catch (...) {
                    // Boost threw an exception presumably because the string was not an IPv4 or IPv6 address
                    addDestination(endpoint);
                }
            }
        }
        return true;
	}
};

typedef std::map<std::string, std::shared_ptr<DeviceProfile>> DeviceProfileMap;


#endif /* DEVICEPROFILE_H_ */
