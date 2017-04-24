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
#include <ctime>
#include <memory>
#include <syslog.h>
#include <json.hpp>
using nlohmann::json;

#include <string.h>

#include "Identifier.h"
#include "MatchCondition.h"



class DeviceProfile {
private:
	std::string DeviceProfileUuid;
	time_t LastUpdated;
	std::vector<std::shared_ptr<Identifier>> Identifiers;
	bool UploadStats;
	bool Valid;
	bool Debug;

public:
	DeviceProfile(const json &j, const bool inDebug = false): Debug{inDebug} {
		LastUpdated = 0;
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
		syslog (LOG_DEBUG, "Destroying DeviceProfile instance");
	}

	std::string Uuid_get () const { return DeviceProfileUuid; }
	time_t LastUpdated_get ()  const { return LastUpdated; }
	bool isValid() const { return Valid; }
	bool UploadStats_get() const { return UploadStats; }

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

		syslog(LOG_DEBUG, "Read Device Profile for UUID %s", DeviceProfileUuid.c_str());

		if (j.find("LastUpdated") == j.end()) {
			syslog(LOG_ERR, "No LastUpdated value set, ignoring this Object");
			return false;
		}
		if (! j["LastUpdated"].is_string()) {
			syslog(LOG_ERR, "LastUpdated is not a string, ignoring this Object");
			return false;
		}
	    std::string l = j["LastUpdated"];
		struct tm timeDate;
	    memset(&timeDate,0,sizeof(struct tm));
	    strptime(l.c_str(),"%Y-%m-%d %T", &timeDate);
	    time_t newtime = mktime(&timeDate);

	    if (newtime < LastUpdated) {
	    	syslog(LOG_DEBUG, "Ignoring DeviceProfile as it is older than there is a new one with the same UUID in memory");
			return false;
	    }
	    LastUpdated = newtime;

		if (j.find("UploadStats") == j.end()) {
			syslog(LOG_DEBUG, "No UploadStats value set, defaulting to false");
			UploadStats = false;
		} else if (! j["LastUpdated"].is_string()) {
			syslog(LOG_DEBUG, "UploadStats is not a string, defaulting to false");
			UploadStats = false;
		} else {
			UploadStats = j["UploadStats"];
		}

		Identifiers.clear();

		if (j.find("Identifiers") == j.end()) {
			syslog(LOG_WARNING, "No Identifiers for profile %s so all devices would match this profile, ignoring this Profile", DeviceProfileUuid.c_str());
			return false;
		}
		json ijson = j["Identifiers"];
		if (! ijson.is_array()) {
			syslog(LOG_ERR, "Identifiers is not an array so ignoring this profile %s", DeviceProfileUuid.c_str());
			return false;
		}
		for (json::iterator it = ijson.begin(); it != ijson.end(); ++it ) {
			syslog(LOG_ERR, "Adding Identifier");
			auto i = std::make_shared<Identifier>(*it);
			Identifiers.push_back(i);
		}

		return true;
	}
};

typedef std::map<std::string, std::shared_ptr<DeviceProfile>> DeviceProfileMap;


#endif /* DEVICEPROFILE_H_ */
