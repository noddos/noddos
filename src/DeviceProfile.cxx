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

 * DeviceProfile.cxx
 *
 *  Created on: Aug 19, 2017
 *      Author: Steven Hessing
 */

#include "DeviceProfile.h"

/*! Creates or updates the IPsets for a Device Profile; the IPset for MAC addresses of hosts identified under the Device Profile
 * the IPset for destination IPv4 addresses and the IPset for destination IPv6 addresses. The latter two may have been listed
 * in the DeviceProfile or may have been resolved through DNS based on the FQDNs listed in the DeviceProfile
 *
 */
void DeviceProfile::createorupdateIpsets (bool inForce) {
    if (inForce || (hasAllowedEndpoints() && Hosts.size() > 0)) {
        try {
            srcIpset.Open(getIpsetName(DeviceProfileUuid, true, false), "hash:mac", false, Debug);
            dstv4Ipset.Open(getIpsetName(DeviceProfileUuid, false, true), "hash:ip", true, Debug);
            dstv6Ipset.Open(getIpsetName(DeviceProfileUuid, false, false), "hash:ip", false, Debug);
        } catch (...) {
        }

        for (auto ip: AllowedIpv4s) {
            dstv4Ipset.Add(ip, 31449600); // TODO: set the TTL based on the TTL of the FQDN instead of 1 year
        }
        for (auto ip: AllowedIpv6s) {
            dstv6Ipset.Add(ip, 31449600); // TODO: set the TTL based on the TTL of the FQDN instead of 1 year
        }
        for (auto host: Hosts) {
            srcIpset.Add(host, 31449600); // 1 year, a host is not expected to change device profile and even if it does, the old entry does no harm
        }
    }
}

/*! Parses JSON object to populate DeviceProfile. The file with JSON objects can be downloaded from https://www.noddos.io/config/DeviceProfiles.json
 */
bool DeviceProfile::from_json(const json &j) {
    if (j.find("DeviceProfileUuid") == j.end()) {
        LOG(ERROR) << "No DeviceProfileUuid set, ignoring this Object";
        return false;
    }
    if (! j["DeviceProfileUuid"].is_string()) {
        LOG(ERROR) << "DeviceProfileUuid is not a string, ignoring this Object";
        return false;
    }
    if (DeviceProfileUuid != j["DeviceProfileUuid"].get<std::string>())
        return false;


    DLOG_IF(INFO, Debug) << "Read Device Profile for UUID " << DeviceProfileUuid;

    if (j.find("DeviceProfileVersion") == j.end()) {
        LOG(ERROR) << "No DeviceProfileVersion value set, ignoring this Object";
        return false;
    }
    if (! j["DeviceProfileVersion"].is_number()) {
        LOG(ERROR) << "DeviceProfile:DeviceProfileVersion is not a number, ignoring this Object";
        return false;
    }
    DeviceProfileVersion = j["DeviceProfileVersion"].get<uint32_t>();

    if (j.find("UploadStats") == j.end()) {
        DLOG_IF(INFO, Debug) << "DeviceProfile:No UploadStats value set, defaulting to false";
        UploadStats = false;
    } else if (! j["UploadStats"].is_boolean()) {
        DLOG_IF(INFO, Debug) <<"UDeviceProfile:UploadStats is not a bool, defaulting to false";
        UploadStats = false;
    } else {
        UploadStats = j["UploadStats"].get<bool>();
    }

    DeviceDescription = "";
    if (j.find("Manufacturer") != j.end() && j["Manufacturer"].is_string()) {
        DeviceDescription = j["Manufacturer"].get<std::string>();
    }
    if (j.find("Model") != j.end() && j["Model"].is_string()) {
        DeviceDescription += j["Model"].get<std::string>();
    }

    Identifiers.clear();

    if (j.find("Identifiers") == j.end()) {
        LOG(WARNING) << "DeviceProfile:No Identifiers for profile " << DeviceProfileUuid << " so all devices would match this profile, ignoring this Profile";
        return false;
    }
    json ijson = j["Identifiers"];
    if (! ijson.is_array()) {
        LOG(ERROR) << "DeviceProfile:Identifiers is not an array so ignoring this profile " << DeviceProfileUuid;
        return false;
    }
    for (json::iterator it = ijson.begin(); it != ijson.end(); ++it ) {
        DLOG_IF(INFO, Debug) << "DeviceProfile: Adding Identifier";
        auto i = std::make_shared<Identifier>(*it);
        Identifiers.push_back(i);
    }

    if (j.find("AllowedEndpoints") == j.end()) {
        DLOG_IF(INFO, Debug) << "DeviceProfile: No whitelist found for profile " << DeviceProfileUuid;
    } else {
        json ajson = j["AllowedEndpoints"];
        if (! ijson.is_array()) {
            LOG(ERROR) << "DeviceProfile:AllowedEndpoints is not an array so ignoring this profile " << DeviceProfileUuid;
            return false;
        }
        for (json::iterator it = ajson.begin(); it != ajson.end(); ++it ) {
            withAllowedEndpoints = true;
            std::string endpoint = it->get<std::string>();
            DLOG_IF(INFO, Debug) << "DeviceProfile: Adding allowed endpoint " << endpoint;
            try {
                if (isIpv4Address(endpoint, Debug)) {
                    Tins::IPv4Address ip(endpoint);
                    AllowedIpv4s.insert(ip);
                } else {
                    Tins::IPv6Address ip(endpoint);
                    AllowedIpv6s.insert(ip);
                }
            } catch (...) {
                addDestination(endpoint);
            }
        }
    }
    return true;
}


