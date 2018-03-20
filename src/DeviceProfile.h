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

#include "json.hpp"
using json = nlohmann::json;

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include <glog/logging.h>

#include <syslog.h>
#include <ctime>
#include <cstring>

#include "Identifier.h"
#include "MatchCondition.h"
#include "Ipset.h"


/*! \class DeviceProfile
 *  \brief DeviceProfiles provides the traits of different devices so that hosts can be matched to them
 *  Device Profiles provide the description of the traits of devices. Hosts found on the network
 *  are matched against these traits to identify what product they are
 */
class DeviceProfile {
private:
    std::string DeviceProfileUuid; //!< Unique identifier for the profile
    uint16_t DeviceProfileVersion; //!< Version of the profile, used to track updates and matching against the latest version of the profile
    std::vector<std::shared_ptr<Identifier>> Identifiers; //!< traits of the profile used to identify the device
    bool UploadStats; //!< Should statistics for hosts matching this profile be upoloaded?
    bool Valid; //!< Is this a well-defined profile
    bool withAllowedEndpoints; //!< Does this profile have whitelisted destinations
    std::string DeviceDescription; //!< A friendly name for the device matched by this profile
    bool Debug; //!< Is debugging enabled
    Ipset srcIpset, dstv4Ipset, dstv6Ipset; //!< Ipset groups that will used to filter traffic from matched hosts to their whitelisted destination IP addresses
    std::set<std::string> Hosts;
    std::set<std::string> AllowedFqdns; //!< List of whitelisted destination FQDNs for the devices matching the profile
    // TODO: Make below a map where the value is the TTL for the Allowed IP v4/v6 address
    std::set<Tins::IPv4Address> AllowedIpv4s; //!< List of whitelisted hardcoded destinations with IPv4 addresses for the devices matching the profile
    std::set<Tins::IPv6Address> AllowedIpv6s;//!< List of whitelisted hardcoded destinations with IPv6 addresses for the devices matching the profile

public:
    DeviceProfile(const json &j, const bool inDebug = false):
        Debug{inDebug}, Valid{false}, UploadStats{false}, withAllowedEndpoints{false}, DeviceProfileVersion{0} {
            DLOG_IF(INFO, Debug == true) << "DeviceProfile: constructing instance";
            if (j.find("DeviceProfileUuid") == j.end()) {
                LOG(ERROR) << "No DeviceProfileUuid set, ignoring this Object";
            } else {
                if (! j["DeviceProfileUuid"].is_string()) {
                    LOG(ERROR) << "DeviceProfileUuid is not a string, ignoring this Object";
                } else {
                    DeviceProfileUuid = j["DeviceProfileUuid"];
                    Valid = from_json(j);
                }
            }
        }
        ~DeviceProfile() {
            DLOG_IF(INFO, Debug == true) << "DeviceProfile: Deleting instance";
        }

        bool from_json(const json &j); //!< Parses json to populate DeviceProfile
        std::string getUuid () const { return DeviceProfileUuid; } //!< Get the UUID of the DeviceProfile
        uint8_t getDeviceProfileVersion ()  const { return DeviceProfileVersion; } //!< Get the Version of the DeviceProfile
        bool isValid() const { return Valid; } //!< Does the Device Profile have the required data and was it parsed correctly from JSON
        bool getUploadStats() const { return UploadStats; } //!< Should statistics for hosts matching this DeviceProfile be uploaded
        std::string getDeviceDescription () const { return DeviceDescription; } //!< Get the description of the DeviceProfile

        void createorupdateIpsets (bool inForce = false); //!< Manage the IPset entries for hosts matching this DeviceProfile

        bool hasHosts() { return Hosts.size() > 0; } //!< Have hosts been matched against this DeviceProfile
        bool hasAllowedEndpoints() { return withAllowedEndpoints; } //!< Does this profile have whitelisted destinations

        /*! \brief addHost adds a host matching the DeviceProfile to the DeviceProfile
         *  When a host matches against a DeviceProfile, it gets added to the list of hosts that matched against the DeviceProfile
         *  so that the IPset lists can be updated the next time the DeviceMatch function is run by the createorupdateIPsets member
         *  \param [in] constant MacAddress object for the host
         */
        void addHost (const MacAddress &inMac) {
            Hosts.insert(inMac.str());
            // return srcIpset.Add(inMac);
        }
        /*! \brief removeHost removes a host from the list of hosts matching a DeviceProfile
         *  When a host is removed from the list of hosts matching a Device Profile, for example when it is matched against a different DeviceProfile,
         *  it gets removed from the list of hosts that matched against the DeviceProfile so that the IPset lists can be updated using the createorupdateIpsets
         *  member the next time the DeviceMatch function is run.
         *  \param [in] constant MacAddress object for the host
         */
        void removeHost (const MacAddress inMac) {
            Hosts.erase(inMac.str());
            // return srcIpset.Remove(inMac.str());
        }
        /*! \brief removeHost removes a host from the list of hosts matching a DeviceProfile
         *  When a host is removed from the list of hosts matching a Device Profile, for example when it is matched against a different DeviceProfile,
         *  it gets removed from the list of hosts that matched against the DeviceProfile so that the IPset lists can be updated using the createorupdateIpsets
         *  member the next time the DeviceMatch function is run.
         *  \param [in] constant string with the MacAddress for the host
         */
        void removeHost (const std::string inMac) {
            Hosts.erase(inMac);
            // return srcIpset.Remove(inMac);
        }


        /*! \brief Add a destination to the list of whitelisted destinations for hosts matching the DeviceProfile
         * Add a destination to the list of whitelisted destinations for hosts matching the DeviceProfile. Adding destinations we
         * do immediately as it is based on DNS lookups, which may expire. We also add the IP to the list of AllowedEndpoints in
         * case we don't have any matched hosts yet as we may need the data if later on we match a host to the device profile
         * \param [in] contant Tins::IPv4Address of the destination
         * \param [in] constant Time To Live for the IPset entry, typically matching the DNS Time To Live value
         */
        void addDestination (const Tins::IPv4Address &inIpAddress, const time_t inTtl = 604800) {
            AllowedIpv4s.insert(inIpAddress);
            if (withAllowedEndpoints == true && Hosts.size() > 0) {
                dstv4Ipset.Add(inIpAddress, inTtl);
            }
        }
        /*! \brief Add a destination to the list of whitelisted destinations for hosts matching the DeviceProfile
         * Add a destination to the list of whitelisted destinations for hosts matching the DeviceProfile. Adding destinations we
         * do immediately as it is based on DNS lookups, which may expire. We also add the IP to the list of AllowedEndpoints in
         * case we don't have any matched hosts yet as we may need the data if later on we match a host to the device profile
         * \param [in] contant Tins::IPv6Address of the destination
         * \param [in] constant Time To Live for the IPset entry, typically matching the DNS Time To Live value
         */
        void addDestination (const Tins::IPv6Address &inIpAddress, const time_t inTtl = 604800) {
            AllowedIpv6s.insert(inIpAddress);
            if (withAllowedEndpoints == true && Hosts.size() > 0) {
                dstv6Ipset.Add(inIpAddress, inTtl);
            }
        }
        /*! \brief Add a destination FQDN to the list of whitelisted destination FQDNs for hosts matching the DeviceProfile
         * Add a destination FQDN to the list of whitelisted destination FQDNs for hosts matching the DeviceProfile.
         * \param [in] contant std::string of the destination
         */
        void addDestination (const std::string inFqdn) {
            AllowedFqdns.insert(inFqdn);
        }
        /*! \brief get the listed of whitelisted FQDNs for hosts matching the DeviceProfile
         *  Returns the list of FQDNs which are allowed by the DeviceProfile for hosts matching the DeviceProfile to communicate with
         *  \return std::set<std::string of FQDNs
         */
        std::set<std::string> getDestinations() {
            return AllowedFqdns;
        }

        /*! \brief Get a vector of the Identifier objects for a DeviceProfile
         *  Returns the vector of Identifier objects for a DeviceProfile
         *  \return constant vector of Identifier objects
         */
        const std::vector<std::shared_ptr<Identifier>> & getIdentifiers() const { return Identifiers; }

};

/*! Map of DeviceProfiles identified by their UUID */
typedef std::map<std::string, std::shared_ptr<DeviceProfile>> DeviceProfileMap;

/*! List of FQDNs and the DeviceProfiles that have that FQDN as whitelisted destination */
typedef std::map<std::string,std::set<std::shared_ptr<DeviceProfile>>> FqdnDeviceProfileMap;

#endif /* DEVICEPROFILE_H_ */
