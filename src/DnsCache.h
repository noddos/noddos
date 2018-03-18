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

 * DnsCache.h
 *
 *  Created on: Jun 3, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef DNSCACHE_H_
#define DNSCACHE_H_

#include <map>
#include <vector>
#include <unordered_set>
#include <set>
#include "syslog.h"

#include "json.hpp"
using nlohmann::json;

#include <glog/logging.h>

#include "DeviceProfile.h"

/* This doesn't work because with the templating, we can't return the list of FQDNs that have been deleted
 * and we need that in HostCache to update the Fqdn-to-DeviceProfile map
 *

template <class U, class V>
size_t pruneDnsCache (std::map<U, std::map<V, time_t>> &cache, bool Force = false, bool Debug = false) {
    size_t PrunedFqdns = 0;
    auto now = time(nullptr);
    auto it_resource = cache.begin();
    while (it_resource != cache.end()) {
        auto it_record = it_resource->second.begin();
        while (it_record != it_resource->second.end()) {
            if (Force || now > (it_record->second + 1)) {
                if (Debug == true) {
                 //   syslog(LOG_DEBUG, "pruneDnsCache: pruning %s pointing to %s with expiration %lu while now is %lu",
                 //           it_resource->first.to_str().c_str(), it_record->first.to_string().c_str(), it_record->second, now);
                }
                it_record = it_resource->second.erase(it_record);
            } else {
                it_record++;
            }
        }
        if (Force || it_resource->second.empty()) {
            if (Debug == true) {
                // syslog(LOG_DEBUG, "pruneDnsCache: Removing record for %s as there is no data left", it_resource->first.to_string.c_str());
            }
            PrunedFqdns++;
            it_resource = cache.erase(it_resource);
            if (Debug == true) {
                syslog(LOG_DEBUG, "pruneDnsCache: Deleted record");
            }
        } else {
            it_resource++;
        }
    }
    return PrunedFqdns;
}
 */

/*! \tclass template of DnsCache
 *  \brief Class of DNS records pointing to objects of type T
 *
 *  This class can store A, AAAA and CNAME records. A specialized class for <std::string> is available for the latter
 *  A records use <Tins::IPv4Address>, AAAA records use <Tins::IPv6Address>. The cache maintains both forward and
 *  reverse mappings so you can find both all IP addresses for an FQDN as well as all the FQDNs that have a specific
 *  A record.
 *  \tparam Tins::IPv4Address or Tins::IPv6Address
 */
template <class T>
class DnsCache {
private:
    std::map<std::string, std::map<T,time_t>> DnsFwdCache; //!< Stores mappings from FQDN to object T
    std::map<T, std::map<std::string,time_t>> DnsRevCache; //!< Stores mappings from object T to FQDN
    bool Debug; //!< Debug logging enable?
    time_t MinTtl; //!< Minimum time to keep DNS records in the cache

public:
    /*! \brief constructor for DnsCache
     *
     * DnsCache constructor
     * \param inMinTtl a constant time_t specifying minimum time objects should stay in the cache
     * \param inDebug a constant bool specifying whether to enable debug logging
     */
    DnsCache(const time_t inMinTtl = 14400, const bool inDebug=false): MinTtl{inMinTtl}, Debug{inDebug} {
        DLOG_IF(INFO, Debug) << "DnsIpCache: constructing instance";
    };
    ~DnsCache() {
        DLOG_IF(INFO, Debug) << "DnsIpCache: destructing instance";
    };

    /*! \brief Set debug logging
     * Set Debug level
     * \param inDebug a bool specifying whether to enable debug logging
     */
    void setDebug (const bool inDebug) {
        Debug = inDebug;
    }
    /*! \brief Set minimum TTL for cached entries
     * \param inMinTtl  a time_t constant specifying the minimum Time-To-Live in seconds
     *
     */
    void setMinTtl (const bool inMinTtl = 14400) {
        MinTtl = inMinTtl;
    }

    /*! \brief Look up resource record for an FQDN
     * Find the resource record pointing to object T for the Fully Qualified Domain Name
     * \param inFqdn a constant string specifying the Fully Qualified Domain Name to look up
     * \return map with resource records and their TTL
     */
    std::map<T, time_t> lookupResourceRecord (const std::string inFqdn) {
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        auto it = DnsFwdCache.find(fqdn);
        if (it == DnsFwdCache.end()) {
            throw std::runtime_error("No resource record found for " + inFqdn);
        }
        return it->second;
    }

    /*! \brief Add or Update Resource Record including its potential entry in a Device Profile Map for FQDNs
     * This function checks whether a Device Profile has the FQDN listed. If so, it adds/updates the Resource Record in the Device
     * Profile Map entry. In any case, it adds/updates the DNS Cache entry for the FQDN
     * \param [in] inFQDN a constant string of the Fully Qualified Domain Name for the cache entry
     * \param [in] inIpAddress a constant IPv4 or IPv6 address for the cache entry
     * \param fdpMap a reference to a FQDN Device Profile Map
     * \param [in] inTtl a constant time_t specifying the Time To Live of the cache entry
     */
    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, FqdnDeviceProfileMap &fdpMap, const time_t inTtl = 604800) {
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        auto fdp_it = fdpMap.find(fqdn);
        if (fdp_it != fdpMap.end()) {
            DLOG_IF(INFO, Debug) << "DnsCache: Updating resource record with FqdnDeviceProfileMap entry for " << inFqdn;
            addorupdateResourceRecord (fqdn, inIpAddress, fdp_it, inTtl);
        } else {
            DLOG_IF(INFO, Debug) << "DnsCache: Didn't find FqdnDeviceProfileMap entry for " << inFqdn;
        }
        addorupdateResourceRecord (fqdn, inIpAddress, inTtl);
    }

    /*! \brief Add or Update Resource Record including its entry in a Device Profile Map for FQDNs
     * This function updates the Resource Record in the Device Profile Map entry. It adds or updates the DNS Cache
     * entry for the FQDN.
     * \param [in] inFQDN a constant string of the Fully Qualified Domain Name for the cache entry
     * \param [in] inIpAddress a constant IPv4 or IPv6 address for the cache entry
     * \param fdpMap_iterator an iterator to a FQDN Device Profile Map entry
     * \param [in] inTtl a constant time_t specifying the Time To Live of the cache entry
     */
    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, FqdnDeviceProfileMap::iterator &fdp_it, const time_t inTtl) {
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        for (auto DeviceProfile_sharedpointer_it: fdp_it->second) {
            DLOG_IF(INFO, Debug) << "DnsCache: Found FqdnDeviceProfileMap entry with UUID " <<
                    DeviceProfile_sharedpointer_it->getUuid() << " for " << inFqdn <<
                    " with IP " << inIpAddress;
            DeviceProfile_sharedpointer_it->addDestination(inIpAddress, inTtl);
        }
    }

    /*! \brief Add or Update Resource Record including its entry in a Device Profile Map for FQDNs
     * This function updates the Resource Record in the Device Profile Map entry. It adds or updates the DNS Cache
     * entry for the FQDN.
     * \param [in] inFQDN a constant string of the Fully Qualified Domain Name for the cache entry
     * \param [in] inIpAddress a constant IPv4 or IPv6 address for the cache entry
     * \param fdpMap_iterator an iterator to a FQDN Device Profile Map entry
     * \param [in] inTtl a constant time_t specifying the Time To Live of the cache entry
     */
    void addorupdateResourceRecord (const std::string inFqdn, const T inIpAddress, time_t inTtl) {
        // We need to keep DNS records at least 4 hours as that is our maximum matching interval
        auto now = time(nullptr);
        if (inTtl < MinTtl) {
            inTtl = MinTtl;
        }
        time_t Expiration = now + inTtl;

        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        DLOG_IF(INFO, Debug) << "DnsCache: Adding resource record for " << inFqdn << " with IP " << inIpAddress << " with TTL " << Expiration;
        DnsFwdCache[inFqdn].insert(std::make_pair(inIpAddress, Expiration));
        DnsRevCache[inIpAddress].insert(std::make_pair(inFqdn, Expiration));
    }

    /*! \brief Imports DNS records from a JSON object as written by DnsCache::exportJson
      * This function imports IP records from the JSON file as written by the DnsCache::exportJson method.
      * \param [in] reference to json object with DNS records
      * \param fdpMap reference to a FqdnDeviceProfileMap
      * \return Number of DNS records imported
      */
    size_t importJson (json &j, FqdnDeviceProfileMap &fdpMap) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCache: importing json");
        }
        size_t dnsRecords = 0;
        auto cj = j.find("AddressRecords");
        if (cj == j.end()) {
            return true;
        }
        if (not cj->is_object()) {
            return true;
        }
        for (json::iterator it = cj->begin(); it != cj->end(); ++it) {
            std::string fqdn = it.key();
            auto fdp_it = fdpMap.find(fqdn);
            json ipj = it.value();
            for (json::iterator ip_it = ipj.begin(); ip_it != ipj.end(); ++ip_it) {
                try {
                    T IpAddress = T(ip_it.key());
                    dnsRecords++;

                    time_t expiration = ip_it.value();
                    if (fdp_it != fdpMap.end()) {
                        addorupdateResourceRecord (fqdn, IpAddress, fdp_it, expiration);
                    } else {
                        addorupdateResourceRecord (fqdn, IpAddress, expiration);
                    }
                } catch (...) {
                    // Must be either IPv4 address while IPv6 template or vice versa
                    // Exceptions are expected here as value can also be a CNAME
                    DLOG_IF(INFO, Debug) << "DnsCache: Record " << fqdn << " has value " << ip_it.key() << " which is neither an IPv4 or IPv6 address";
                }
            }
        }
        return dnsRecords;
    }

    /*! \brief Exports DNS records to a JSON object
      * This function exports IPv4 and IPv6 records from the JSON object
      * \param [out] reference to json object to store DNS records
      * \return number of DNS records exported
      */
    size_t exportJson(json &j) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "DnsCache: export to json");
        }
        size_t dnsRecords = 0;
        j["AddressRecords"] = json::object();
        for (auto it_resource: DnsFwdCache) {
            dnsRecords++;
            j["AddressRecords"][it_resource.first] = json::object();
            for (auto it_record: it_resource.second) {
                std::string ip = it_record.first.to_string();
                time_t ttl = it_record.second;
                j["AddressRecords"][it_resource.first][ip] = ttl;
            }

        }

        return dnsRecords;
    }

    /*! \brief Gets all the FQDNs that have an A or AAAA record to the IP address,
      * This function returns all the FQDNs that have an A or AAAA record to the IP address.
      * \param [in] IPv4 or IPv6 address
      * \return vector of strings with Fqdns
      */
    std::vector<std::string> getAllFqdns  (T const inIpAddress) const {
        std::vector<std::string> fqdns;
        std::string ipstring = inIpAddress.to_string();
        auto it = DnsRevCache.find(inIpAddress);
        if (it != DnsRevCache.end()) {
            const std::map<std::string,time_t> &m = it->second;
            for (auto itf : m) {
                if (Debug == true) {
                    syslog (LOG_DEBUG, "DnsCache: AllFqdns adding %s", itf.first.c_str());
                }
                fqdns.push_back(itf.first);
            }
        } else {
            if (Debug == true) {
                syslog(LOG_DEBUG, "DnsIpCache: couldn't find DNS mappings for %s", ipstring.c_str());
            }
        }
        return fqdns;
    }

    /*
    size_t pruneResourceRecords (const bool Force) {
        size_t PrunedFqdns = pruneDnsCache(DnsFwdCache, Force, Debug);
        PrunedFqdns += pruneDnsCache(DnsRevCache, Force, Debug);
        return PrunedFqdns;
    }
    */

    /*! \brief Removes expired DNS A or AAAA records from the DNS cache
      * This function removes all DNS A or AAAA records whose TTLs have expired.
      * \param [in] boolean specifying whether expired or all records have to be pruned
      * \return vector of strings with Fqdns that have been pruned
      */
    std::set<std::string> pruneResourceRecords (const bool Force) {
        std::set<std::string> PrunedFqdns;
        auto now = time(nullptr);
        {
            auto it_resource = DnsFwdCache.begin();
            while (it_resource != DnsFwdCache.end()) {
                auto it_record = it_resource->second.begin();
                while (it_record != it_resource->second.end()) {
                    if (Force || now > (it_record->second + 1)) {
                        DLOG_IF(INFO, Debug) << "DnsCache: pruning " << it_resource->first <<
                                " pointing to " << it_record->first << " with expiration " <<
                                it_record->second << " while now is " << now;
                        it_record = it_resource->second.erase(it_record);
                    } else {
                        it_record++;
                    }
                }
                if (Force || it_resource->second.empty()) {
                    DLOG_IF(INFO, Debug) << "DnsCache: Removing record for " << it_resource->first << " as there is no data left";
                    PrunedFqdns.insert(it_resource->first);
                    it_resource = DnsFwdCache.erase(it_resource);
                    DLOG_IF(INFO, Debug) << "DnsCache: Deleted record";

                } else {
                    it_resource++;
                }
            }
        }
        {
            auto it_resource = DnsRevCache.begin();
            while (it_resource != DnsRevCache.end()) {
                auto it_record = it_resource->second.begin();
                while (it_record != it_resource->second.end()) {
                    if (Force || now > (it_record->second + 1)) {
                        DLOG_IF(INFO, Debug) << "DnsCache: pruning entry " << it_resource->first <<
                                " pointing to " << it_record->first << " with expiration " <<
                                it_record->second << " while now is " << now;
                        it_record = it_resource->second.erase(it_record);
                    } else {
                        it_record++;
                    }
                }
                if (Force || it_resource->second.empty()) {
                    DLOG_IF(INFO, Debug) << "DnsCache: Removing record as there is no data left";

                    it_resource = DnsRevCache.erase(it_resource);
                    DLOG_IF(INFO, Debug) << "DnsCache: Deleted record";
                } else {
                    it_resource++;
                }
            }
        }
        return PrunedFqdns;
    }
};

/*! \tclass specialization of class template DnsCache
 *  \brief Class of DNS CNAMEs
 *
 *  This specialized class template can store  CNAME records. The cache maintains both forward and
 *  reverse mappings so you can find both CNAMEs for an FQDN and all FQDNS that have a CNAME to a FQDN
 */
template<>
class DnsCache <std::string> {
private:
    std::map<std::string,std::map<std::string,time_t>> DnsFwdCache; /// Stores CNAME mappings
    std::map<std::string,std::map<std::string,time_t>> DnsRevCache; //// Stores mappings from the CNAME FQDN to the FQDN with the CNAME record
    time_t MinTtl; /// Minimum TTL for any record
    bool Debug; /// Whether to output Debug logging

public:
    /*! \brief constructor for DnsCache
     *
     * DnsCache constructor
     * \param inMinTtl a constant time_t specifying minimum time objects should stay in the cache
     * \param inDebug a constant bool specifying whether to enable debug logging
     */    DnsCache(const time_t inMinTtl = 14400, const bool inDebug=false): MinTtl{inMinTtl}, Debug{inDebug} {
        DLOG_IF(INFO, Debug) << "DnsCnameCache: constructing instance";
    };
    ~DnsCache() {
        DLOG_IF(INFO, Debug) << "DnsCnameCache: deleting instance";
    };

    /*! \brief Set debug logging
     * Set Debug level
     * \param inDebug a bool specifying whether to enable debug logging
     */
    void setDebug (bool inDebug) {
        Debug = inDebug;
    }
    /*! \brief Set minimum TTL for cached entries
     * \param inMinTtl  a time_t constant specifying the minimum Time-To-Live in seconds
     *
     */
    void setMinTtl (bool inMinTtl = 14400) {
        MinTtl = inMinTtl;
    }

    /*! \brief Add or update CNAME
     * Adds the CNAME record for an FQDN
     * \param [in] inFqdn a constant string specifying the Fully Qualified Domain Name to add
     * \param [in] inCname a constant string specifying the CNAME record
     * \param [in] inTtl a time_t specifying the Time To Live for the DNS record
     * \return bool whether the record was added
     */
    bool addorupdateCname (const std::string inFqdn, const std::string inCname,  time_t inTtl) {
        auto now = time(nullptr);
        if (inTtl < MinTtl) {
            inTtl = MinTtl;
        }
        time_t Expiration = now + inTtl;

        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        std::string cname = inCname;
        std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

        DLOG_IF(INFO, Debug) << "DnsCnameCache: Setting " << fqdn << " to CNAME " << cname << " with expiration " << Expiration;

        bool fqdnAdded = (DnsFwdCache.find(fqdn) == DnsFwdCache.end());
        DnsRevCache[cname][fqdn] = Expiration;
        DnsFwdCache[fqdn][cname] = Expiration;
        return fqdnAdded;
    }

    /*! \brief Add or update CNAME
     * Adds the DNS lookup for a FQDN that resulted in a CNAME. If the FQDN is in the FQDN-to-DeviceProfile map then
     * copy that entry for the CNAME so that the CNAME is also associated with the Device Profiles.
     * \param [in] inFqdn a constant string specifying the Fully Qualified Domain Name to add
     * \param [in] inCname a constant string specifying the CNAME record
     * \param [in/out] fdpMap reference to a FQDN to Device Profile Map
     * \param [in] inTtl a time_t specifying the Time To Live for the DNS record
     * \return bool whether the record was added
     * \sa addorupdateCname(const std::string inFqdn, const std::string inCname, const time_t inTtl), FqdnDeviceProfileMap, DnsCache
     */
    bool addorupdateCname (const std::string inFqdn, const std::string inCname, FqdnDeviceProfileMap &fdpMap, const time_t inTtl) {
        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        std::string cname = inCname;
        std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

        // If the FQDN is in the DeviceProfileMap with then we want to create another
        // DeviceProfileMap entry for the CNAME with the same data as for the FQDN
        auto it = fdpMap.find(fqdn);
        if (it != fdpMap.end()) {
            DLOG_IF(INFO, Debug) << "DnsCnameCache: Found FqdnDeviceProfileMap entry for " << inFqdn << " with CNAME " << inCname << ", so copying its data";
            fdpMap[cname].insert(it->second.begin(), it->second.end());
        } else {
            DLOG_IF(INFO, Debug) << "DnsCnameCache: Didn't find FqdnDeviceProfileMap entry for " << inFqdn << " with CNAME " << inCname;
        }
        return addorupdateCname(fqdn, cname, inTtl);
    }


    /*! \brief Find the FQDNs that have a CNAME record to the FQDN, either directly or indirectly
     * Find the FQDNs that have a CNAME record to the FQDN, either directly or indirectly when a FQDN has a CNAME to an FQDN
     * that has a CNAME to the FQDN. This is recursive to catch CNAMEs to CNAMEs to CNAMEs etc.
     * \param [in] inCname a constant string specifying the Fully Qualified Domain Name for which to find FQDNs that have a CNAME to it
     * \param [in] recdepth an optional constant uint8_t specifying the depth of the recursion. This is a safety valve against CNAMEs that
     * directly or indirectly point back to the original FQDN
     * \return bool whether the record was added
     * \sa addorupdateCname(const std::string inFqdn, const std::string inCname, FqdnDeviceProfileMap &fdpMap,const time_t inTtl), FqdnDeviceProfileMap, DnsCache
     */
    std::set<std::string> getFqdns (const std::string inCname, const uint8_t recdepth = 0) const {
        if (recdepth > 5) {
            DLOG_IF(INFO, Debug) << "DnsCnameCache: Reached max recursion depth for CNAME " << inCname;
            throw std::runtime_error("DNS reverse CNAME recursion depth reached for " + inCname);
        }
        DLOG_IF(INFO, Debug) << "DnsCnameCache: Resolving CNAME " << inCname;

        std::string cname = inCname;
        std::transform(cname.begin(), cname.end(), cname.begin(), ::tolower);

        std::set<std::string> fqdns;
        auto it = DnsRevCache.find(cname);
        if (it != DnsRevCache.end()) {
            DLOG_IF(INFO, Debug) << "DnsCnameCache: Found one or more reverse CNAME for " << cname;
            for (auto fqdn_it: it->second) {
                fqdns.insert(fqdn_it.first);
                std::set<std::string> additional_fqdns = getFqdns(fqdn_it.first, recdepth + 1);
                fqdns.insert(additional_fqdns.begin(),additional_fqdns.end());
            }
        }
        return fqdns;
    }

    /*! \brief Find the FQDNs for which the provided FQDN has a CNAME record, either directly or indirectly
     * Find the FQDNs for which the provided FQDN has a CNAME record, either directly or indirectly when the FQDN has a CNAME to an FQDN
     * that also has a CNAME record. This is recursive to catch CNAMEs to CNAMEs to CNAMEs etc.
     * \param [in] inFqdn a constant string specifying the Fully Qualified Domain Name for which to find the CNAME records
     * \param [in] recdepth an optional constant uint8_t specifying the depth of the recursion. This is a safety valve against CNAMEs that directly or indirectly
     * point back to the original FQDN
     */
    std::set<std::string> getCnames (const std::string inFqdn, const uint8_t recdepth = 0) {
        if (recdepth > 5) {
            DLOG_IF(INFO, Debug) << "DnsCnameCache: Reached max recursion depth for FQDN " << inFqdn;
            throw std::runtime_error("DNS CNAME recursion depth reached for " + inFqdn);
        }
        DLOG_IF(INFO, Debug) << "DnsCnameCache: Looking up CNAMEs for " << inFqdn;

        std::string fqdn = inFqdn;
        std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

        auto it = DnsFwdCache.find(fqdn);
        if (it == DnsFwdCache.end()) {
            DLOG_IF(INFO, Debug) << "DnsCnameCache: " << inFqdn << " does not have a CNAME";
            throw std::runtime_error("No CNAME found for " + inFqdn);
        }
        DLOG_IF(INFO, Debug) << "DnsCnameCache: Found one or more CNAME for " << fqdn;
        std::set<std::string> cnames;
        for (auto cname_it: it->second) {
                cnames.insert(cname_it.first);
                std::set<std::string> additional_cnames;
                try {
                    additional_cnames = getCnames(cname_it.first, recdepth + 1);
                }
                catch (const std::runtime_error &e) {

                }
                cnames.insert(additional_cnames.begin(),additional_cnames.end());
        }
        return cnames;
    }

    /*! \brief Imports DNS records from a JSON object as written by DnsCache::exportJson
       * This function imports CNAME records from the JSON file as written by the DnsCache::exportJson method.
       * \param [in] reference to json object with DNS records
       * \param fdpMap reference to a FqdnDeviceProfileMap
       * \return Number of DNS records imported
       */
    size_t importJson (json &j, FqdnDeviceProfileMap &fdpMap) {
        DLOG_IF(INFO, Debug) << "DnsCnameCache: importing json with cnames";
        size_t dnsRecords = 0;
        auto cj = j.find("CnameRecords");
        if (cj == j.end()) {
            return true;
        }
        if (not cj->is_object()) {
            return true;
        }
        for (json::iterator it = cj->begin(); it != cj->end(); ++it) {
            std::string fqdn = it.key();
            json v = it.value();
            if (v.is_object() == true) {
                for (json::iterator c_it = it->begin(); c_it != it->end(); ++c_it) {
                    dnsRecords++;
                    std::string cname = c_it.key();
                    time_t expiration = c_it.value();
                    auto fdp_it = fdpMap.find(fqdn);
                    if (fdp_it != fdpMap.end()) {
                        addorupdateCname (fqdn, cname, fdpMap, expiration);
                    } else {
                        addorupdateCname (fqdn, cname, expiration);
                    }
                }
            }
        }
        return dnsRecords;
    }

    /*! \brief Exports DNS records to a JSON object
      * This function exports CNAME records to a JSON object
      * \param [out] reference to json object to store DNS records
      * \return number of DNS records exported
      */
    size_t exportJson (json &j) {
        DLOG_IF(INFO, Debug) << "DnsCnameCache: exporting cnames to json";
        size_t dnsRecords = 0;
        j["CnameRecords"] = json::object();
        for (auto it_resource: DnsFwdCache) {
            dnsRecords++;
            j["CnameRecords"][it_resource.first]= json::object();
            for (auto it_cname: it_resource.second) {
                j["CnameRecords"][it_resource.first][it_cname.first] = it_cname.second;
            }
        }
        return dnsRecords;
    }

    /*! \brief Removes expired DNS CNAME records from the DNS cache
      * This function removes all DNS CNAME records whose TTLs have expired.
      * \param [in] boolean specifying whether expired or all records have to be pruned
      * \return vector of strings with Fqdns that have been pruned
      */
    std::set<std::string> pruneCnames (const bool Force) {
        DLOG_IF(INFO, Debug) << "DnsCnameCache: pruning cnames";
        std::set<std::string> PrunedFqdns;
        auto now = time(nullptr);
        {
            auto it = DnsFwdCache.begin();
            while (it != DnsFwdCache.end()) {
                std::string Fqdn = it->first;
                std::map <std::string,time_t> &CnameMap = it->second;
                bool RecordsKept = false;
                bool Pruned = false;
                auto cname_it = CnameMap.begin();
                while(cname_it != CnameMap.end()) {
                    if (Force || now > cname_it->second) {
                        DLOG_IF(INFO, Debug) << "Deleting CNAME for " << Fqdn << " pointing to " <<
                                cname_it->first << " with TTL " << cname_it->second;
                        Pruned = true;
                        cname_it = CnameMap.erase(cname_it);
                    } else {
                        cname_it++;
                        RecordsKept = true;
                    }
                }
                if (Pruned == true) {
                    PrunedFqdns.insert(it->first);
                }
                if (RecordsKept == false) {
                    it = DnsFwdCache.erase(it);
                } else {
                    it++;
                }
            }
        }
        {
            auto it_rev = DnsRevCache.begin();
            while (it_rev != DnsRevCache.end()) {
                std::string Cname = it_rev->first;
                std::map <std::string,time_t> &FqdnMap = it_rev->second;
                bool RecordsKept = false;
                bool Pruned = false;
                auto fqdn_it = FqdnMap.begin();
                while(fqdn_it != FqdnMap.end()) {
                    if (Force || now > fqdn_it->second) {
                        DLOG_IF(INFO, Debug) << "Deleting reverse CNAME for " << Cname << " pointing to " <<
                                fqdn_it->first << " with TTL " << fqdn_it->second;
                        Pruned = true;
                        fqdn_it = FqdnMap.erase(fqdn_it);
                    } else {
                        fqdn_it++;
                        RecordsKept = true;
                    }
                }
                if (Pruned == true) {
                    PrunedFqdns.insert(it_rev->first);
                }
                if (RecordsKept == false) {
                    it_rev = DnsRevCache.erase(it_rev);
                } else {
                    it_rev++;
                }
            }
        }
        return PrunedFqdns;
    }
};

#endif /* DNSCACHE_H_ */
