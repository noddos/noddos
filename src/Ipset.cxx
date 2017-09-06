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

 * Ipset.cxx
 *
 *  Created on: Aug 9, 2017
 *      Author: Steven Hessing
 */

#include "Ipset.h"
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <fstream>
#include <iterator>


std::string getIpsetUuid (const std::string inUuid) {
    std::string res = "";
    std::stringstream ss;
    ss.str(inUuid);
    std::string item;
    uint8_t count = 0;
    while (std::getline(ss, item, '-')) {
        if (count != 0) {
            res += item;
        }
        count++;
    }
    return res;
}

std::string getIpsetName (const std::string inUuid, bool inSrc, bool inIpv4) {
    std::string res = "Nod";
    if (inSrc == true) {
        res += "src-";
    } else {
        res += "ds";
        if (inIpv4 == false) {
            res += "6-";
        } else {
            res += "4-";
        }
    }
    res += getIpsetUuid(inUuid);
    return res;
}

void Ipset::Open (const std::string inIpsetName, std::string inIpsetType, bool inisIpsetv4, bool inDebug) {
    Debug = inDebug;
    if (Debug == true) {
        syslog (LOG_DEBUG, "Ipset: opening instance %s of type %s", inIpsetName.c_str(), inIpsetType.c_str());
    }
    ipsetName = inIpsetName;
    ipsetType = inIpsetType;
    isIpsetv4 = inisIpsetv4;
    ipset_load_types();

    session = ipset_session_init(printf);
    if (session == nullptr) {
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    if (ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL) < 0) {
        throw std::runtime_error ("Can't set environment option.");
    }
    if (Exists()) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Not creating set %s as it already exists", ipsetName.c_str());
        }
        return;
    }

    uint32_t timeout;

    if (ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str()) < 0) {
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_error(session));
    }
    if (ipset_session_data_set(session, IPSET_OPT_TYPENAME, ipsetType.c_str()) < 0) {
        throw std::runtime_error("Can't set type " + ipsetType + ": " + ipset_session_error(session));
    }
    const struct ipset_type *type = ipset_type_get(session, IPSET_CMD_CREATE);
    if (type == NULL) {
        throw std::runtime_error("Can't create ipset " + ipsetName + ": " + ipset_session_error(session));
    }

    timeout = 0; /* default to infinity */
    if (ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout) < 0) {
        throw std::runtime_error("Can't set time-out " + ipsetName + ": " + ipset_session_error(session));
    }
    if (ipset_session_data_set(session, IPSET_OPT_TYPE, type)) {
        throw std::runtime_error("Can't set ipset type: " + ipsetName + ": " + ipset_session_error(session));
    }
    uint8_t family = 0;
    if (ipsetType == "hash:ip" && isIpsetv4 == true) {
        family = NFPROTO_IPV4;
    } else if (ipsetType == "hash:ip" && isIpsetv4 == false) {
        family = NFPROTO_IPV6;
    } else if (ipsetType == "hash:mac") {
        family = NFPROTO_UNSPEC;
     } else {
        throw std::invalid_argument("Unknown ipset data type " + ipsetType);
    }
    ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);

    if (ipset_session_data_set(session, IPSET_OPT_FAMILY, &family) < 0) {
        throw std::runtime_error("Cannot set ipset family: " + ipsetName + ": " + ipset_session_error(session));
    }

    if (ipset_cmd(session, IPSET_CMD_CREATE, /*lineno*/ 0)) {
        throw std::runtime_error("Failed to create ipset " + ipsetName + ": " + ipset_session_error(session));
    }
    // ipset_commit(session);
    // ipset_data_reset(session->data);
}


bool Ipset::ipset_exec(enum ipset_cmd cmd) {

    if (Debug == true) {
        syslog(LOG_DEBUG, "Ipset: received command %d for ipset %s", cmd, ipsetName.c_str());
    }
    int r = ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str());

    /* The below check actually fails but it doesn't seem to be needed
    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == nullptr) {
         return false;
    }
    */

    r = ipset_cmd(session, cmd, 0);
// The below is from sample Ipset code but does not seem needed.
//    r = ipset_commit(session);
//    ipset_data_reset(session->data);
    return r == 0;
}

bool Ipset::ipset_exec(enum ipset_cmd cmd, const boost::asio::ip::address &inIpAddress, uint32_t timeout) {

    int r = ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str());

    if (Debug == true) {
        syslog(LOG_DEBUG, "Ipset: received command %d for IP address %s for ipset %s", cmd, inIpAddress.to_string().c_str(), ipsetName.c_str());
    }
    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == NULL) {
        std::string e = "Can't get ipset type for command, error: ";
        e.append(ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error(e);
        return false;
    }

    if (inIpAddress.is_v4()) {
        uint8_t family = NFPROTO_IPV4;
        ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);
        struct in_addr sin;
        inet_aton (inIpAddress.to_string().c_str(), &sin);
        r = ipset_session_data_set(session, IPSET_OPT_IP, &sin);
    } else {
        uint8_t family = NFPROTO_IPV6;
        ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);
        unsigned char buf[sizeof(struct in6_addr)];
        int s = inet_pton(AF_INET6, inIpAddress.to_string().c_str(), buf);
        r = ipset_session_data_set(session, IPSET_OPT_IP, &buf);
    }
    if (timeout) {
        r = ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
        if (r != 0) {
            std::string e = "Can't set timeout for " + ipsetName + ", error: " + ipset_session_error(session);
            ipset_session_fini(session);
            throw std::runtime_error(e);
            return false;
        }
    }
    r = ipset_cmd(session, cmd, 0);
    if (r != 0) {
        std::string e = "Can't call ipset_cmd, error: ";
        e.append(ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error(e);
        return false;
    }
// The below is from sample Ipset code but does not seem needed.
//    r = ipset_commit(session);
//    ipset_data_reset(session->data);
    return true;
}

bool Ipset::ipset_exec(enum ipset_cmd cmd, const std::string Mac, uint32_t timeout) {
    if (Debug == true) {
        syslog(LOG_DEBUG, "Ipset: received command %d for MAC address %s for ipset %s", cmd, Mac.c_str(), ipsetName.c_str());
    }
    int r;
    r = ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str());

    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == NULL) {
        std::string e = "Can't get ipset type for command, error: ";
        e.append(ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error(e);
    }
    // ipset_parse_ether(session, IPSET_OPT_ETHER, Mac.c_str());
    // ipset_session_data_set(session, IPSET_OPT_ETHER, Mac.c_str());
    r = ipset_parse_elem(session, (ipset_opt)type->last_elem_optional, Mac.c_str());
    if (r < 0) {
        std::string e = "Can't call ipset_parse_elem, error: ";
        e.append(ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error(e);
        return false;
    }
    if (timeout) {
        r = ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
        if (r != 0) {
            std::string e = "Can't set timeout for " + ipsetName + ", error: " + ipset_session_error(session);
            ipset_session_fini(session);
            throw std::runtime_error(e);
            return false;
        }
    }
    r = ipset_cmd(session, cmd, 0);
    if (r != 0) {
        std::string e = "Can't call ipset_cmd, error: ";
        e.append(ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error(e);
        return false;
    }
// The below is from sample Ipset code but does not seem needed.
//    r = ipset_commit(session);
//    ipset_data_reset(session->data);

    return true;
}



