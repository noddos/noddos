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

bool isIpv4Address(const std::string inIpAddress, const bool Debug) {
    unsigned char buf[sizeof(struct in6_addr)];
    if (inet_pton(AF_INET, inIpAddress.c_str(), buf) == 1) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Ipset: %s is an IPv4 address", inIpAddress.c_str());
        }
        return true;
    }
    if (inet_pton(AF_INET6, inIpAddress.c_str(), buf) == 1) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Ipset: %s is an IPv6 address", inIpAddress.c_str());
        }
        return false;
    }
    if (Debug == true) {
        syslog (LOG_DEBUG, "Ipset: %s is not an IPv4/v6 address", inIpAddress.c_str());
    }
    throw std::runtime_error ("Not an IP address " + inIpAddress);
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

    struct ipset_session *session = ipset_session_init(printf);
    if (session == nullptr) {
        syslog (LOG_ERR, "Ipset: Cannot initialize ipset session.");
        ipset_session_fini(session);
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    if (ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set environment option.");
        ipset_session_fini(session);
        throw std::runtime_error ("Can't set environment option.");
    }
    if (Exists()) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Ipset: Not creating set %s as it already exists", ipsetName.c_str());
            // ipset_session_fini(session);
        }
        return;
    }

    uint32_t timeout;

    if (ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str()) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_error(session));
    }
    if (ipset_session_data_set(session, IPSET_OPT_TYPENAME, ipsetType.c_str()) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set setname %s to type %s: %s", ipsetName.c_str(), ipsetType.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set type " + ipsetType + ": " + ipset_session_error(session));
    }
    const struct ipset_type *type = ipset_type_get(session, IPSET_CMD_CREATE);
    if (type == NULL) {
        syslog (LOG_ERR, "Ipset: Can't set create ip %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't create ipset " + ipsetName + ": " + ipset_session_error(session));
    }

    timeout = 0; /* default to infinity */
    if (ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set setname %s to timeout %d: %s", ipsetName.c_str(), timeout, ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set time-out " + ipsetName + ": " + ipset_session_error(session));
    }
    if (ipset_session_data_set(session, IPSET_OPT_TYPE, type)) {
        syslog (LOG_ERR, "Ipset: Can't set setname %s option type: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
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
        ipset_session_fini(session);
        throw std::invalid_argument("Unknown ipset data type " + ipsetType);
    }
    if (ipset_session_data_set(session, IPSET_OPT_FAMILY, &family) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set setname %s address family %d: %s", ipsetName.c_str(), family, ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Cannot set ipset family: " + ipsetName + ": " + ipset_session_error(session));
    }

    if (ipset_cmd(session, IPSET_CMD_CREATE, /*lineno*/ 0) != 0) {
        syslog (LOG_ERR, "Ipset: Can't create setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Failed to create ipset " + ipsetName + ": " + ipset_session_error(session));
    }
    if (ipset_commit(session) < 0) {
        syslog (LOG_ERR, "Ipset: Can't commit for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_error(session));
    }
    // ipset_session_fini(session);
}


bool Ipset::ipset_exec(enum ipset_cmd cmd) {

    if (Debug == true) {
        syslog(LOG_DEBUG, "Ipset: received command %d for ipset %s", cmd, ipsetName.c_str());
    }
    struct ipset_session *session = ipset_session_init(printf);
    if (session == nullptr) {
        syslog (LOG_ERR, "Ipset: Cannot initialize ipset session.");
        ipset_session_fini(session);
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    if (ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set environment option.");
        ipset_session_fini(session);
        throw std::runtime_error ("Can't set environment option.");
    }
    if (ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str()) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_error(session));
    }

    if (ipset_cmd(session, cmd, 0) != 0) {
        ipset_session_fini(session);
        syslog (LOG_ERR, "Ipset: Can't exec ipset cmd for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        throw std::runtime_error("Can't exec ipset cmd for " + ipsetName + ": " + ipset_session_error(session));
    }
    if (ipset_commit(session) < 0) {
        syslog (LOG_ERR, "Ipset: Can't commit for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_error(session));
    }

    return true;
}


bool Ipset::ipset_exec(enum ipset_cmd cmd,  const Tins::IPv4Address &inIpAddress, time_t timeout) {
    if (Debug == true) {
        syslog(LOG_DEBUG, "Ipset: received command %d for IP address %s for ipset %s", cmd, inIpAddress.to_string().c_str(), ipsetName.c_str());
    }
    struct ipset_session *session = ipset_session_init(printf);
    if (session == nullptr) {
        syslog (LOG_ERR, "Ipset: Cannot initialize ipset session.");
        ipset_session_fini(session);
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    if (ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set environment option.");
        ipset_session_fini(session);
        throw std::runtime_error ("Can't set environment option.");
    }
    if (ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str()) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_error(session));
    }
    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == NULL) {
        syslog (LOG_ERR, "Ipset: Can't get type for set %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't get type for set " + ipsetName + ": " + ipset_session_error(session));
    }

    uint8_t family = NFPROTO_IPV4;
    if (ipset_session_data_set(session, IPSET_OPT_FAMILY, &family) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set session data to IPv4 family for set %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set session data for " + ipsetName + " to the IPv4 family, error: " + ipset_session_error(session));
    }
    struct in_addr sin;
    inet_aton (inIpAddress.to_string().c_str(), &sin);
    if (ipset_session_data_set(session, IPSET_OPT_IP, &sin) < 0) {
        syslog (LOG_ERR, "Can't set session data to the IPv4 address for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set session data to the IPv4 address for setname " + ipsetName + ", error: " + ipset_session_error(session));
    }

    if (timeout) {
        if (ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout) != 0) {
            syslog (LOG_ERR, "Ipset: Can't set timeout for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
            ipset_session_fini(session);
            throw std::runtime_error("Can't set timeout for " + ipsetName + ": " + ipset_session_error(session));
            return false;
        }
    }
    if (ipset_cmd(session, cmd, 0) != 0) {
        ipset_session_fini(session);
        syslog (LOG_ERR, "Ipset: Can't exec ipset cmd for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        throw std::runtime_error("Can't exec ipset cmd for " + ipsetName + ": " + ipset_session_error(session));
    }
    if (ipset_commit(session) < 0) {
        syslog (LOG_ERR, "Ipset: Can't commit for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_error(session));
    }
    return true;
}

bool Ipset::ipset_exec(enum ipset_cmd cmd,  const Tins::IPv6Address &inIpAddress, time_t timeout) {
    if (Debug == true) {
        syslog(LOG_DEBUG, "Ipset: received command %d for IP address %s for ipset %s", cmd, inIpAddress.to_string().c_str(), ipsetName.c_str());
    }
    struct ipset_session *session = ipset_session_init(printf);
    if (session == nullptr) {
        syslog (LOG_ERR, "Ipset: Cannot initialize ipset session.");
        ipset_session_fini(session);
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    if (ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set environment option.");
        ipset_session_fini(session);
        throw std::runtime_error ("Can't set environment option.");
    }
    if (ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str()) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_error(session));
    }
    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == NULL) {
        syslog (LOG_ERR, "Ipset: Can't get type for set %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't get type for set " + ipsetName + ": " + ipset_session_error(session));
    }

    uint8_t family = NFPROTO_IPV6;
    if (ipset_session_data_set(session, IPSET_OPT_FAMILY, &family) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set session data to IPv6 family for set %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set session data for " + ipsetName + " to the IPv6 family, error: " + ipset_session_error(session));
    }

    unsigned char buf[sizeof(struct in6_addr)];
    int s = inet_pton(AF_INET6, inIpAddress.to_string().c_str(), buf);
    if (ipset_session_data_set(session, IPSET_OPT_IP, &buf) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set session data to the IPv4 address for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set session data to the IPv4 address for setname " + ipsetName + ", error: " + ipset_session_error(session));
    }

    if (timeout) {
        if (ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout) != 0) {
            syslog (LOG_ERR, "Ipset: Can't set timeout for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
            ipset_session_fini(session);
            throw std::runtime_error("Can't set timeout for " + ipsetName + ": " + ipset_session_error(session));
            return false;
        }
    }
    if (ipset_cmd(session, cmd, 0) != 0) {
        ipset_session_fini(session);
        syslog (LOG_ERR, "Ipset: Can't exec ipset cmd for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        throw std::runtime_error("Can't exec ipset cmd for " + ipsetName + ": " + ipset_session_error(session));
    }
    if (ipset_commit(session) < 0) {
        syslog (LOG_ERR, "Ipset: Can't commit for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_error(session));
    }
    return true;
}

bool Ipset::ipset_exec(enum ipset_cmd cmd, const std::string Mac, time_t timeout) {
    if (Debug == true) {
        syslog(LOG_DEBUG, "Ipset: received command %d for MAC address %s for ipset %s", cmd, Mac.c_str(), ipsetName.c_str());
    }
    struct ipset_session *session = ipset_session_init(printf);
    if (session == nullptr) {
        syslog (LOG_ERR, "Ipset: Cannot initialize ipset session.");
        ipset_session_fini(session);
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    if (ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set environment option.");
        ipset_session_fini(session);
        throw std::runtime_error ("Can't set environment option.");
    }
    if (ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str()) < 0) {
        syslog (LOG_ERR, "Ipset: Can't set setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_error(session));
    }
    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == NULL) {
        syslog (LOG_ERR, "Ipset: Can't get type for set %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't get type for set " + ipsetName + ": " + ipset_session_error(session));
    }
    if (ipset_parse_elem(session, (ipset_opt)type->last_elem_optional, Mac.c_str()) < 0) {
        syslog (LOG_ERR, "Ipset: Can't call ipset_parse_elem for %s: %s ", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_parse_elem for ipset " + ipsetName + ": " + ipset_session_error(session));
    }
    if (timeout) {
        if (ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout) != 0) {
            syslog (LOG_ERR, "Ipset: Can't set timeout for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
            ipset_session_fini(session);
            throw std::runtime_error("Can't set timeout for " + ipsetName + ": " + ipset_session_error(session));
            return false;
        }
    }
    if (ipset_cmd(session, cmd, 0) != 0) {
        ipset_session_fini(session);
        syslog (LOG_ERR, "Ipset: Can't exec ipset cmd for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        throw std::runtime_error("Can't exec ipset cmd for " + ipsetName + ": " + ipset_session_error(session));
    }
    if (ipset_commit(session) < 0) {
        syslog (LOG_ERR, "Ipset: Can't commit for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_error(session));
    }
    return true;
}



