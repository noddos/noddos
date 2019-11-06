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

#include <glog/logging.h>

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
            DLOG_IF(INFO, Debug) << "" << inIpAddress << " is an IPv4 address";
        }
        return true;
    }
    if (inet_pton(AF_INET6, inIpAddress.c_str(), buf) == 1) {
        if (Debug == true) {
            DLOG_IF(INFO, Debug) << "" << inIpAddress << " is an IPv6 address";
        }
        return false;
    }
    if (Debug == true) {
        DLOG_IF(INFO, Debug) << "" << inIpAddress << " is not an IPv4/v6 address";
    }
    throw std::runtime_error ("Not an IP address " + inIpAddress);
}

void Ipset::Open (const std::string inIpsetName, std::string inIpsetType, bool inisIpsetv4, bool inDebug) {
    Debug = inDebug;
    ipsetName = inIpsetName;
    ipsetType = inIpsetType;
    isIpsetv4 = inisIpsetv4;
    DLOG_IF(INFO, Debug) << "opening instance " << inIpsetName << " of type " << inIpsetType;
    ipset_load_types();

    struct ipset_session *session = noddos_ipset_session_init();
    if (session == nullptr) {
        LOG(ERROR) << "Cannot initialize ipset session.";
        ipset_session_fini(session);
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    ipset_envopt_set(session, IPSET_ENV_EXIST);
    int r = ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str());
    if ( r < 0) {
        LOG(ERROR) << "Can't set setname " << ipsetName << ": "  << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_report_msg(session));
    } else if (r > 0) {
        DLOG_IF(INFO, Debug) << "Not creating set " << ipsetName << " as it already exists";
        ipset_session_fini(session);
        return;
    }
    if (ipset_session_data_set(session, IPSET_OPT_TYPENAME, ipsetType.c_str()) < 0) {
        LOG(ERROR) << "Can't set setname " << ipsetName << " to type " << ipsetType << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set type " + ipsetType + ": " + ipset_session_report_msg(session));
    }
    const struct ipset_type *type = ipset_type_get(session, IPSET_CMD_CREATE);
    if (type == NULL) {
        LOG(ERROR) << "Can't set create ip " << ipsetName << ": %s" << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't create ipset " + ipsetName + ": " + ipset_session_report_msg(session));
    }

    uint32_t timeout = 0; /* default to infinity */
    if (ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout) < 0) {
        LOG(ERROR) << "Can't set setname " << ipsetName << " to timeout " << timeout << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set time-out " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    if (ipset_session_data_set(session, IPSET_OPT_TYPE, type)) {
        LOG(ERROR) << "Can't set setname " << ipsetName << " option type: " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set ipset type: " + ipsetName + ": " + ipset_session_report_msg(session));
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
        LOG(ERROR) << "Can't set setname " << ipsetName << " address family "  << family << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Cannot set ipset family: " + ipsetName + ": " + ipset_session_report_msg(session));
    }

    if (ipset_cmd(session, IPSET_CMD_CREATE, /*lineno*/ 0) != 0) {
        LOG(ERROR) << "Can't create setname " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Failed to create ipset " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    if (ipset_commit(session) < 0) {
        LOG(ERROR) << "Can't commit for setname " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    ipset_session_fini(session);
}


bool Ipset::ipset_exec(enum ipset_cmd cmd) {

    if (Debug == true) {
        DLOG_IF(INFO, Debug) << "received command " << cmd << " for ipset " << ipsetName;
    }
    struct ipset_session *session = noddos_ipset_session_init();
    if (session == nullptr) {
        LOG(ERROR) << "Cannot initialize ipset session.";
        ipset_session_fini(session);
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    ipset_envopt_set(session, IPSET_ENV_EXIST);
    if (ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str()) < 0) {
        LOG(ERROR) << "Can't set setname " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_report_msg(session));
    }

    if (ipset_cmd(session, cmd, 0) != 0) {
        ipset_session_fini(session);
        LOG(ERROR) << "Can't exec ipset cmd for setname " << ipsetName << ": " << ipset_session_report_msg(session);
        throw std::runtime_error("Can't exec ipset cmd for " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    if (ipset_commit(session) < 0) {
        LOG(ERROR) << "Can't commit for setname " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    ipset_session_fini(session);
    return true;
}


bool Ipset::ipset_exec(enum ipset_cmd cmd,  const Tins::IPv4Address &inIpAddress, time_t timeout) {
    if (Debug == true) {
        DLOG_IF(INFO, Debug) << "received command " << cmd << " for IP address " << inIpAddress << " for ipset " << ipsetName;
    }
    struct ipset_session *session = noddos_ipset_session_init();
    if (session == nullptr) {
        LOG(ERROR) << "Cannot initialize ipset session.";
        ipset_session_fini(session);
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    ipset_envopt_set(session, IPSET_ENV_EXIST);
    if (ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str()) < 0) {
        LOG(ERROR) << "Can't set setname " << ipsetName << ": %s", ipsetName.c_str(), ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == NULL) {
        LOG(ERROR) << "Can't get type for set " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't get type for set " + ipsetName + ": " + ipset_session_report_msg(session));
    }

    uint8_t family = NFPROTO_IPV4;
    if (ipset_session_data_set(session, IPSET_OPT_FAMILY, &family) < 0) {
        LOG(ERROR) << "Can't set session data to IPv4 family for set " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set session data for " + ipsetName + " to the IPv4 family, error: " + ipset_session_report_msg(session));
    }
    struct in_addr sin;
    inet_aton (inIpAddress.to_string().c_str(), &sin);
    if (ipset_session_data_set(session, IPSET_OPT_IP, &sin) < 0) {
        LOG(ERROR) << "Can't set session data to the IPv4 address for setname " << ipsetName << ": %s", ipsetName.c_str(), ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set session data to the IPv4 address for setname " + ipsetName + ", error: " + ipset_session_report_msg(session));
    }

    if (timeout) {
        if (ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout) != 0) {
            LOG(ERROR) << "Can't set timeout for setname " << ipsetName << ": %s", ipsetName.c_str(), ipset_session_report_msg(session);
            ipset_session_fini(session);
            throw std::runtime_error("Can't set timeout for " + ipsetName + ": " + ipset_session_report_msg(session));
            return false;
        }
    }
    if (ipset_cmd(session, cmd, 0) != 0) {
        ipset_session_fini(session);
        LOG(ERROR) << "Can't exec ipset cmd for setname " << ipsetName << ": " << ipset_session_report_msg(session);
        throw std::runtime_error("Can't exec ipset cmd for " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    if (ipset_commit(session) < 0) {
        LOG(ERROR) << "Can't commit for setname " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    ipset_session_fini(session);
    return true;
}

bool Ipset::ipset_exec(enum ipset_cmd cmd,  const Tins::IPv6Address &inIpAddress, time_t timeout) {
    if (Debug == true) {
        DLOG_IF(INFO, Debug) << "received command " << cmd << " for IP address " << inIpAddress << " for ipset " << ipsetName;
    }
    struct ipset_session *session = noddos_ipset_session_init();
    if (session == nullptr) {
        PLOG(ERROR) << "Cannot initialize ipset session.";
        ipset_session_fini(session);
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    ipset_envopt_set(session, IPSET_ENV_EXIST);
    if (ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str()) < 0) {
        LOG(ERROR) << "Can't set setname " << ipsetName << ": " <<  ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == NULL) {
        LOG(ERROR) << "Can't get type for set " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't get type for set " + ipsetName + ": " + ipset_session_report_msg(session));
    }

    uint8_t family = NFPROTO_IPV6;
    if (ipset_session_data_set(session, IPSET_OPT_FAMILY, &family) < 0) {
        LOG(ERROR) << "Can't set session data to IPv6 family for set " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set session data for " + ipsetName + " to the IPv6 family, error: " + ipset_session_report_msg(session));
    }

    unsigned char buf[sizeof(struct in6_addr)];
    int s = inet_pton(AF_INET6, inIpAddress.to_string().c_str(), buf);
    if (ipset_session_data_set(session, IPSET_OPT_IP, &buf) < 0) {
        LOG(ERROR) << "Can't set session data to the IPv4 address for setname " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set session data to the IPv4 address for setname " + ipsetName + ", error: " + ipset_session_report_msg(session));
    }

    if (timeout) {
        if (ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout) != 0) {
            LOG(ERROR) << "Can't set timeout for setname " << ipsetName << ": %s" << ipset_session_report_msg(session);
            ipset_session_fini(session);
            throw std::runtime_error("Can't set timeout for " + ipsetName + ": " + ipset_session_report_msg(session));
        }
    }
    if (ipset_cmd(session, cmd, 0) != 0) {
        LOG(ERROR) << "Can't exec ipset cmd for setname " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't exec ipset cmd for " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    if (ipset_commit(session) < 0) {
        LOG(ERROR) << "Can't commit for setname " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    ipset_session_fini(session);
    return true;
}

bool Ipset::ipset_exec(enum ipset_cmd cmd, const std::string Mac, time_t timeout) {
    if (Debug == true) {
        DLOG_IF(INFO, Debug) << "received command " << cmd << " for MAC address " << Mac
                << " for ipset " << ipsetName;
    }
    struct ipset_session *session = noddos_ipset_session_init();
    if (session == nullptr) {
        PLOG(ERROR) << "Cannot initialize ipset session.";
        ipset_session_fini(session);
        throw std::runtime_error ("Cannot initialize ipset session.");
    }

    ipset_envopt_set(session, IPSET_ENV_EXIST);
    if (ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str()) < 0) {
        LOG(ERROR) << "Can't set setname " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't set setname " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == NULL) {
        LOG(ERROR) << "Can't get type for set " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't get type for set " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    if (ipset_parse_elem(session, (ipset_opt)type->last_elem_optional, Mac.c_str()) < 0) {
        LOG(ERROR) << "Can't call ipset_parse_elem for " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_parse_elem for ipset " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    if (timeout) {
        if (ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout) != 0) {
            LOG(ERROR) << "Can't set timeout for setname " << ipsetName << ": " << ipset_session_report_msg(session);
            ipset_session_fini(session);
            throw std::runtime_error("Can't set timeout for " + ipsetName + ": " + ipset_session_report_msg(session));
        }
    }
    if (ipset_cmd(session, cmd, 0) != 0) {
        LOG(ERROR) << "Can't exec ipset cmd for setname " << ipsetName << ": " << ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't exec ipset cmd for " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    if (ipset_commit(session) < 0) {
        LOG(ERROR) << "Can't commit for setname " << ipsetName << ": %s", ipsetName.c_str(), ipset_session_report_msg(session);
        ipset_session_fini(session);
        throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_report_msg(session));
    }
    ipset_session_fini(session);
    return true;
}



