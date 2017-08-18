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

 * Ipset.h
 *
 *  Created on: Aug 9, 2017
 *      Author: Steven Hessing
 */

#ifndef IPSET_H_
#define IPSET_H_

#include <iostream>
#include <stdexcept>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>

#include <libipset/linux_ip_set.h>
#include <libipset/types.h>
#include <libipset/session.h>

#include "boost/asio.hpp"

#include "MacAddress.h"


std::string getIpsetUuid (const std::string inUuid);
std::string getIpsetName (const std::string inUuid, bool inSrc, bool inIpv4 = true);


class Ipset {
private:
    struct ipset_session *session ;
    std::string ipsetType;
    std::string ipsetName;
    bool isIpsetv4;
    bool Debug;

    bool ipset_exec(enum ipset_cmd cmd, const boost::asio::ip::address &inIpAddress, uint32_t timeout);
    bool ipset_exec(enum ipset_cmd cmd, const MacAddress &Mac, uint32_t timeout);
    // bool ipset_exec(enum ipset_cmd cmd, const MacAddress &Mac, uint32_t timeout = 0);
    // bool ipsec_exec(enum ipset_cmd cmd, const boost::asio::ip::address &inIpAddress, uint32_t timeout);

public:
    Ipset (const bool inDebug = false): Debug{inDebug}, ipsetType{""}, ipsetName{""}, isIpsetv4{false} {
        session = nullptr;
        if (Debug == true) {
            syslog (LOG_DEBUG, "Ipset: new instance");
        }
    };

    Ipset(const std::string inIpsetName, std::string inIpsetType, bool inisIpsetv4, bool inDebug = false):
            ipsetName{inIpsetName}, ipsetType{inIpsetType}, isIpsetv4{inisIpsetv4}, Debug{inDebug} {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Ipset: new instance");
        }
        Open(inIpsetName, inIpsetType, inisIpsetv4);
    }

    ~Ipset(void) {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Ipset: deleting instance");
        }
        if (session != nullptr) {
            ipset_session_fini(session);
            session = nullptr;
        }
    }
    void Open (const std::string inIpsetName, std::string inIpsetType, bool inisIpsetv4, bool inDebug = false) {
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

    bool Exists() {
         ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str());
         return ipset_cmd(session, IPSET_CMD_HEADER, 0) == 0;
     }

     bool Add(const boost::asio::ip::address &inIpAddress, time_t timeout = 604800) {
         return ipset_exec(IPSET_CMD_ADD, inIpAddress, timeout);
     }

     bool Add(const MacAddress &inMac, time_t timeout = 7776000) {
         return ipset_exec(IPSET_CMD_ADD, inMac, timeout);
     }

     bool Remove(const boost::asio::ip::address &inIpAddress) {
         return ipset_exec(IPSET_CMD_DEL, inIpAddress, 0);
     }
     bool Remove(const MacAddress &Mac) {
         return ipset_exec(IPSET_CMD_DEL, Mac, 0);
     }

     bool In(const boost::asio::ip::address &inIpAddress) {
         return ipset_exec(IPSET_CMD_TEST, inIpAddress, 0);
     }
     bool In(const MacAddress &Mac) {
         return ipset_exec(IPSET_CMD_TEST, Mac, 0);
     }

};

#endif /* IPSET_H_ */
