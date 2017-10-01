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

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include "MacAddress.h"


std::string getIpsetUuid (std::string inUuid);
std::string getIpsetName (std::string inUuid, bool inSrc, bool inIpv4 = true);
bool isIpv4Address(std::string inIpAddress, bool Debug = false);

class Ipset {
private:
    // struct ipset_session *session ;
    std::string ipsetType;
    std::string ipsetName;
    bool isIpsetv4;
    bool Debug;

    // template <class T>
    bool ipset_exec(enum ipset_cmd cmd,  const Tins::IPv4Address &inIpAddress, time_t timeout);
    bool ipset_exec(enum ipset_cmd cmd,  const Tins::IPv6Address &inIpAddress, time_t timeout);


    bool ipset_exec(enum ipset_cmd cmd, const std::string Mac, time_t timeout);
    bool ipset_exec(enum ipset_cmd cmd);

public:
    Ipset (const bool inDebug = false): Debug{inDebug}, ipsetType{""}, ipsetName{""}, isIpsetv4{false} {
        // session = nullptr;
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
        // if (session != nullptr) {
        //    ipset_session_fini(session);
        //    session = nullptr;
        // }
    }
    void Open (const std::string inIpsetName, std::string inIpsetType, bool inisIpsetv4, bool inDebug = false);

    bool Destroy() {
        try {
            return ipset_exec(IPSET_CMD_DESTROY);
        } catch (...) {
            syslog (LOG_ERR, "Ipset: Failed to destroy ipset %s", ipsetName.c_str());
        }
        return false;
    }
    bool Exists() {
        try {
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
            int r = ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str());
            if (ipset_commit(session) < 0) {
                syslog (LOG_ERR, "Ipset: Can't commit for setname %s: %s", ipsetName.c_str(), ipset_session_error(session));
                ipset_session_fini(session);
                throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_error(session));
            }
            ipset_session_fini(session);
            return r == 0;
        } catch (...) {
            syslog (LOG_ERR, "Ipset: Failed to check existence of ipset %s", ipsetName.c_str());
        }
        return false;
     }

    template <class T>
    bool Add(const T &inIpAddress, time_t timeout) {
         try {
             return ipset_exec(IPSET_CMD_ADD, inIpAddress, timeout);
         } catch (...) {
             syslog (LOG_ERR, "Ipset: Failed to add IP address %s to ipset %s", inIpAddress.to_string().c_str(), ipsetName.c_str());
         }
         return false;
     }

     bool Add(const MacAddress &inMac, const time_t timeout) {
         try {
             return ipset_exec(IPSET_CMD_ADD, inMac.str(), timeout);
         } catch (...) {
             syslog (LOG_ERR, "Ipset: Failed to add MAC address %s to ipset %s", inMac.c_str(), ipsetName.c_str());
         }
         return false;
     }
     bool Add(const std::string &inMac, const time_t timeout) {
         try {
             return ipset_exec(IPSET_CMD_ADD, inMac, timeout);
         } catch (...) {
             syslog (LOG_ERR, "Ipset: Failed to add MAC address %s to ipset %s", inMac.c_str(), ipsetName.c_str());
         }
         return false;
     }
     template <class T>
     bool Remove(const T &inIpAddress) {
         try {
             return ipset_exec(IPSET_CMD_DEL, inIpAddress, 0);
         } catch (...) {
             syslog (LOG_ERR, "Ipset: Failed to remove IP address %s from ipset %s ", inIpAddress.to_string().c_str(), ipsetName.c_str());
         }
         return false;
     }

     bool Remove(const MacAddress &Mac) {
         try {
         return ipset_exec(IPSET_CMD_DEL, Mac.str(), 0);
         } catch (...) {
             syslog (LOG_ERR, "Ipset: Failed to remove MAC address %s from  ipset %s", Mac.c_str(), ipsetName.c_str());
         }
         return false;
     }
     bool Remove(const std::string &Mac) {
         try {
          return ipset_exec(IPSET_CMD_DEL, Mac, 0);
         } catch (...) {
             syslog (LOG_ERR, "Ipset: Failed to remove Mac address %s from ipset %s", Mac.c_str(), ipsetName.c_str());
         }
         return false;
     }

     template <class T>
     bool In(const T &inIpAddress) {
         try {
         return ipset_exec(IPSET_CMD_TEST, inIpAddress, 0);
         } catch (...) {
             syslog (LOG_ERR, "Ipset: Failed to check wheth IP address %s is in ipset %s", inIpAddress.to_string().c_str(), ipsetName.c_str());
         }
         return false;
     }

      bool In(const MacAddress &Mac) {
         try {
         return ipset_exec(IPSET_CMD_TEST, Mac.str(), 0);
         } catch (...) {
             syslog (LOG_ERR, "Ipset: Failed to check whether MAC address %s is in ipset %s", Mac.c_str(), ipsetName.c_str());
         }
         return false;
     }
};



#endif /* IPSET_H_ */
