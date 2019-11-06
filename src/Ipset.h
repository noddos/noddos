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

#include <libipset/linux_ip_set.h>
#include <libipset/types.h>
#include <libipset/session.h>

#include <glog/logging.h>
#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include "MacAddress.h"

#if IPSET_PROTOCOL < 7
/* compatibility shims */

inline void ipset_envopt_set(struct ipset_session *session, enum ipset_envopt opt)
{
    ipset_envopt_parse(session, opt, NULL);
}

inline const char * ipset_session_report_msg(const struct ipset_session *session)
{
  return ipset_session_error(session);
}

static inline struct ipset_session *noddos_ipset_session_init(void)
{
  return ipset_session_init(printf);
}

#else

static inline struct ipset_session *noddos_ipset_session_init(void)
{
  return ipset_session_init(NULL, NULL);
}
#endif

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
        DLOG_IF(INFO, Debug) << "new instance";
    };

    Ipset(const std::string inIpsetName, std::string inIpsetType, bool inisIpsetv4, bool inDebug = false):
            ipsetName{inIpsetName}, ipsetType{inIpsetType}, isIpsetv4{inisIpsetv4}, Debug{inDebug} {
        DLOG_IF(INFO, Debug) << "new instance";
        Open(inIpsetName, inIpsetType, inisIpsetv4);
    }

    ~Ipset(void) {
        DLOG_IF(INFO, Debug) << "deleting instance";
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
            PLOG(ERROR) << "Failed to destroy ipset " << ipsetName;
        }
        return false;
    }
    bool Exists() {
        try {
            struct ipset_session *session = noddos_ipset_session_init();
            if (session == nullptr) {
                PLOG(ERROR) << "Cannot initialize ipset session.";
                ipset_session_fini(session);
                throw std::runtime_error ("Cannot initialize ipset session.");
            }

            ipset_envopt_set(session, IPSET_ENV_EXIST);
            int r = ipset_session_data_set(session, IPSET_SETNAME, ipsetName.c_str());
            if (ipset_commit(session) < 0) {
                LOG(ERROR) << "Can't commit for setname " << ipsetName << ": " << ipset_session_report_msg(session);
                ipset_session_fini(session);
                throw std::runtime_error("Can't call ipset_commit for " + ipsetName + ": " + ipset_session_report_msg(session));
            }
            ipset_session_fini(session);
            return r == 0;
        } catch (...) {
            LOG(ERROR) << "Failed to check existence of ipset " << ipsetName;
        }
        return false;
    }

    template <class T>
    bool Add(const T &inIpAddress, time_t timeout) {
        try {
            return ipset_exec(IPSET_CMD_ADD, inIpAddress, timeout);
        } catch (...) {
            PLOG(ERROR) << "Failed to add IP address " << inIpAddress << " to ipset " << ipsetName;
        }
        return false;
    }

    bool Add(const MacAddress &inMac, const time_t timeout) {
        try {
            return ipset_exec(IPSET_CMD_ADD, inMac.str(), timeout);
        } catch (...) {
            PLOG(ERROR) << "Failed to add MAC address " << inMac << " to ipset " << ipsetName;
        }
        return false;
    }
    bool Add(const std::string &inMac, const time_t timeout) {
        try {
            return ipset_exec(IPSET_CMD_ADD, inMac, timeout);
        } catch (...) {
            PLOG(ERROR) << "Failed to add MAC address " << inMac << " to ipset " << ipsetName;
        }
        return false;
    }
    template <class T>
    bool Remove(const T &inIpAddress) {
        try {
            return ipset_exec(IPSET_CMD_DEL, inIpAddress, 0);
        } catch (...) {
            PLOG(ERROR) << "Failed to remove IP address " << inIpAddress << " from ipset " <<  ipsetName;
        }
        return false;
    }

    bool Remove(const MacAddress &Mac) {
        try {
            return ipset_exec(IPSET_CMD_DEL, Mac.str(), 0);
        } catch (...) {
            PLOG(ERROR) << "Failed to remove MAC address " << Mac << " from  ipset " << ipsetName;
        }
        return false;
    }
    bool Remove(const std::string &Mac) {
        try {
            return ipset_exec(IPSET_CMD_DEL, Mac, 0);
        } catch (...) {
            PLOG(ERROR) << "Failed to remove Mac address " << Mac << " from ipset " << ipsetName;
        }
        return false;
    }

    template <class T>
    bool In(const T &inIpAddress) {
        try {
            return ipset_exec(IPSET_CMD_TEST, inIpAddress, 0);
        } catch (...) {
            PLOG(ERROR) << "Failed to check wheth IP address " << inIpAddress << " is in ipset " << ipsetName;
        }
        return false;
    }

    bool In(const MacAddress &Mac) {
        try {
            return ipset_exec(IPSET_CMD_TEST, Mac.str(), 0);
        } catch (...) {
            PLOG(ERROR) << "Failed to check whether MAC address " << Mac << " is in ipset " << ipsetName;
        }
        return false;
    }
};



#endif /* IPSET_H_ */
