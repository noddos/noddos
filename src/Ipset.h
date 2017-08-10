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

#include "MacAddress.h"

class Ipset {
private:
    struct ipset_session *session;
    std::string setType;
    std::string setName;

    bool try_cmd(enum ipset_cmd cmd, const struct in_addr *addr, uint32_t timeout = 0);
    bool try_cmd(enum ipset_cmd cmd, const MacAddress &Mac, uint32_t timeout = 0);
    bool try_create();

public:
    Ipset(const std::string insetName, std::string insetType): setName{insetName}, setType{insetType} {
        ipset_load_types();

        session = ipset_session_init(printf);
        if (!session) {
            throw std::runtime_error("Can't initialize IPset session");
        }

        /* return success on attempting to add an existing / remove an
         * non-existing rule */
        ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL);

        if (!Exists() && !try_create()) {
            std::string e = "Failed to create " + setName + "(" + setType + "):" + ipset_session_error(session);
            throw std::runtime_error(e.c_str());
            // fprintf(stderr, "Failed to create %s: %s\n", setname.c_str(),
            //        ipset_session_error(session));
            ipset_session_fini(session);
        }
    }

    ~Ipset(void) {
        ipset_session_fini(session);
    }
    bool Exists() {
         ipset_session_data_set(session, IPSET_SETNAME, setName.c_str());
         return ipset_cmd(session, IPSET_CMD_HEADER, 0) == 0;
     }

     bool Add(const struct in_addr * addr, time_t timeout = 604800) {
         return try_cmd(IPSET_CMD_ADD, addr, timeout);
     }

     bool Add(const MacAddress &Mac, time_t timeout = 2419200 ) {
         return try_cmd(IPSET_CMD_ADD, Mac, timeout);
     }
     bool Remove(const struct in_addr * addr) {
         return try_cmd(IPSET_CMD_DEL, addr, 0);
     }

     bool In(const struct in_addr *addr) {
         return try_cmd(IPSET_CMD_TEST, addr, 0);
     }

};

#endif /* IPSET_H_ */
