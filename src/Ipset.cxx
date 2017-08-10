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
 *      Author: Steven HEssing
 */

#include "Ipset.h"
#include <iostream>
#include <stdexcept>

bool Ipset::try_cmd(enum ipset_cmd cmd, const struct in_addr *addr, uint32_t timeout) {
    int r = ipset_session_data_set(session, IPSET_SETNAME, setName.c_str());

    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == NULL) {
         return false;
    }

    uint8_t family = NFPROTO_IPV4;
    ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);
    ipset_session_data_set(session, IPSET_OPT_IP, addr);
    if (timeout) {
        ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
    }
    r = ipset_cmd(session, cmd, 0);
    /* assume that errors always occur if NOT in set. To do it otherwise,
     * see lib/session.c for IPSET_CMD_TEST in ipset_cmd */
    return r == 0;
}

bool Ipset::try_cmd(enum ipset_cmd cmd, const MacAddress &Mac, uint32_t timeout) {
    int r;
    r = ipset_session_data_set(session, IPSET_SETNAME, setName.c_str());

    const struct ipset_type *type = ipset_type_get(session, cmd);
    if (type == NULL) {
         return false;
    }
    // ipset_parse_ether(session, IPSET_OPT_ETHER, Mac.c_str());
    // ipset_session_data_set(session, IPSET_OPT_ETHER, Mac.c_str());
    r = ipset_parse_elem(session, (ipset_opt)type->last_elem_optional, Mac.c_str());
    if (r < 0) {
        std::string e = "Can't call ipset_parse_elem, error: ";
        e.append(ipset_session_error(session));
        ipset_session_fini(session);
        throw std::runtime_error(e.c_str());
        return false;
    } else {
        if (timeout) {
            r = ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
            if (r != 0) {
                std::string e = "Can't set timeout for " + setName + ", error: " + ipset_session_error(session);
                ipset_session_fini(session);
                throw std::runtime_error(e.c_str());
            }
        }
        r = ipset_cmd(session, cmd, 0);
        if (r != 0) {
            std::string e = "Can't call ipset_cmd, error: ";
            e.append(ipset_session_error(session));
            ipset_session_fini(session);
            throw std::runtime_error(e.c_str());
            return false;
        }
    }
    r = ipset_commit(session);
    /* assume that errors always occur if NOT in set. To do it otherwise,
     * see lib/session.c for IPSET_CMD_TEST in ipset_cmd */
    return r == 0;
}

bool Ipset::try_create() {
      const struct ipset_type *type;
      int r;
      r = ipset_session_data_set(session, IPSET_SETNAME, setName.c_str());
      /* since the IPSET_SETNAME option is valid, this should never fail */
      // assert(r == 0);
      ipset_session_data_set(session, IPSET_OPT_TYPENAME, setType.c_str());
      type = ipset_type_get(session, IPSET_CMD_CREATE);
      if (type == NULL) {
          return false;
      }
      uint32_t timeout = 0; /* timeout support, but default to infinity */
      ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
      ipset_session_data_set(session, IPSET_OPT_TYPE, setType.c_str());
      if (setType == "hash:ip") {
          uint8_t family = NFPROTO_IPV4;
          ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);
      } else if (setType == "hash:mac") {
          throw std::logic_error("Creating ipsets of type hash:mac not supported yet");
          uint8_t family = NFPROTO_UNSPEC;
          ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);
      }
      r = ipset_cmd(session, IPSET_CMD_CREATE, 0);
      return r == 0;
}

