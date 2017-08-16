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

 * Ipset_test.cxx
 *
 *  Created on: Aug 9, 2017
 *      Author: Steven Hessing
 */

#include "Ipset.h"
#include "MacAddress.h"

#include <unistd.h>
#include <sys/types.h>
#include <syslog.h>

int main(int argc, char** argv) {
    openlog("Ipsettest", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
    bool testfailed = false;
    if (geteuid() != 0) {
        std::cout << "Skipping ipset test as we're not running as root" << std::endl;
        return 0;
    }
    Ipset i("noddostest", "hash:ip", true);
    struct in_addr sin;
    inet_aton ("192.168.1.1", &sin);
    if (i.Add(&sin) == false ) {
        testfailed = 1;
        std::cout << "Failed to add IP address to hash:ip ipset" << std::endl;
    } else {
        if (i.In(&sin) == false) {
            testfailed = 1;
            std::cout << "Couldn't find IP address in hash:ip ipset" << std::endl;
        } else {
            if (i.Remove(&sin) == false) {
                testfailed = 1;
                std::cout << "Couldn't remove IP address from hash:ip ipset" << std::endl;
            }
        }
    }
    // disable hash:mac test as it requires an existing ipset hash:map to exist
    /* Ipset m("noddosmac", "hash:mac");
    MacAddress Mac("AA:BB:CC:DD:EE:FF");
    if (m.Add(Mac) == false ) {
        testfailed = 1;
        std::cout << "Failed to add MAC address to hash:mac ipset" << std::endl;
    } else {
        if (m.In(Mac) == false) {
            testfailed = 1;
            std::cout << "Couldn't find MAC address in hash:mac ipset" << std::endl;
        } else {
            if (m.Remove(Mac) == false) {
                testfailed = 1;
                std::cout << "Couldn't remove MAC address from hash:mac ipset" << std::endl;
            }
        }
    }
    return testfailed;
    */
}

