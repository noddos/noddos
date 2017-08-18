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

#include "boost/asio.hpp"

int main(int argc, char** argv) {
    openlog("Ipsettest", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
    bool testfailed = false;
    if (geteuid() != 0) {
        std::cout << "Skipping ipset test as we're not running as root" << std::endl;
        return 0;
    }
    Ipset i(true);
    i.Open("noddostestv4", "hash:ip", true, true);

    boost::asio::ip::address ipfirst = boost::asio::ip::address::from_string("192.168.1.1");
    struct in_addr sin;
    inet_aton ("192.168.1.1", &sin);
    if (i.Add(ipfirst) == false ) {
        testfailed = 1;
        std::cout << "Failed to add IP address to hash:ip ipset" << std::endl;
    } else {
        std::cout << "Added IP address to hash:ip ipset" << std::endl;
        if (i.In(ipfirst) == false) {
            testfailed = 1;
            std::cout << "Couldn't find IP address in hash:ip ipset" << std::endl;
        } else {
            if (i.Remove(ipfirst) == false) {
                testfailed = 1;
                std::cout << "Couldn't remove IP address from hash:ip ipset" << std::endl;
            } else {
                std::cout << "Removed IP address from hash:ip ipset" << std::endl;
            }
        }
    }
    boost::asio::ip::address ipthird = boost::asio::ip::address::from_string("192.168.1.3");    struct in_addr sin3;
    inet_aton ("192.168.3.3", &sin3);
    if (i.Add(ipthird) == false ) {
        testfailed = 1;
        std::cout << "Failed to add 3rd IP address to hash:ip ipset" << std::endl;
    } else {
        std::cout << "Added 3rd IP address to hash:ip ipset" << std::endl;
        if (i.In(ipthird) == false) {
            testfailed = 1;
            std::cout << "Couldn't find 3rd IP address in hash:ip ipset" << std::endl;
        } else {
            if (i.Remove(ipthird) == false) {
                testfailed = 1;
                std::cout << "Couldn't remove 3rd IP address from hash:ip ipset" << std::endl;
            } else {
                std::cout << "Removed 3rd IP address from hash:ip ipset" << std::endl;
            }
        }
    }
    Ipset s(true);
    i.Open("noddostestv6", "hash:ip", false, true);

    boost::asio::ip::address ipsix = boost::asio::ip::address::from_string("fdbb:2ad1:cea0:0:1e1b:dff:fe7d:f5ec");
    if (i.Add(ipsix) == false ) {
        testfailed = 1;
        std::cout << "Failed to add IPv6 address to hash:ip ipset" << std::endl;
    } else {
        std::cout << "Added IPv6 address to hash:ip ipset" << std::endl;
        if (i.In(ipsix) == false) {
            testfailed = 1;
            std::cout << "Couldn't find IP address in hash:ip ipset" << std::endl;
        } else {
            if (i.Remove(ipsix) == false) {
                testfailed = 1;
                std::cout << "Couldn't remove IPv6 address from hash:ip ipset" << std::endl;
            } else {
                std::cout << "Removed IPv6 address from hash:ip ipset" << std::endl;
            }
        }
    }

    Ipset j("noddostest2", "hash:ip", NFPROTO_IPV4, true);

    struct in_addr sin2;
    inet_aton ("192.168.2.2", &sin2);
    if (j.Add(&sin2) == false ) {
        testfailed = 1;
        std::cout << "Failed to add IP address to second hash:ip ipset" << std::endl;
    } else {
        std::cout << "Added IP address to second hash:ip ipset" << std::endl;
        if (j.In(&sin2) == false) {
            testfailed = 1;
            std::cout << "Couldn't find IP address in second hash:ip ipset" << std::endl;
        } else {
            if (j.Remove(&sin2) == false) {
                testfailed = 1;
                std::cout << "Couldn't remove IP address from second hash:ip ipset" << std::endl;
            } else {
                std::cout << "Removed IP address from second hash:ip ipset" << std::endl;
            }
        }
    }

    // disable hash:mac test as it requires an existing ipset hash:map to exist
    Ipset m("noddosmac", "hash:mac", NFPROTO_UNSPEC);
    std::string MacString = "AA:22:CC:44:EE:66";

    MacAddress Mac(MacString);

    std::string mstr = Mac.str();

    if (m.Add(Mac) == false ) {
        testfailed = 1;
        std::cout << "Failed to add MAC address to hash:mac ipset" << std::endl;
    } else {
        std::cout << "Added MAC address to hash:mac ipset" << std::endl;
        if (m.In(Mac) == false) {
            testfailed = 1;
            std::cout << "Couldn't find MAC address in hash:mac ipset" << std::endl;
        } else {
            std::cout << "Found MAC address in hash:mac ipset" << std::endl;
            if (m.Remove(Mac) == false) {
                testfailed = 1;
                std::cout << "Couldn't remove MAC address from hash:mac ipset" << std::endl;
            } else {
                std::cout << "Removed MAC address from hash:mac ipset" << std::endl;
            }
        }
    }
    return testfailed;

}

