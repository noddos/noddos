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

int main(int argc, char** argv) {
    bool testfailed = false;
    Ipset i("noddostest", "hash:ip");
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
    Ipset m("noddosmac", "hash:mac");
    MacAddress Mac("aa:bb:cc:dd:ee:ff");
    if (m.Add(Mac) == false ) {
        testfailed = 1;
        std::cout << "Failed to add MAC address to hash:mac ipset" << std::endl;
    }
    return testfailed;
}

