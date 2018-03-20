/*

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

 * MacAddress.h
 *  Created on: May 24, 2017
 *  Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef MACADDRESS_H_
#define MACADDRESS_H_

#include <iostream>
#include <sstream>
#include <iomanip>

#include <stdio.h>
#include <net/ethernet.h> /* the L2 protocols */

class MacAddress {
private:
    unsigned long long Mac;
    std::string MacString;
    bool Debug;

public:
    MacAddress (): Mac{0}, MacString{""}, Debug{false} {}
    MacAddress (const unsigned long long inMac, bool inDebug = false): Mac{inMac}, Debug{inDebug} { create_string(); }
    MacAddress (const unsigned char inMac[ETH_ALEN], bool inDebug = false): Debug{inDebug} {
        Mac = uint64_t(inMac[0]) << 40 |
                uint64_t(inMac[1]) << 32 |
                uint64_t(inMac[2]) << 24 |
                uint64_t(inMac[3]) << 16 |
                uint64_t(inMac[4]) << 8 |
                uint64_t(inMac[5]);
        create_string();
    }
    MacAddress(const std::string inMacString) {	set(inMacString); create_string(); }
    void create_string () {
        std::ostringstream osstr;
        for (unsigned int x = 0; x < 6; x++) {
            osstr << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << ((Mac >> ((6 - x - 1) * 8)) & 0xff);

            if (x != 5)
                osstr << ':';
        }
        MacString = osstr.str();
    }
    void set (const unsigned long long inMac)  { Mac = inMac; create_string(); }
    void set (const std::string inMacString)  {
        unsigned char a[6];
        int last = -1;
        int rc = sscanf(inMacString.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n",
                a + 0, a + 1, a + 2, a + 3, a + 4, a + 5, &last);
        if(rc < 6)
            throw std::runtime_error("PacketSnoop: invalid mac address format " + inMacString);
        Mac =  uint64_t(a[0]) << 40 |
                uint64_t(a[1]) << 32 |
                uint64_t(a[2]) << 24 |
                uint64_t(a[3]) << 16 |
                uint64_t(a[4]) << 8 |
                uint64_t(a[5]);
        create_string();
    }
    unsigned long long get () const { return Mac; }
    const std::string str() const { return MacString; }
    const char* c_str() const { return MacString.c_str(); }

    bool isValid() const { return Mac > 0; }
    bool operator()( MacAddress const& lhs, MacAddress const& rhs ) const  { return lhs.Mac < rhs.Mac; }
    bool operator == (const MacAddress &rhs) const {
        return Mac == rhs.Mac;
    }
    bool operator != (const MacAddress &rhs) const {
        return Mac != rhs.Mac;
    }

    friend std::ostream &operator<< (std::ostream & stream, const MacAddress mac) {
        stream<<mac.MacString;
        return stream;
    }
};

#endif /* MACADDRESS_H_ */
