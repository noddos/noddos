/*
 * MacAddress.h
 *
 *  Created on: May 24, 2017
 *      Author: steven
 */

#ifndef MACADDRESS_H_
#define MACADDRESS_H_

#include <iostream>
#include <sstream>
#include <iomanip>

#include <stdio.h>

class MacAddress {
public:
	unsigned long long Mac;
	MacAddress (): Mac{0} {};
	MacAddress (const unsigned long long inMac): Mac{inMac} {};
	MacAddress(const std::string inMacString) {	set(inMacString); }
	void set (const unsigned long long inMac)  { Mac = inMac; };
	void set (const std::string inMacString)  {
		 unsigned char a[6];
		 int last = -1;
		 int rc = sscanf(inMacString.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n",
		                a + 0, a + 1, a + 2, a + 3, a + 4, a + 5,
		                &last);
		 if(rc != 6 || inMacString.size() != last)
		    throw std::runtime_error("invalid mac address format " + inMacString);
		 Mac =  uint64_t(a[0]) << 40 |
		        uint64_t(a[1]) << 32 |
		        uint64_t(a[2]) << 24 |
		        uint64_t(a[3]) << 16 |
		        uint64_t(a[4]) << 8 |
		        uint64_t(a[5]);
	}
	unsigned long long get () const { return Mac; }
	const std::string  str() const {
		std::ostringstream osstr;
		for (unsigned int x = 0; x < 6; x++) {
			osstr << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << ((Mac >> ((6 - x - 1) * 8)) & 0xff);

			if (x != 5)
				osstr << ':';
		}

		return osstr.str();
    };

	const char* c_str() const {return str().c_str(); };
};

#endif /* MACADDRESS_H_ */
