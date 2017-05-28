/*
 * MacAddress_test.cxx
 *
 *  Created on: May 24, 2017
 *      Author: steven
 */

#include <iostream>

#include "MacAddress.h"

int main () {
	bool testfailed = false;
	std::string MacString = "AA:22:CC:44:EE:66";

	MacAddress m(MacString);

	std::string res = m.str();
	if (res != MacString) {
		testfailed = true;
		std::cout << res << " does not match original MAC address " << MacString << std::endl;
	}
	if (testfailed == true) {
		return 1;
	}
	return 0;
}


