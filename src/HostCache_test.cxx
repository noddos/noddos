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

 * HostCache_test.cxx
 *
 *  Created on: Apr 3, 2017
 *      Author: steven
 */


#include <iostream>

#include <syslog.h>

#include "noddos.h"
#include "HostCache.h"
#include "Host.h"

// static std::string deviceprofilesfile = "tests/DeviceProfiles.json";

int main () {

	openlog("Host_test", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
	HostCache hC;
	// hC.DeviceProfiles_load(deviceprofilesfile);
	hC.AddByMac ("00:00:00:00:00:03", "192.168.1.99");

	std::string s;
	bool testfailure = false;
	auto h = hC.FindOrCreateHostByIp("192.168.1.99");
	if ((s = h->MacAddress_get()) != "00:00:00:00:00:03") {
		testfailure = true;
		std::cout << "Mac lookup failure for 192.168.1.99 resulting in: " << s << std::endl;
	}
	if ((s = hC.MacLookup("192.168.1.1",1)) != "f4:f2:6d:70:77:7c") {
		testfailure = true;
		std::cout << "Mac lookup failure for 192.168.1.1 resulting in: " << s << std::endl;
	}
	if ((s = hC.MacLookup("99.99.99.99",1)) != "") {
		testfailure = true;
		std::cout << "Mac lookup failure for 99.99.99.99 resulting in: " << s << std::endl;
	}
	if ((s = hC.MacLookup("192.168.1.240", "enp0s31f6")) == "00:01:2e:6f:e0:f3") {
		std::cout << "IOCTL lookup for 192.168.1.240: " << s << std::endl;
	} else {
		std::cout << "Mac lookup failure for 192.168.1.240 resulting in: " << s << std::endl;
		testfailure = true;
	}
	if (testfailure) {
		exit(1);
    }
	exit(0);
}

