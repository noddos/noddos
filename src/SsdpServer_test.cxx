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

 * SsdpServer_test.cxx
 *
 *  Created on: Apr 2, 2017
 *      Author: steven
 */

#include <iostream>
#include <string.h>
#include <memory>
#include "SsdpServer.h"
#include "HostCache.h"
#include "SsdpHost.h"
#include "SsdpLocation.h"

int main () {
	bool testfailure = false;
	InterfaceMap ifMap;
	HostCache hC(ifMap, 0, true);
	char msg[300] = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=60\r\nlOCATION: http://192.168.1.248:49152/rootDesc.xml\r\nSERVER: Linux 3.0.8 UPnP/1.1 MiniUPnPd/1.7\r\nupnp:rootdevice\r\nuuid:Upnp-BasicDevice-1_0-BC66411075FD::upnp:rootdevice\r\n\01-NLS: 1\r\nBOOTID.UPNP.ORG: 1\r\nCONFIGID.UPNP.ORG: 1337\r\n";
	auto sHost = std::make_shared<SsdpHost>();
	sHost->Location="http://192.168.1.248:49152/rootDesc.xml";
	sHost->IpAddress = "192.168.1.249";
	if (SsdpLocation::Get(*sHost, true) != true) {
		testfailure=true;
		std::cout << "Couldn't get SSDP Host info using call to the Location address 192.168.1.249" << std::endl;
		if (sHost->FriendlyName != "SAMSUNG-SNH-E6440BN-BC66411075FD") {
			testfailure = 1;
			std::cout << "Failed parsing FriendlyName" << std::endl;
		}
		if (sHost->Manufacturer != "SAMSUNG-SNH-E6440BN-BC66411075FD") {
			testfailure = 1;
			std::cout << "Failed parsing Manufacturer" << std::endl;
		}
		if (sHost->ManufacturerUrl != "http://www.samsungtechwin.com/") {
			testfailure = 1;
			std::cout << "Failed parsing ManufacturerUrl" << std::endl;
		}
		if (sHost->ModelName != "SNH-E6440BN") {
			testfailure = 1;
			std::cout << "Failed parsing ModelName" << std::endl;
		}
		if (sHost->ModelUrl != "http://www.samsungtechwin.com/") {
			testfailure = 1;
			std::cout << "Failed parsing ModelUrl" << std::endl;
		}
		if (sHost->SerialNumber != "KJ2J69MFB010NKP") {
			testfailure = 1;
			std::cout << "Failed parsing SerialNumber" << std::endl;
		}
	} else {
		std::cout << "SsdpLocation test succesful" << std::endl;
	}
	SsdpServer sServer(hC, 86400);
	if (sServer.ParseSsdpMessage(sHost, msg, strlen(msg)) == true) {
		if (sHost->Location == "http://192.168.1.248:49152/rootDesc.xml" &&
				sHost->Server == "Linux 3.0.8 UPnP/1.1 MiniUPnPd/1.7" &&
				sHost->UserAgent == "") {
			std::cout << "Ssdp message #1 parsed succesfully" << std::endl;
		} else {
			std::cout << "Ssdp message #1 parse value failure" << std::endl;
		}
	} else {
		std::cout << "Ssdp message #1 NOT parsed succesfully" << std::endl;
		testfailure = true;

	}
	if (testfailure) {
		exit(1);
    }
	exit(0);
}
