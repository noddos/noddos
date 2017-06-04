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

 * DeviceProfile_test.cpp
 *
 *  Created on: Mar 25, 2017
 *      Author: steven
 */

#include <fstream>
#include <memory>
#include <iostream>

#include <json.hpp>
using nlohmann::json;


#include "noddos.h"
#include "DeviceProfile.h"
#include "HostCache.h"
#include "DnsmasqLogFile.h"

static std::string deviceprofilesfile = "tests/DeviceProfiles.json";

bool test_match (std::string inIp, std::string inDpUuid, HostCache &hc);

int main()
{
	openlog("DnsmasqLogFile_test", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
	bool testfailed = false;
	std::map<std::string, std::shared_ptr<DeviceProfile>> DeviceProfiles;
	std::ifstream ifs(deviceprofilesfile);
	json j;
	ifs >> j;
	for (json::iterator it = j.begin(); it != j.end(); ++it) {
	  std::cout << *it << std::endl;
	  std::string uuid = (*it)["DeviceProfileUuid"].get<std::string>();
	  DeviceProfiles[uuid] = std::make_shared<DeviceProfile>(*it);
	  if (DeviceProfiles[uuid]->isValid()) {
		  std::cout << "Valid Device Profile with UUID " << uuid << std::endl;
	  } else {
		  testfailed = true;
		  std::cout << "Invalid Device Profile " << uuid << std::endl;
	  }
	}
	InterfaceMap ifMap;
	HostCache hc(ifMap, 0, true);
	hc.AddByMac (MacAddress("00:00:00:00:00:01"), "192.168.1.232");
	hc.AddByMac (MacAddress("00:00:00:00:00:02"), "192.168.1.98");
	hc.AddByMac (MacAddress("00:00:00:00:00:03"), "192.168.1.99");
	hc.AddByMac (MacAddress("00:00:00:00:00:04"), "192.168.1.235");
	hc.AddByMac (MacAddress("00:00:00:00:00:05"), "192.168.1.241");
	hc.AddByMac (MacAddress("00:00:00:00:00:06"), "192.168.1.251");
	hc.AddByMac (MacAddress("00:00:00:00:00:07"), "192.168.1.234");
	hc.AddByMac (MacAddress("00:00:00:00:00:08"), "192.168.1.240");
	hc.AddByMac (MacAddress("00:00:00:00:00:09"), "192.168.1.238");
	hc.AddByMac (MacAddress("00:00:00:00:00:10"), "192.168.1.234");
	hc.AddByMac (MacAddress("00:00:00:00:00:13"), "192.168.1.80");
	hc.AddByMac (MacAddress("00:00:00:00:00:11"), "192.168.1.225");
	hc.AddByMac (MacAddress("00:00:00:00:00:12"), "192.168.1.242");
	hc.AddByMac (MacAddress("00:00:00:00:00:14"), "192.168.1.231");
	hc.AddByMac (MacAddress("00:00:00:00:00:15"), "192.168.1.133");
	hc.AddByMac (MacAddress("00:00:00:00:00:16"), "192.168.1.238");
	hc.AddByMac (MacAddress("00:00:00:00:00:17"), "192.168.1.146");
	hc.AddByMac (MacAddress("00:00:00:00:00:18"), "192.168.1.224");
	hc.AddByMac (MacAddress("00:00:00:00:00:19"), "192.168.1.239");
	hc.AddByMac (MacAddress("00:00:00:00:00:20"), "192.168.1.11");
	hc.AddByMac (MacAddress("00:00:00:00:00:21"), "192.168.1.227");
	hc.AddByMac (MacAddress("00:00:00:00:00:22"), "192.168.1.226");
	hc.AddByMac (MacAddress("00:00:00:00:00:23"), "192.168.1.248");
	hc.AddByMac (MacAddress("00:00:00:00:00:24"), "192.168.1.243");
	hc.AddByMac (MacAddress("00:00:00:00:00:25"), "192.168.1.229");
	hc.DeviceProfiles_load(deviceprofilesfile);
	DnsmasqLogFile d ("tests/dnsmasqmatchdata.log", hc, 86400, true);


	// pending good test data for dnsmasq.log that allows the matching of most of these.
	// testfailed |= ! test_match ("192.168.1.235", "694e8c7e-69f0-400f-824d-b94af7c7b7cc", hc);
	// testfailed |= ! test_match ("192.168.1.244", "dff464bf-c954-43d2-8b5a-87ef4b632da5", hc);
	// testfailed |= ! test_match ("192.168.1.251", "6e617357-5a44-4f5a-8675-5ecba34055be", hc);
	// testfailed |= ! test_match ("192.168.1.248", "7d8f2ed0-38f9-455d-a816-89a1daeb6ae2", hc);
	// testfailed |= ! test_match ("192.168.1.225", "5ec4dd66-22ee-4cd6-beed-fa4fdfd38c34", hc);
	// testfailed |= ! test_match ("192.168.1.243", "7b50c7cd-d7b9-40ad-980d-0b520ad3d05e", hc);
	// testfailed |= ! test_match ("192.168.1.229", "b2e13a63-c40b-4448-b524-3c2852bc1cb7", hc);
	// testfailed |= ! test_match ("192.168.1.227", "2ae4a61f-75f7-481f-b28c-e3534ee1e04b", hc);
	// testfailed |= ! test_match ("192.168.1.226", "76905373-748b-4e25-a550-296b3e1c7086", hc);
	// testfailed |= ! test_match ("192.168.1.224", "76905373-748b-4e25-a550-296b3e1c7086", hc);
	if (testfailed) {
		exit (1);
    }

	exit(0);
}

bool test_match (std::string inIp, std::string inDpUuid, HostCache &hc) {
	std::shared_ptr<Host> h_ptr = hc.FindHostByIp(inIp);
	if (h_ptr == nullptr) {
		std::cout << "IP address " << inIp << " not found in HostCache" << std::endl;
		return false;
	}
	h_ptr->Match(hc.DeviceProfiles_getmap());
	std::string uuid = h_ptr->Uuid_get ();
	if (uuid != inDpUuid) {
		if (uuid == "") {
			std::cout << inIp << " did not match with profile " << inDpUuid << std::endl;
		} else {
			std::cout << inIp << " did not match with profile " << inDpUuid << " but with " << uuid << std::endl;
		}
		json j;
		h_ptr->DeviceStats(j, true, true);
		std::cout << j << std::endl;
		return false;

	} else {
		std::cout << inIp << " MATCHED " << inDpUuid << std::endl;
		return true;
	}
}
