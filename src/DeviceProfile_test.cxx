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

int main()
{
	std::map<std::string, std::shared_ptr<DeviceProfile>> DeviceProfiles;
	std::ifstream ifs("tests/DeviceProfiles.json");
	json j;
	ifs >> j;
	bool invalid = false;
	for (json::iterator it = j.begin(); it != j.end(); ++it) {
	  std::cout << *it << std::endl;
	  std::string uuid = (*it)["DeviceProfileUuid"].get<std::string>();
	  DeviceProfiles[uuid] = std::make_shared<DeviceProfile>(*it);
	  if (DeviceProfiles[uuid]->isValid()) {
		  std::cout << "Valid Device Profile with UUID " << uuid << std::endl;
	  } else {
		  invalid = true;
		  std::cout << "Invalid Device Profile " << uuid << std::endl;
	  }
	}
	if (invalid) {
		exit (1);
    }
	HostCache hc(true);
	hc.AddByMac ("00:00:00:00:00:01", "192.168.1.232");
	hc.AddByMac ("00:00:00:00:00:02", "192.168.1.98");
	hc.AddByMac ("00:00:00:00:00:03", "192.168.1.99");
	hc.AddByMac ("00:00:00:00:00:04", "192.168.1.235");
	hc.AddByMac ("00:00:00:00:00:05", "192.168.1.241");
	hc.AddByMac ("00:00:00:00:00:06", "192.168.1.251");
	hc.AddByMac ("00:00:00:00:00:07", "192.168.1.234");
	hc.AddByMac ("00:00:00:00:00:08", "192.168.1.240");
	hc.AddByMac ("00:00:00:00:00:09", "192.168.1.238");
	hc.AddByMac ("00:00:00:00:00:10", "192.168.1.234");
	hc.DeviceProfiles_load(deviceprofilesfile);
	DnsmasqLogFile d ("tests/dnsmasqdnsdata.log", hc, 86400);
	hc.Match();

	exit(0);
}
