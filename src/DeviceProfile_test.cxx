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


#include "DeviceProfile.h"

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
	exit(0);
}
