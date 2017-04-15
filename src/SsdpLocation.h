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

 * SsdpLocation.h
 *
 *  Created on: Mar 19, 2017
 *      Author: steven
 */

#ifndef SSDPLOCATION_H_
#define SSDPLOCATION_H_

#include <regex>
#include <syslog.h>

#include "cpr/cpr.h"



#include "noddos.h"
#include "SsdpHost.h"

class SsdpLocation {
public:
	static bool Get(SsdpHost &s, int32_t timeout = 2000) {
		auto friendlyname_rx = std::regex(R"delim(\<friendlyname\>(.*?)\<\/friendlyname\>)delim",
		    	std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
		auto manufacturer_rx = std::regex(R"delim(<manufacturer\>(.*?)\<\/manufacturer\>)delim",
				std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
		auto manufacturerurl_rx = std::regex(R"delim(\<manufacturerurl\>(.*?)\<\/manufacturerurl\>)delim",
				std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
		auto modelname_rx = std::regex(R"delim(\<modelname\>(.*?)\<\/modelname>)delim",
				std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
		auto modelurl_rx = std::regex(R"delim(\<modelurl\>(.*?)\<\/modelurl\>)delim",
				std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
		auto udn_rx = std::regex(R"delim(\<udn\>(.*?)\<\/udn\>)delim",
				std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
		auto serialnumber_rx = std::regex(R"delim(\<serialnumber\>(.*?)\<\/serialnumber\>)delim",
				std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);

		auto response = cpr::Get(cpr::Url{s.Location},cpr::Timeout{timeout});
		if (response.elapsed > 2000) {
			syslog(LOG_WARNING, "Ssdp info time-out after %d ms for %s", timeout, s.Location.c_str());
			return false;
		}

		syslog(LOG_DEBUG, "%s", response.text.c_str());

		std::smatch m;
		if (std::regex_search(response.text, m, friendlyname_rx))
			s.FriendlyName = m.str(1);
		if (std::regex_search(response.text, m, manufacturer_rx))
			s.Manufacturer = m.str(1);
		if (std::regex_search(response.text, m, manufacturerurl_rx))
			s.ManufacturerUrl = m.str(1);
		if (std::regex_search(response.text, m, modelname_rx))
			s.ModelName = m.str(1);
		if (std::regex_search(response.text, m, modelurl_rx))
			s.ModelUrl = m.str(1);
		if (std::regex_search(response.text, m, serialnumber_rx))
			s.SerialNumber = m.str(1);
		return true;
	}
};

#endif /* SSDPLOCATION_H_ */
