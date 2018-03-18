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
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef SSDPLOCATION_H_
#define SSDPLOCATION_H_

#include <regex>
#include <iostream>

#include <curl/curl.h>

#include <glog/logging.h>

#include "noddos.h"


class SsdpLocation {
public:
	static bool Get(SsdpHost &s, const int32_t timeout = 2000, const bool inDebug = false) {
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
        auto devicetype_rx = std::regex(R"delim(\<devicetype\>(.*?)\<\/devicetype\>)delim",
                std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);

		// auto response = cpr::Get(cpr::Url{s.Location},cpr::Timeout{timeout});

	    std::string response_string;
	    std::string header_string;
	    long response_code;
	    double elapsed;
		auto curl = curl_easy_init();
		if (curl) {
			curl_easy_setopt(curl, CURLOPT_URL, s.Location.c_str());
		    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
		    curl_easy_setopt(curl, CURLOPT_USERAGENT, "noddos/1.0.0");
		    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
		    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 0L);
		    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long) timeout * 1000);
		    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlwriteFunction);
		    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

		    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);

			if (false && inDebug) {
				// TODO test on whether STDOUT is open for writing
				// 'always' disabled as this logs to STDOUT, which is normally closed
				curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			}
		    curl_easy_perform(curl);
		    curl_easy_cleanup(curl);
		    curl = NULL;
		}
		if (elapsed > (timeout / 1000)) {
			LOG(INFO) << "Ssdp info time-out after " << timeout << " ms for " << s.Location;
			return false;
		}

		// std::string response_string = response.text;

		DLOG_IF(INFO, inDebug) << "HTTP response: " << response_string;

		std::smatch m;
		if (std::regex_search(response_string, m, friendlyname_rx)) {
			s.FriendlyName = m.str(1);
		}
		if (std::regex_search(response_string, m, manufacturer_rx)) {
			s.Manufacturer = m.str(1);
		}
		if (std::regex_search(response_string, m, manufacturerurl_rx)) {
			s.ManufacturerUrl = m.str(1);
		}
		if (std::regex_search(response_string, m, modelname_rx)) {
			s.ModelName = m.str(1);
		}
		if (std::regex_search(response_string, m, modelurl_rx)) {
			s.ModelUrl = m.str(1);
		}
        if (std::regex_search(response_string, m, devicetype_rx)) {
            s.DeviceType = m.str(1);
        }
		if (std::regex_search(response_string, m, serialnumber_rx)) {
			s.SerialNumber = m.str(1);
		}
		return true;
	}
};



#endif /* SSDPLOCATION_H_ */
