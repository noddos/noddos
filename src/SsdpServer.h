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

 * SsdpHost.h
 *
 *  Created on: Mar 6, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef SSDPSERVER_H_
#define SSDPSERVER_H_

#include <regex>
#include <string>
#include <ctime>
#include <memory>
#include <sys/epoll.h>


#include "iDeviceInfoSource.h"
#include "HostCache.h"
#include "noddos.h"

class SsdpServer : public iDeviceInfoSource {
private:
	std::string IpAddress;
	int socket_fd;
	time_t Expiration;
	HostCache &hCache;
	bool Debug;

	std::regex ssdp_rx;


public:
	SsdpServer(HostCache &inhCache, const time_t inExpiration, const std::string inIpAddress = "", const bool inDebug = false):
	        hCache{inhCache}, Expiration{inExpiration}, IpAddress{inIpAddress}, Debug{inDebug} {
		if (Debug == true) {
		    syslog (LOG_DEBUG, "SsdpServer: constructing instance");
		}
	    ssdp_rx = std::regex(R"delim(^(SERVER|LOCATION|NT|USN|USER-AGENT): (.*)$)delim",
				std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);

		socket_fd = -1;
		Open (IpAddress);

	}
	virtual ~SsdpServer() {
		Close();
		if(Debug) {
			syslog (LOG_DEBUG, "SsdpServer: destructing instance");
		}
	}

	bool ParseSsdpMessage (std::shared_ptr<SsdpHost> host, const char * msgbuf, const int nbytes);
	int Open(std::string input, uint32_t inExpiration = 0);
	bool Close();
	bool processEvent(struct epoll_event &event);
	int getFileHandle();

};

#endif /* SSDPSERVER_H_ */
