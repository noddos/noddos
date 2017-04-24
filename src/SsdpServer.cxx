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

 * SsdpHost.cpp
 *
 *  Created on: Mar 6, 2017
 *      Author: steven
 */


#include <iostream>
#include <memory>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "SsdpServer.h"
#include "HostCache.h"
#define MSGBUFSIZE 10000


bool SsdpServer::ProcessEvent (struct epoll_event &event) {
	if (socket_fd != event.data.fd) {
		syslog(LOG_CRIT, "Mismatch in socket FD between class object and epoll event");
	}
	char msgbuf[MSGBUFSIZE];
	memset(&msgbuf, 0, MSGBUFSIZE);
	struct sockaddr addr;
	memset(&addr, 0, sizeof(addr));

	socklen_t addrlen = sizeof(addr);
	int nbytes;
	int packets = 0;
	while (packets++ < 3 && (nbytes = recvfrom(socket_fd, msgbuf, MSGBUFSIZE, 0, &addr, &addrlen)) > 0) {
		if (addr.sa_family == AF_INET) {
			auto sHost = std::make_shared<SsdpHost>();
			struct sockaddr_in  *addr_in_ptr = (struct sockaddr_in *) &addr;
			sHost->IpAddress = inet_ntoa(addr_in_ptr->sin_addr);
			if(Debug) {
				syslog(LOG_DEBUG, "Received multicast packet from %s with %d bytes", sHost->IpAddress.c_str(), nbytes);
			}

			if (ParseSsdpMessage(sHost, msgbuf, nbytes)) {
				hCache.AddSsdpInfo(sHost);
			} else {
				if(Debug) {
					syslog(LOG_DEBUG, "Didn't parse SSDP packet");
				}
            }
		} else {
			syslog(LOG_WARNING, "Unknown address family: %u", addr.sa_family);
		}

		addrlen = sizeof(addr);
	}
	if (nbytes < 0) {
		syslog(LOG_ERR, "recvfrom");
		return false;
	}
	return true;

}


//! Parses SSDP information for certain fields, then adds this info to the Host instance
bool SsdpServer::ParseSsdpMessage (std::shared_ptr<SsdpHost> host, const char * msgbuf, const int nbytes) {
	uint32_t pos = 0;
	std::string line = "";
	while (pos < nbytes) {
		// Lines in SSDP packets are separated by \r\n
		if (msgbuf[pos] == '\r') {
			 if (line != "") {
				 std::smatch m;
				 if(Debug) {
					 syslog(LOG_DEBUG, "Line %s", line.c_str());
				 }
				 std::regex_search(line, m, ssdp_rx);
				 if (not m.empty()) {
					 std::string header = m.str(1);
					 std::transform(header.begin(), header.end(), header.begin(), std::ptr_fun<int, int>(std::toupper));
					 std::string value = m.str(2);
					 if(Debug) {
						 syslog(LOG_DEBUG, "Matched SSDP regex %s %s", header.c_str(), value.c_str());
					 }
					 if (header == "SERVER") {
						 host->Server = value;
				 	 }
					 if (header == "LOCATION") {
						 host->Location = value;
				 	 }
					 if (header == "USER-AGENT") {
						 host->UserAgent = value;
				 	 }
				 }
			 }
		 	 line.erase();
		} else {
			if (msgbuf[pos] != '\n') {
				line.push_back(msgbuf[pos]);
			}
		}
		pos++;
	}
	if (host->Server == "" && host->Location == "" && host->UserAgent == "") {
		return false;
    }
	return true;
}

int SsdpServer::Open (std::string input, uint32_t inExpiration) {
	IpAddress = input;
	if(Debug) {
		syslog(LOG_DEBUG, "Opening SsdpServer socket");
	}
	if ((socket_fd=socket(AF_INET,SOCK_DGRAM,0)) < 0) {
		syslog(LOG_CRIT, "socket");
		perror("socket");
	 	exit(1);
	}
	int yes = 1;
	if (setsockopt(socket_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) < 0) {
		syslog(LOG_ERR, "Reusing ADDR failed");
		perror("SO_REUSEADDR");
		exit(1);
	}

	struct sockaddr_in addr;
	memset(&addr,0,sizeof(addr));
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr=htonl(INADDR_ANY);
	addr.sin_port=htons(1900);
	if (bind(socket_fd,(struct sockaddr *) &addr,sizeof(addr)) < 0) {
		syslog(LOG_CRIT, "bind");
		exit(1);
	}
	int flags = fcntl(socket_fd, F_GETFD, 0);
	if (flags == -1) {
		flags = 0;
    }
	if ((fcntl(socket_fd,F_SETFD,flags | O_NONBLOCK)) == -1) {
		syslog(LOG_ERR, "Set socket O_NONBLOCK");
	}

	// TODO: add support for multiple IP addresses or interfaces to join multicast groups with
	struct ip_mreqn mreqn;
	mreqn.imr_multiaddr.s_addr=inet_addr("239.255.255.250");
	if (IpAddress == "") {
		mreqn.imr_address.s_addr=htonl(INADDR_ANY);
	} else {
		mreqn.imr_address.s_addr=inet_addr(IpAddress.c_str());
    }
	mreqn.imr_ifindex = 0;
	if (setsockopt(socket_fd,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreqn,sizeof(mreqn)) < 0) {
		syslog(LOG_CRIT, "setsockopt");
		exit(1);
	}
	return socket_fd;
}

bool SsdpServer::Close() {
	if(socket_fd >= 0) {
		close (socket_fd);
		return true;
	}
	return false;
}

int SsdpServer::GetFileHandle () { return socket_fd; }

