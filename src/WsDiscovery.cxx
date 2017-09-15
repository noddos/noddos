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

 * WsDiscovery.cxx
 *
 *  Created on: September 9, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#include "WsDiscovery.h"

#include <string>
#include <memory>
#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#define MSGBUFSIZE 10000

bool WsDiscovery::Probe () {
    if (Debug == true) {
        syslog (LOG_DEBUG, "WsDiscovery: sending probe to 239.255.255.250");
    }
    if (socket_fd < 0) {
        syslog (LOG_ERR, "WsDiscovery: can't send probe on socket that hasn't been opened");
        throw std::logic_error("WsDiscovery: can't send probe over socket that hasn't been opened");
    }
    unsigned char msg[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:4ed84e57-4743-412a-ab29-e7887ce6f587</wsa:MessageID></soap:Header><soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>";
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    if (inet_pton(AF_INET, "239.255.255.250", (struct sockaddr *) &(addr.sin_addr)) < 1) {
        syslog(LOG_ERR, "WsDiscovery: inet_pton");
        throw std::logic_error("WsDiscovery: inet_pton");
    }
    addr.sin_port=htons(3702);
    if (sendto(socket_fd, msg, sizeof (msg), 0, (struct sockaddr *) &addr, sizeof (addr)) <= 0) {
        syslog(LOG_ERR, "WsDiscovery: probe sendto");
        throw std::system_error(errno, std::system_category());
    }
    return true;
}

bool WsDiscovery::ParseWsDiscoveryMessage (std::shared_ptr<WsDiscoveryHost> host, const char * msgbuf, const int nbytes) {
    uint32_t pos = 0;
    std::string line = "";
    syslog (LOG_DEBUG, "Wsdiscovery message: %s", msgbuf);
    return false;
    while (pos < nbytes) {
        // Lines in SSDP packets are separated by \r\n
        if (msgbuf[pos] == '\r') {
             if (line != "") {
                 std::smatch m;
                 if(Debug) {
                     syslog(LOG_DEBUG, "WsDiscovery: Line %s", line.c_str());
                 }
                 std::regex_search(line, m, wsdiscovery_rx);
                 if (not m.empty()) {
                     std::string header = m.str(1);
                     std::transform(header.begin(), header.end(), header.begin(), std::ptr_fun<int, int>(std::toupper));
                     std::string value = m.str(2);
                     if(Debug) {
                         syslog(LOG_DEBUG, "WsDiscovery: Matched regex %s %s", header.c_str(), value.c_str());
                     }
                     /*
                     if (header == "SERVER") {
                         host->Server = value;
                     }
                     if (header == "LOCATION") {
                         host->Location = value;
                     }
                     if (header == "USER-AGENT") {
                         host->UserAgent = value;
                     }
                     */
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
    /*
    if (host->Server == "" && host->Location == "" && host->UserAgent == "") {
        return false;
    }
    */
    return true;
}
bool WsDiscovery::processEvent (struct epoll_event &event) {
    if (socket_fd != event.data.fd) {
        syslog(LOG_CRIT, "WsDiscovery: Mismatch in socket FD between class object and epoll event");
    }
    if (Debug) {
        syslog(LOG_DEBUG, "WsDiscovery: processing event");
    }
    char msgbuf[MSGBUFSIZE];
    memset(&msgbuf, 0, MSGBUFSIZE);
    struct sockaddr addr;
    memset(&addr, 0, sizeof(addr));

    socklen_t addrlen = sizeof(addr);
    int nbytes;
	// uint32_t packets = 0;
    // while (packets++ == 0 && (nbytes = recvfrom(socket_fd, msgbuf, MSGBUFSIZE, 0, &addr, &addrlen)) > 0) {
	while ((nbytes = recvfrom(socket_fd, msgbuf, MSGBUFSIZE, 0, &addr, &addrlen)) > 0) {
        if (addr.sa_family == AF_INET) {
            auto wsdHost = std::make_shared<WsDiscoveryHost>();
            struct sockaddr_in  *addr_in_ptr = (struct sockaddr_in *) &addr;
            wsdHost->IpAddress = inet_ntoa(addr_in_ptr->sin_addr);
            if(Debug) {
                syslog(LOG_DEBUG, "WsDiscovery: Received packet from %s with %d bytes", wsdHost->IpAddress.c_str(), nbytes);
            }

            if (ParseWsDiscoveryMessage(wsdHost, msgbuf, nbytes)) {
                // hCache.AddSsdpInfo(sHost);
            } else {
                if(Debug) {
                    syslog(LOG_DEBUG, "WsDiscovery: Didn't parse  packet");
                }
            }
        } else {
            syslog(LOG_WARNING, "WsDiscovery: Unknown address family: %u", addr.sa_family);
        }
    }
    if (nbytes < 0) {
        syslog(LOG_ERR, "WsDiscovery: recvfrom");
        return false;
    }
    if(Debug) {
        syslog(LOG_DEBUG, "WsDiscovery: Leaving processevent");
    }

    return true;
}
int WsDiscovery::Open (std::string input, uint32_t inExpiration) {
    IpAddress = input;
    if(Debug) {
        syslog(LOG_DEBUG, "WsDiscovery: Opening socket");
    }
    if ((socket_fd=socket(AF_INET,SOCK_DGRAM | SOCK_NONBLOCK,0)) < 0) {
        syslog(LOG_CRIT, "WsDiscovery: socket");
        throw std::system_error(errno, std::system_category());
    }
    int yes = 1;
    if (setsockopt(socket_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) < 0) {
        syslog(LOG_ERR, "WsDiscovery: Reusing ADDR failed");
        throw std::system_error(errno, std::system_category());
    }
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_ANY);
    addr.sin_port=htons(3702);
    if (bind(socket_fd,(struct sockaddr *) &addr,sizeof(addr)) < 0) {
        syslog(LOG_CRIT, "WsDiscovery: bind");
        throw std::system_error(errno, std::system_category());
    }
/*    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1) {
        flags = 0;
    }
    if ((fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK)) == -1) {
        syslog(LOG_ERR, "WsDiscovery: Set socket O_NONBLOCK");
        throw std::system_error(errno, std::system_category());
    }*/
    int flags;
    if(! (flags = (fcntl(socket_fd, F_GETFL, 0) & O_NONBLOCK))) {
        syslog(LOG_ERR, "WsDiscovery: socket O_NONBLOCK not set: %d", flags);
    }
    return socket_fd;
}

bool WsDiscovery::Close() {
    if(socket_fd >= 0) {
        close (socket_fd);
        return true;
    }
    return false;
}

int WsDiscovery::getFileHandle () { return socket_fd; }
