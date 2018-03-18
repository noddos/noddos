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
    DLOG_IF(INFO, Debug) << "sending probe to 239.255.255.250";
    if (socket_fd < 0) {
        LOG(ERROR) << "can't send probe on socket that hasn't been opened";
        throw std::logic_error("can't send probe over socket that hasn't been opened");
    }
    unsigned char msg[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:4ed84e57-4743-412a-ab29-e7887ce6f587</wsa:MessageID></soap:Header><soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>";
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    if (inet_pton(AF_INET, "239.255.255.250", (struct sockaddr *) &(addr.sin_addr)) < 1) {
        PLOG(ERROR) << "inet_pton";
        throw std::logic_error("inet_pton");
    }
    addr.sin_port=htons(3702);
    if (sendto(socket_fd, msg, sizeof (msg), 0, (struct sockaddr *) &addr, sizeof (addr)) <= 0) {
        PLOG(ERROR) << "probe sendto";
        throw std::system_error(errno, std::system_category());
    }
    return true;
}

bool WsDiscovery::ParseWsDiscoveryMessage (std::shared_ptr<WsDiscoveryHost> host, const unsigned char * msgbuf, const int nbytes) {
    uint32_t pos = 0;
    DLOG_IF(INFO, Debug) << "message: %s", msgbuf;

    std::string line = (char *) msgbuf;
    std::smatch m;
    std::regex_search(line, m, wsdxaddrs_rx);
    if (not m.empty()) {
        host->wsdXAddrs = m.str(1);
        DLOG_IF(INFO, Debug) << "Matched XAddrs regex " << host->wsdXAddrs;
    }
    std::regex_search(line, m, wsdtypes_rx);
    if (not m.empty()) {
        host->wsdTypes = m.str(1);
        DLOG_IF(INFO, Debug) << "Matched Types regex " << host->wsdTypes;
    }
    if (host->wsdXAddrs == "" && host->wsdTypes == "") {
        return false;
    }
    return true;
}
bool WsDiscovery::processEvent (struct epoll_event &event) {
    if (socket_fd != event.data.fd) {
        LOG(ERROR) << "Mismatch in socket FD between class object and epoll event";
    }
    DLOG_IF(INFO, Debug) << "processing event";
    unsigned char msgbuf[MSGBUFSIZE];
    memset(&msgbuf, 0, MSGBUFSIZE);
    struct sockaddr addr;
    memset(&addr, 0, sizeof(addr));

    socklen_t addrlen = sizeof(addr);
    int nbytes;
	while ((nbytes = recvfrom(socket_fd, msgbuf, MSGBUFSIZE, 0, &addr, &addrlen)) > 0) {
        if (addr.sa_family == AF_INET) {
            auto wsdHost = std::make_shared<WsDiscoveryHost>();
            struct sockaddr_in  *addr_in_ptr = (struct sockaddr_in *) &addr;
            wsdHost->IpAddress = inet_ntoa(addr_in_ptr->sin_addr);
            DLOG_IF(INFO, Debug) << "Received packet from " << wsdHost->IpAddress
                    << " with " << nbytes << " bytes";

            if (ParseWsDiscoveryMessage(wsdHost, msgbuf, nbytes)) {
                hCache.AddWsDiscoveryInfo(wsdHost);
            } else {
                DLOG_IF(INFO, Debug) << "Didn't parse packet";
            }
        } else {
            LOG(WARNING) << "Unknown address family: " << addr.sa_family;
        }
    }
    if (nbytes < 0 && ! (errno == EWOULDBLOCK || errno == EAGAIN)) {
        PLOG(ERROR) << "recvfrom";
        return false;
    }
    DLOG_IF(INFO, Debug) << "Leaving processevent";

    return true;
}

int WsDiscovery::Open (std::string input, uint32_t inExpiration) {
    IpAddress = input;
    DLOG_IF(INFO, Debug) << "Opening socket";
    if ((socket_fd=socket(AF_INET,SOCK_DGRAM | SOCK_NONBLOCK,0)) < 0) {
        PLOG(ERROR) << "socket";
        throw std::system_error(errno, std::system_category());
    }
    int yes = 1;
    if (setsockopt(socket_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) < 0) {
        PLOG(ERROR) << "Reusing ADDR failed";
        close (socket_fd);
        socket_fd = -1;
        throw std::system_error(errno, std::system_category());
    }
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_ANY);
    addr.sin_port=htons(0);
    if (bind(socket_fd,(struct sockaddr *) &addr,sizeof(addr)) < 0) {
        LOG(ERROR) << "bind";
        close (socket_fd);
        socket_fd = -1;
        throw std::system_error(errno, std::system_category());
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
