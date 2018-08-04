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

 * Mdns.cxx
 *
 *  Created on: September 9, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#include "Mdns.h"

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include <string>
#include <memory>
#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>

#include <cstring>

#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#define MSGBUFSIZE 10000

#define MDNS_GROUP "224.0.0.251"
#define MDNS_PORT 5353

bool Mdns::parseMessage (std::shared_ptr<MdnsHost> host, const unsigned char * msgbuf, const int nbytes) {
    uint32_t pos = 0;

    if (nbytes < 12) {
        LOG(INFO) << "Malformed mDNS packet smaller than 12 bytes";
        throw std::runtime_error ("malformed mDNS TXT record");
    }
    Tins::DNS *q;
    try {
        q = new Tins::DNS(msgbuf, nbytes);
    } catch (const Tins::malformed_packet &e) {
        LOG(INFO) << "Malformed mDNS packet";
        throw std::runtime_error ("malformed mDNS TXT record");
    }
    DLOG_IF(INFO, Debug) << "Query ID: " << q->id();
    DLOG_IF(INFO, Debug) << "Questions: " << q->questions_count()
                                        << "Answers: " << q->answers_count()
                                        << "Additional answers: " << q->additional_count();
    if (q->answers_count() == 0) {
        delete q;
        return false;
    }
    Tins::DNS::resources_type rt = q->answers();
    Tins::DNS::resources_type rt_additional = q->additional();
    rt.insert (rt.begin(), rt_additional.begin(), rt_additional.end());
    uint16_t i = 0;
    for (auto it : rt) {
        char ipaddr[INET6_ADDRSTRLEN];
        if (it.query_type() != 41) { // OPT pseudo-RR
            DLOG_IF(INFO, Debug) << "Answer " << ++i << ": " << it.dname() << " "
                    << it.ttl() << " " << it.query_class()
                    << " " << it.query_type();
            std::string dnsdata = it.data();
            switch (it.query_type()) {
            case Tins::DNS::QueryType::A: {
                DLOG_IF(INFO, Debug) << "A record: " << it.data();
                Tins::IPv4Address ip(it.data());
                break;
            }
            case Tins::DNS::QueryType::AAAA: {
                Tins::IPv6Address ip(it.data());
                DLOG_IF(INFO, Debug) << "AAAA record: " << ip;
                break;
            }
            case Tins::DNS::QueryType::CNAME:
                DLOG_IF(INFO, Debug) << "CNAME record: " << dnsdata;
                break;
            case Tins::DNS::QueryType::PTR:
                DLOG_IF(INFO, Debug) << "PTR record: " << dnsdata;
                // We give preference to FQDN in TXT record
                if (host->Hostname == "") {
                    host->Hostname = it.dname();
                }
                break;
            case Tins::DNS::QueryType::TXT:
                DLOG_IF(INFO, Debug) << "TXT record: " << dnsdata;
                // We give preference to FQDN in TXT record
                host->Hostname = it.dname();
                parseTxtRr(host, dnsdata);
                break;
            case Tins::DNS::QueryType::SRV:
                DLOG_IF(INFO, Debug) << "SRV record: " << dnsdata;
                // We give preference to FQDN in TXT record
                if (host->Hostname == "") {
                    host->Hostname = it.dname();
                }
                break;
            default:
                DLOG_IF(INFO, Debug) << "unhandled resource record type " << it.query_type() << ": " << dnsdata;
                break;
            }
        } else {
            DLOG_IF(INFO, Debug) << "RR OPT";
        }
    }
    delete q;
    return true;
}

void Mdns::parseTxtRr (std::shared_ptr<MdnsHost> host, const std::string txt) {
    size_t stridx = 0;
    size_t txtlen = txt.length();
    while (stridx < txtlen) {
        unsigned char len = txt[stridx++];
        if (stridx + len > txtlen) {
            LOG(INFO) << "malformed mDNS TXT record";
            throw std::runtime_error ("malformed mDNS TXT record");
        }
        size_t keylength = txt.find("=", stridx) - stridx;
        if (keylength == std::string::npos) {
            LOG(INFO) << "malformed mDNS TXT record with '=' separating key and value";
            throw std::runtime_error ("malformed mDNS TXT record");
        }
        std::string key = txt.substr(stridx, keylength);
        std::transform(key.begin(),key.end(), key.begin(), ::tolower);
        size_t valuepos = stridx + keylength + 1;
        size_t valuelength = len - keylength - 1;
        DLOG_IF(INFO, Debug) << "TXT-len: " << txtlen <<", strindex: " << stridx
                << ", kv-pair length: " << len << ", key-length: " << keylength
                << ", value-length " << valuelength;
        std::string value = txt.substr(valuepos, valuelength);
        stridx += len;
        DLOG_IF(INFO, Debug) << "TXT record kv-pair " << key << " = " << value;
        if (key == "os") {
            host->Os = value;
        } else if(key == "hw") {
            host->Hw = value;
        } else if (key == "md" || key == "mdl" || key == "usb_mdl") {
            host->ModelName = value;
        } else if (key == "mfg" || key == "usb_mfg") {
            host->Manufacturer = value;
        } else if (key == "adminurl") {
            host->DeviceUrl = value;
        }
    }
}


bool Mdns::processEvent (struct epoll_event &event) {
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
            auto mdnsHost = std::make_shared<MdnsHost>();
            struct sockaddr_in  *addr_in_ptr = (struct sockaddr_in *) &addr;
            mdnsHost->IpAddress = inet_ntoa(addr_in_ptr->sin_addr);
            DLOG_IF(INFO, Debug) << "Received packet from " << mdnsHost->IpAddress
                    << " with " << nbytes << " bytes";
            try {
                if (parseMessage(mdnsHost, msgbuf, nbytes) == true) {
                    hCache.addMdnsInfo(mdnsHost);
                }
            } catch (...) {
                DLOG_IF(INFO, Debug) << "Couldn't parse packet";
            }
        } else {
            LOG(WARNING) << "Unknown address family: ", addr.sa_family;
        }
    }
    if (nbytes < 0 && ! (errno == EWOULDBLOCK || errno == EAGAIN)) {
        PLOG(ERROR) << "recvfrom";
        return false;
    }
    return true;
}
int Mdns::Open (std::string input, uint32_t inExpiration) {
    IpAddress = input;
    DLOG_IF(INFO, Debug) << "Opening socket";
    if ((socket_fd=socket(AF_INET,SOCK_DGRAM | SOCK_NONBLOCK,0)) < 0) {
        PLOG(ERROR) << "socket";
        throw std::system_error(errno, std::system_category());
    }
    int yes = 1;
    if (setsockopt(socket_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) < 0) {
        PLOG(ERROR) << "Reusing ADDR failed";
        throw std::system_error(errno, std::system_category());
    }
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_ANY);
    addr.sin_port=htons(MDNS_PORT);
    if (bind(socket_fd,(struct sockaddr *) &addr,sizeof(addr)) < 0) {
        PLOG(ERROR) << "bind";
        throw std::system_error(errno, std::system_category());
    }
    // TODO: add support for multiple IP addresses or interfaces to join multicast groups with
    struct ip_mreqn mreqn;
    mreqn.imr_multiaddr.s_addr=inet_addr(MDNS_GROUP);
    if (IpAddress == "") {
        mreqn.imr_address.s_addr=htonl(INADDR_ANY);
    } else {
        mreqn.imr_address.s_addr=inet_addr(IpAddress.c_str());
    }
    mreqn.imr_ifindex = 0;
    if (setsockopt(socket_fd,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreqn,sizeof(mreqn)) < 0) {
        PLOG(ERROR) <<  "setsockopt";
        throw std::system_error(errno, std::system_category());
    }
    return socket_fd;
}

bool Mdns::Close() {
    if(socket_fd >= 0) {
        close (socket_fd);
        return true;
    }
    return false;
}

int Mdns::getFileHandle () { return socket_fd; }
