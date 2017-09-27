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

#include "boost/asio.hpp"

#define MSGBUFSIZE 10000

#define MDNS_GROUP "224.0.0.251"
#define MDNS_PORT 5353

bool Mdns::parseMessage (std::shared_ptr<MdnsHost> host, const unsigned char * msgbuf, const int nbytes) {
    uint32_t pos = 0;

    if (nbytes < 12) {
        syslog(LOG_NOTICE, "Mdns: Malformed mDNS packet smaller than 12 bytes");
        throw std::runtime_error ("Mdns: malformed mDNS TXT record");
    }
    Tins::DNS *q;
    try {
        q = new Tins::DNS(msgbuf, nbytes);
    } catch (const Tins::malformed_packet &e) {
        if (Debug == true) {
            syslog(LOG_NOTICE, "Mdns: Malformed mDNS packet");
        }
        throw std::runtime_error ("Mdns: malformed mDNS TXT record");
    }
    if (Debug == true) {
        syslog(LOG_DEBUG, "Mdns: Query ID: %u", q->id());
        syslog(LOG_DEBUG, "Mdns: Questions: %u Answers: %u Additional answers: %u",
                q->questions_count(), q->answers_count(),
                q->additional_count());
    }
    if (q->answers_count == 0) {
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
            if (Debug == true) {
                syslog(LOG_DEBUG, "Mdns: Answer %u : %-24s %5u %u %u", ++i,
                        it.dname().c_str(), it.ttl(), it.query_class(),
                        it.query_type());
            }
            std::string dnsdata = it.data();
            switch (it.query_type()) {
            case Tins::DNS::QueryType::A: {
                if (Debug == true) {
                    syslog(LOG_DEBUG, "Mdns: A record: %s",
                            it.data().c_str());
                }
                boost::asio::ip::address ip = boost::asio::ip::address::from_string(it.data());
                break;
            }
            case Tins::DNS::QueryType::AAAA: {
                boost::asio::ip::address ip = boost::asio::ip::address::from_string(it.data());
                if (Debug == true) {
                    syslog(LOG_DEBUG, "Mdns: AAAA record: %s",
                            ip.to_string().c_str());
                }
                break;
            }
            case Tins::DNS::QueryType::CNAME:
                if (Debug == true) {
                    syslog(LOG_DEBUG, "Mdns: CNAME record: %s", dnsdata.c_str());
                }
                break;
            case Tins::DNS::QueryType::PTR:
                if (Debug == true) {
                    syslog(LOG_DEBUG, "Mdns: PTR record: %s", dnsdata.c_str());
                }
                break;
            case Tins::DNS::QueryType::TXT:
                if (Debug == true) {
                    syslog(LOG_DEBUG, "Mdns: TXT record: %s", dnsdata.c_str());
                }
                parseTxtRr(host, dnsdata);
                break;
            case Tins::DNS::QueryType::SRV:
                if (Debug == true) {
                    syslog(LOG_DEBUG, "Mdns: SRV record: %s", dnsdata.c_str());
                }
                break;
            default:
                if (Debug == true) {
                    syslog(LOG_DEBUG, "Mdns: unhandled resource record type %d: %s", it.query_type(), dnsdata.c_str());
                }
                break;
            }
        } else {
            if (Debug == true) {
                syslog(LOG_DEBUG, "Mdns: RR OPT");
            }
        }
    }
    delete q;
    return true;
}

void Mdns::parseTxtRr (std::shared_ptr<MdnsHost> host, const std::string txt) {
    size_t stridx = 0;
    while (stridx < txt.length()) {
        size_t len = txt[stridx++];
        if (stridx + len > txt.length()) {
            if(Debug == true) {
                syslog (LOG_NOTICE, "Mdns: malformed mDNS TXT record");
            }
            throw std::runtime_error ("Mdns: malformed mDNS TXT record");
        }
        size_t keylength = txt.find("=", stridx) - stridx;
        if (keylength == std::string::npos) {
            if(Debug == true) {
                syslog (LOG_NOTICE, "Mdns: malformed mDNS TXT record with '=' separating key and value");
            }
            throw std::runtime_error ("Mdns: malformed mDNS TXT record");
        }
        std::string key = txt.substr(stridx, keylength);
        std::transform(key.begin(),key.end(), key.begin(), ::tolower);
        size_t valuepos = stridx + keylength + 1;
        size_t valuelength = len - keylength - 1;
        if(Debug == true) {
            syslog (LOG_DEBUG, "Mdns: strindex: %zd, kv-pair length: %zd, key-length: %zd, value-length %zd", stridx, len, keylength, valuelength);
        }
        std::string value = txt.substr(valuepos, valuelength);
        stridx += len;
        if (Debug == true) {
            syslog(LOG_DEBUG, "Mdns: TXT record kv-pair %s = %s",
                    key.c_str(), value.c_str());
        }
        if (key == "os") {
            host->Os = value;
        } else if(key == "hw") {
            host->Hw = value;
        } else if (key == "md" || key == "usb_mdl") {
            host->ModelName = value;
        } else if (key == "usb_mfg") {
            host->Manufacturer = value;
        } else if (key == "adminurl") {
            host->DeviceUrl = value;
        }
    }
}


bool Mdns::processEvent (struct epoll_event &event) {
    if (socket_fd != event.data.fd) {
        syslog(LOG_CRIT, "Mdns: Mismatch in socket FD between class object and epoll event");
    }
    if (Debug == true) {
        syslog(LOG_DEBUG, "Mdns: processing event");
    }
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
            if(Debug) {
                syslog(LOG_DEBUG, "Mdns: Received packet from %s with %d bytes", mdnsHost->IpAddress.c_str(), nbytes);
            }

            try {
                if (parseMessage(mdnsHost, msgbuf, nbytes) == true) {
                    hCache.AddMdnsInfo(mdnsHost);
                }
            } catch (...) {
                if(Debug) {
                    syslog(LOG_DEBUG, "Mdns: Couldn't parse packet");
                }
            }
        } else {
            syslog(LOG_WARNING, "Mdns: Unknown address family: %u", addr.sa_family);
        }
    }
    if (nbytes < 0 && ! (errno == EWOULDBLOCK || errno == EAGAIN)) {
        syslog(LOG_ERR, "Mdns: recvfrom");
        return false;
    }
    return true;
}
int Mdns::Open (std::string input, uint32_t inExpiration) {
    IpAddress = input;
    if(Debug) {
        syslog(LOG_DEBUG, "Mdns: Opening socket");
    }
    if ((socket_fd=socket(AF_INET,SOCK_DGRAM | SOCK_NONBLOCK,0)) < 0) {
        syslog(LOG_CRIT, "Mdns: socket");
        throw std::system_error(errno, std::system_category());
    }
    int yes = 1;
    if (setsockopt(socket_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) < 0) {
        syslog(LOG_ERR, "Mdns: Reusing ADDR failed");
        throw std::system_error(errno, std::system_category());
    }
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_ANY);
    addr.sin_port=htons(MDNS_PORT);
    if (bind(socket_fd,(struct sockaddr *) &addr,sizeof(addr)) < 0) {
        syslog(LOG_CRIT, "Mdns: bind");
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
        syslog(LOG_CRIT, "setsockopt");
        throw std::system_error(errno, std::system_category());
    }    return socket_fd;
}

bool Mdns::Close() {
    if(socket_fd >= 0) {
        close (socket_fd);
        return true;
    }
    return false;
}

int Mdns::getFileHandle () { return socket_fd; }
