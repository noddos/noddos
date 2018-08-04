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

 * PacketSnoop.cxx
 *
 *  Created on: May 28, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include "InterfaceMap.h"
#include "PacketSnoop.h"
#include "TcpSnoop.h"



int PacketSnoop::Open(std::string input, uint32_t inExpiration) {
    // BPF filter, created with:
    // sudo tcpdump -dd '(ip or ip6) and ((tcp or udp) and port 53) or (udp and (port 67 or port 68))'
    struct sock_filter bpfcode[] = {
            { 0x28, 0, 0, 0x0000000c },
            { 0x15, 0, 19, 0x00000800 },
            { 0x30, 0, 0, 0x00000017 },
            { 0x15, 0, 7, 0x00000006 },
            { 0x28, 0, 0, 0x00000014 },
            { 0x45, 33, 0, 0x00001fff },
            { 0xb1, 0, 0, 0x0000000e },
            { 0x48, 0, 0, 0x0000000e },
            { 0x15, 29, 0, 0x00000035 },
            { 0x48, 0, 0, 0x00000010 },
            { 0x15, 27, 28, 0x00000035 },
            { 0x15, 0, 27, 0x00000011 },
            { 0x28, 0, 0, 0x00000014 },
            { 0x45, 25, 0, 0x00001fff },
            { 0xb1, 0, 0, 0x0000000e },
            { 0x48, 0, 0, 0x0000000e },
            { 0x15, 21, 0, 0x00000035 },
            { 0x15, 20, 0, 0x00000043 },
            { 0x15, 19, 0, 0x00000044 },
            { 0x48, 0, 0, 0x00000010 },
            { 0x15, 17, 15, 0x00000035 },
            { 0x15, 0, 17, 0x000086dd },
            { 0x30, 0, 0, 0x00000014 },
            { 0x15, 0, 4, 0x00000006 },
            { 0x28, 0, 0, 0x00000036 },
            { 0x15, 12, 0, 0x00000035 },
            { 0x28, 0, 0, 0x00000038 },
            { 0x15, 10, 11, 0x00000035 },
            { 0x15, 10, 0, 0x0000002c },
            { 0x15, 0, 9, 0x00000011 },
            { 0x28, 0, 0, 0x00000036 },
            { 0x15, 6, 0, 0x00000035 },
            { 0x15, 5, 0, 0x00000043 },
            { 0x15, 4, 0, 0x00000044 },
            { 0x28, 0, 0, 0x00000038 },
            { 0x15, 2, 0, 0x00000035 },
            { 0x15, 1, 0, 0x00000043 },
            { 0x15, 0, 1, 0x00000044 },
            { 0x6, 0, 0, 0x00040000 },
            { 0x6, 0, 0, 0x00000000 },
    };
    struct sock_fprog bpf = { .len = size(bpfcode), .filter = bpfcode, };

    DLOG_IF(INFO, Debug) << "Opening AF_PACKET SOCK_RAW with ETH_P_ALL on interface " << input;
    // ETH_P_ALL is required to also capture outgoing packets
    // TPACKET_V3: https://gist.github.com/giannitedesco/5863705
    // Kernel 3.19 required: http://www.spinics.net/lists/netdev/msg309630.html
    sock = socket( AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        PLOG(FATAL) << "Socket error";
        throw std::system_error(errno, std::system_category());
    }
    int val = TPACKET_V3;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &val, sizeof(val))) {
        PLOG(FATAL) << "setsockopt(TPACKET_V3)";
        Close();
        throw std::system_error(errno, std::system_category());
    }
    int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if (ret < 0) {
        PLOG(FATAL) << "setsockopt error";
        Close();
        throw std::system_error(errno, std::system_category());
    }

    struct tpacket_req3 req;

    req.tp_block_size = getpagesize() << 2;
    req.tp_block_nr = numBlocks;
    req.tp_frame_size = TPACKET_ALIGNMENT << 7;
    req.tp_frame_nr = req.tp_block_size / req.tp_frame_size * req.tp_block_nr;
    req.tp_retire_blk_tov = 64;
    req.tp_sizeof_priv = sizeof(struct priv);
    req.tp_feature_req_word = 0;
    //req.tp_feature_req_word |= TP_REQ_FILL_RXHASH;
    if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (char *)&req, sizeof(req))) {
        PLOG(FATAL) << "setsockopt(PACKET_RX_RING)";
        Close();
        throw std::system_error(errno, std::system_category());
    };

    map_sz = req.tp_block_size * req.tp_block_nr;
    nr_blocks = req.tp_block_nr;
    block_sz = req.tp_block_size;

    struct sockaddr_ll sll;

    if (input != "") {
        struct ifreq ifr;
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", input.c_str());
        if ( ioctl(sock, SIOCGIFINDEX, &ifr) ) {
            PLOG(FATAL) << "ioctl";
            Close();
            throw std::system_error(errno, std::system_category());
        }
        ifindex = ifr.ifr_ifindex;
    }else{
        /* interface "any" */
        ifindex = 0;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if ( bind(sock, (struct sockaddr *)&sll, sizeof(sll)) ) {
        PLOG(FATAL) << "bind()";
        Close();
        throw std::system_error(errno, std::system_category());
    }

    map = (uint8_t *) mmap(nullptr, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
    if ((char *) map == MAP_FAILED) {
        LOG(FATAL) << "mmap()";
        Close();
        throw std::system_error(errno, std::system_category());
    }
    DLOG_IF(INFO, Debug) << "Successfully opened AF_PACKET SOCK_RAW with ETH_P_ALL on interface "
            << input;

    return sock;
}

bool PacketSnoop::Close () {
    pruneTcpSnoopInstances(true);

    if (map != nullptr && (char *) map != MAP_FAILED) {
        if (munmap(map, map_sz)) {
            PLOG(ERROR) << "munmap";
            return true;
        }
    }
    if (sock >= 0) {
        if (close (sock)) {
            PLOG(WARNING) << "Error closing PacketSnoop socket";
            return true;
        }
    }
    sock = -1;
    return false;
}

bool PacketSnoop::processEvent(struct epoll_event &event) {
    int ret;
    LOG(INFO) << "Received AF_PACKET event";

    struct tpacket_block_desc *desc = (struct tpacket_block_desc *) (map + r_idx * block_sz);

    if (!(desc->hdr.bh1.block_status & TP_STATUS_USER)) {
        LOG(INFO) << "Packet is not yet handed over to user-space";
        return true;

    }
    const uint8_t *ptr;
    struct tpacket3_hdr *hdr;
    unsigned int num_pkts, i;

    ptr = (uint8_t *)desc + desc->hdr.bh1.offset_to_first_pkt;
    num_pkts = desc->hdr.bh1.num_pkts;

    for(i = 0; i < num_pkts; i++) {
        LOG(INFO) << "Processing packet " << i+1 << " of " << num_pkts;
        hdr = (struct tpacket3_hdr *)ptr;

        Parse((unsigned char *) ptr + hdr->tp_mac);

        ptr += hdr->tp_next_offset;
        __sync_synchronize();
    }
    desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
    __sync_synchronize();
    r_idx = (r_idx + 1) % nr_blocks;
    return false;
}


bool PacketSnoop::Parse(unsigned char *frame) {
    LOG_IF(INFO, Debug) << "Parsing packet on interface " << ifindex;

    struct ethhdr *ethh = (struct ethhdr *) frame;
    uint8_t af;
    unsigned short iphdrlen;
    unsigned short protocol;
    bool isIPv4 = true;
    uint16_t ipPayloadLen = 0;
    uint16_t ipPacketLen = 0;

    std::string srcString, destString;
    // char srcString[INET6_ADDRSTRLEN], destString[INET6_ADDRSTRLEN];

    Tins::IPv4Address srcv4, dstv4;
    Tins::IPv6Address srcv6, dstv6;
    if (ntohs(ethh->h_proto) == 0x0800) {
        af = AF_INET;
        struct iphdr *iph = (struct iphdr*) (frame + sizeof(struct ethhdr));
        iphdrlen = iph->ihl * 4;
        if (iphdrlen < sizeof(struct iphdr)) {
            // Packet is broken!
            // IP packets must not be smaller than the mandatory IP header.
            LOG(INFO) << "Received packet with invalid IP header length: " << iphdrlen;
            return false;
        }
        if (in_cksum((void *) iph, iphdrlen, 0) != 0) {
            // Packet is broken!
            // Checksum of IP header does not verify, thus header is corrupt.
            LOG(INFO) << "Received packet with invalid IP checksum";
            return false;
        }
        ipPacketLen = ntohs(iph->tot_len);
        if (ipPacketLen < iphdrlen) {
            // Packet is broken!
            // The overall packet cannot be smaller than the header.
            LOG(INFO) << "Received packet with packet length " << ipPacketLen
                    << " smaller than header length " << iphdrlen;
            return false;
        }
        ipPayloadLen = ipPacketLen - iphdrlen;
        if (ipPayloadLen < sizeof(struct tcphdr)) {
            // Packet is broken!
            // A TCP header doesn't even fit into the data that follows the IP header.
            LOG(INFO) << "Received packet with payload length " << ipPayloadLen
                    << " smaller than TCP header length " << sizeof(struct tcphdr);
            return false;
        }
        uint8_t ipFlags = (uint8_t) (iph->frag_off >> 13);
        if ((ipFlags & 1) == 1) {
            LOG(INFO) << "PacketSnoop: Fragmented IPv4 packets are not supported, discarding";
            return false;
        }
        protocol = iph->protocol;
        srcv4 = Tins::IPv4Address(iph->saddr);
        dstv4 = Tins::IPv4Address(iph->daddr);
        srcString = srcv4.to_string();
        destString = dstv4.to_string();

    } else if (ntohs(ethh->h_proto) == 0x86DD) {
        isIPv4 = false;
        af = AF_INET6;
        iphdrlen = 40;
        struct ipv6hdr *ipv6h =
                (struct ipv6hdr*) (frame + sizeof(struct ethhdr));
        ipPayloadLen = ntohs(ipv6h->payload_len);
        if (ipv6h->nexthdr != 6 && ipv6h->nexthdr != 17) {
            LOG(INFO) <<
                    "PacketSnoop: Sorry, only support for IPv6 without optional headers for now "
                    << ipv6h->nexthdr;
            return true;
        }
        protocol = ipv6h->nexthdr;
        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop(af, &(ipv6h->saddr), buf, INET6_ADDRSTRLEN)
                == nullptr) {
            LOG(ERROR) << "PacketSnoop: Received packet with invalid source IPv6 address";
            return false;
        }
        srcv6 = Tins::IPv6Address(buf);

        if (inet_ntop(af, &(ipv6h->daddr), buf, INET6_ADDRSTRLEN)
                == nullptr) {
            LOG(ERROR) << "PacketSnoop: Received packet with invalid destination IPv6 address";
            return false;
        }
        dstv6 = Tins::IPv6Address(buf);

        srcString = srcv6.to_string();
        destString = dstv6.to_string();
    } else {
        LOG(INFO) << "PacketSnoop: Received packet with unsupported protocol "
                << ethh->h_proto;
        return true;
    }

    MacAddress Mac(ethh->h_source);

    LOG_IF(INFO, Debug) <<
            "PacketSnoop: Parsing " << (ntohs(ethh->h_proto) == 0x0800 ? "IPv4" : "IPv6")
            << "packet from " << srcString << " to " << destString << ", protocol " << protocol
            << ", packet size " << ipPacketLen << ", header length " << iphdrlen << " payload length "
            << ipPayloadLen << " from MAC " << Mac;

    //Check the Protocol and do accordingly...
    switch (protocol) {
    case 6: //TCP Protocol
    {
        struct tcphdr *tcph = (struct tcphdr*) (frame + iphdrlen + sizeof(struct ethhdr));
        if (ipPacketLen < (iphdrlen + tcph->doff * 4)) {
            LOG_IF(INFO, Debug) <<
                    "PacketSnoop: Received packet with IP packet length < ip header + tcp header";
            return false;
        }
        // We have to pass the TCP header to TcpSnoop so only skip ethernet and IP headers
        int header_size = sizeof(struct ethhdr) + iphdrlen;
        unsigned char *payload = frame + header_size;
        if (tcpcsum(frame) != 0) {
            LOG_IF(INFO, Debug) << "Received packet with invalid TCP checksum";
            return false;
        }
        uint16_t srcPort = ntohs(tcph->source);
        uint16_t destPort = ntohs(tcph->dest);

        DLOG_IF(INFO, Debug) << "TCP source port " << srcPort << ", dest port "
                << destPort << ", headersize " << header_size;
        if (ntohs(tcph->source) == 53 || ntohs(tcph->dest) == 53) {
            bool finFlag = (tcph->th_flags & TH_FIN);
            bool rstFlag = (tcph->th_flags & TH_RST) >> 2;
            std::shared_ptr<TcpSnoop> tsPtr;
            if (isIPv4) {
                tsPtr = getTcpSnoopInstance(srcv4, srcPort, dstv4, destPort);
            } else {
                tsPtr = getTcpSnoopInstance(srcv6, srcPort, dstv6, destPort);

            }

            // FIXME: the below logic does free up memory but a FIN may be followed by an ACK of an incoming FIN so
            // a new TcpSnoopInstance would be created and would have to be pruned using the periodic pruning algorithm
            // But we do free up memory with the current solution so the extra `cost' is worth it.
            if (finFlag == true || rstFlag == true) {
                if (tsPtr != nullptr) {
                    LOG(INFO) << "saw FIN or RST for TCP stream, pruning TcpSnoop instance";
                    if (isIPv4) {
                        clearTcpSnoopInstance(srcv4, srcPort, dstv4, destPort);

                    } else {
                        clearTcpSnoopInstance(srcv6, srcPort, dstv6, destPort);

                    }
                }
                return true;
            }
            if (tsPtr == nullptr) {
                tsPtr = std::make_shared<TcpSnoop>(Debug);
                LOG_IF(INFO, Debug) << "Creating TcpSnoop shared pointer at %p", tsPtr;
                if (isIPv4) {
                    addTcpSnoopInstance(srcv4, srcPort, dstv4, destPort, tsPtr);
                } else {
                    addTcpSnoopInstance(srcv6, srcPort, dstv6, destPort, tsPtr);

                }
            }
            //
            // For TCP, we pass both TCP header and payload
            //
            if ((tsPtr)->addPacket(payload, ipPayloadLen)) {
                unsigned char buffer[65600];
                uint16_t bytesRead = (tsPtr)->getDnsMessage(buffer);
                parseDnsPacket(buffer, bytesRead, Mac, srcString, ifindex);
            }
        } else {
            LOG(WARNING) <<
                    "PacketSnoop: Received packet with unexpected TCP ports: source "
                    << srcPort << ", destination " << destPort;
        }
    }
    break;
    case 17: //UDP Protocol
    {
        struct udphdr *udph = (struct udphdr*) (frame + iphdrlen + sizeof(struct ethhdr));
        int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
        //
        // for UDP, we only process the UDP payload
        //
        unsigned char *udpPayload = frame + header_size;
        size_t udpPayloadLen = ipPayloadLen - sizeof(struct udphdr);

        DLOG_IF(INFO, Debug) << "UDP source port " << ntohs(udph->source)
                        << ", dest port " << ntohs(udph->dest) << ", header size "
                        << header_size;
        if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53) {
            parseDnsPacket(udpPayload, udpPayloadLen, Mac, srcString, ifindex);
        } else if (ntohs(udph->source) == 67 || ntohs(udph->dest) == 68
                || ntohs(udph->source) == 68 || ntohs(udph->dest) == 68) {
            parseDhcpv4UdpPacket(udpPayload, udpPayloadLen);
        } else {
            LOG(WARNING) << "PacketSnoop: Received packet with UDP source port "
                    << ntohs(udph->source) << ", destination port "
                    << ntohs(udph->dest);
        }
    }
    break;
    default: //Some Other Protocol like ARP, ICMP etc.
        LOG(INFO) << "PacketSnoop: Received packet with protocol other than TCP or UDP";
    }
    return false;
}

std::shared_ptr<TcpSnoop> PacketSnoop::getTcpSnoopInstance(
        const Tins::IPv4Address inSrc, const uint16_t inSrcPort,
        const Tins::IPv4Address inDest, const uint16_t inDestPort) {
    auto sit = tcpv4Snoops.find(inSrc);
    if (sit == tcpv4Snoops.end()) {
        return nullptr;
    }
    auto spit = tcpv4Snoops[inSrc].find(inSrcPort);
    if (spit == tcpv4Snoops[inSrc].end()) {
        return nullptr;
    }
    auto dit = tcpv4Snoops[inSrc][inSrcPort].find(inDest);
    if (dit == tcpv4Snoops[inSrc][inSrcPort].end()) {
        return nullptr;
    }
    auto dpit = tcpv4Snoops[inSrc][inSrcPort][inDest].find(inDestPort);
    if (dpit == tcpv4Snoops[inSrc][inSrcPort][inDest].end()) {
        return nullptr;
    }
    return dpit->second;
}

std::shared_ptr<TcpSnoop> PacketSnoop::getTcpSnoopInstance(
        const Tins::IPv6Address inSrc, const uint16_t inSrcPort,
        const Tins::IPv6Address inDest, const uint16_t inDestPort) {
    auto sit = tcpv6Snoops.find(inSrc);
    if (sit == tcpv6Snoops.end()) {
        return nullptr;
    }
    auto spit = tcpv6Snoops[inSrc].find(inSrcPort);
    if (spit == tcpv6Snoops[inSrc].end()) {
        return nullptr;
    }
    auto dit = tcpv6Snoops[inSrc][inSrcPort].find(inDest);
    if (dit == tcpv6Snoops[inSrc][inSrcPort].end()) {
        return nullptr;
    }
    auto dpit = tcpv6Snoops[inSrc][inSrcPort][inDest].find(inDestPort);
    if (dpit == tcpv6Snoops[inSrc][inSrcPort][inDest].end()) {
        return nullptr;
    }
    return dpit->second;
}

void PacketSnoop::clearTcpSnoopInstance(const Tins::IPv4Address inSrc, const uint16_t inSrcPort,
        const Tins::IPv4Address inDest, const uint16_t inDestPort) {
    tcpv4Snoops[inSrc][inSrcPort][inDest][inDestPort] = nullptr;
}

void PacketSnoop::clearTcpSnoopInstance(const Tins::IPv6Address inSrc, const uint16_t inSrcPort,
        const Tins::IPv6Address inDest, const uint16_t inDestPort) {
    tcpv6Snoops[inSrc][inSrcPort][inDest][inDestPort] = nullptr;
}

void PacketSnoop::addTcpSnoopInstance(const Tins::IPv4Address inSrc,
        const uint16_t inSrcPort, const Tins::IPv4Address inDest,
        const uint16_t inDestPort, const std::shared_ptr<TcpSnoop> ts_ptr) {
    LOG_IF(INFO, Debug) << "Adding TcpSnoop shared pointer at " << ts_ptr;
    tcpv4Snoops[inSrc][inSrcPort][inDest][inDestPort] = ts_ptr;
}

void PacketSnoop::addTcpSnoopInstance(const Tins::IPv6Address inSrc,
        const uint16_t inSrcPort, const Tins::IPv6Address inDest,
        const uint16_t inDestPort, const std::shared_ptr<TcpSnoop> ts_ptr) {
    LOG_IF(INFO, Debug) << "Adding TcpSnoop shared pointer at " << ts_ptr;
    tcpv6Snoops[inSrc][inSrcPort][inDest][inDestPort] = ts_ptr;
}

uint32_t PacketSnoop::pruneTcpSnoopInstances(const bool Force) {
    uint32_t deletedinstances = 0;
    {
        auto sit = tcpv4Snoops.begin();
        while (sit != tcpv4Snoops.end()) {
            auto spit = sit->second.begin();
            while (spit != sit->second.end()) {
                auto dit = spit->second.begin();
                while (dit != spit->second.end()) {
                    auto dpit = dit->second.begin();
                    while (dpit != dit->second.end()) {
                        if (Force == true || dpit->second == nullptr || dpit->second->isExpired() == true) {
                            dpit = dit->second.erase(dpit);
                        } else {
                            ++dpit;
                        }
                    }
                    if (Force == true || dit->second.empty() == true) {
                        dit = spit->second.erase(dit);
                    } else {
                        ++dit;
                    }
                }
                if (Force == true || spit->second.empty() == true) {
                    spit = sit->second.erase(spit);
                } else {
                    ++spit;
                }
            }
            if (Force == true || sit->second.empty()) {
                sit = tcpv4Snoops.erase(sit);
            } else {
                ++sit;
            }
        }
    }
    {
        auto sit = tcpv6Snoops.begin();
        while (sit != tcpv6Snoops.end()) {
            auto spit = sit->second.begin();
            while (spit != sit->second.end()) {
                auto dit = spit->second.begin();
                while (dit != spit->second.end()) {
                    auto dpit = dit->second.begin();
                    while (dpit != dit->second.end()) {
                        if (Force == true || dpit->second == nullptr || dpit->second->isExpired() == true) {
                            dpit = dit->second.erase(dpit);
                        } else {
                            ++dpit;
                        }
                    }
                    if (Force == true || dit->second.empty() == true) {
                        dit = spit->second.erase(dit);
                    } else {
                        ++dit;
                    }
                }
                if (Force == true || spit->second.empty() == true) {
                    spit = sit->second.erase(spit);
                } else {
                    ++spit;
                }
            }
            if (Force == true || sit->second.empty()) {
                sit = tcpv6Snoops.erase(sit);
            } else {
                ++sit;
            }
        }
    }
    return deletedinstances;
}

bool PacketSnoop::parseDnsPacket(const unsigned char *payload,
        const size_t size, const MacAddress &inMac, const std::string sourceIp,
        const int ifIndex) {
    if (size < 12) {
        LOG(WARNING) << "Received DNS packet smaller than 12 bytes";
        return true;
    }
    Tins::DNS *q;
    InterfaceMap *ifMap = hC->getInterfaceMap();
    try {
        q = new Tins::DNS(payload, size);
    } catch (const Tins::malformed_packet &e) {
        DLOG_IF(INFO, Debug) << "Malformed DNS packet";
        return true;
    }

    // Note, additional resources section is not processed as this is not information a non-resursive DNS client would use

    DLOG_IF(INFO, Debug) << "Query ID:" << q->id() << " on interface " << ifIndex;
    DLOG_IF(INFO, Debug) << "Questions: " << q->questions_count() <<
            " Answers: " <<  q->answers_count() << " Additional answers: "
            << q->additional_count();
    /*
     * From the LAN, only accept packets with no answers
     * From the WAN, only accept packets with answers with Query ID matching earlier outbound packet
     *
     * Two use cases:
     *   1: client uses DNS recursive server on equipment which Noddos is running
     *     -> DNS Query ID on LAN interface is different from DNS Query ID on WAN interface
     *     -> DNS Query ID can't be associated with a Noddos Host instance
     *   2: client uses DNS server on remote location
     *     -> DNS Query ID on LAN interface matches DNS Query ID on WAN interface
     *
     */
    if (ifMap->isLanInterface(ifIndex) == true && q->answers_count() == 0
            && q->additional_count() == 0) {
        for (auto it : q->queries()) {
            DLOG_IF(INFO, Debug) << "Question " << q->id() << " : " << it.dname()
                            << " " << it.query_class() << " " << it.query_type();
            // Here we track which DNS queries each Host has executed so when we report traffic stats, we can
            // look at the reverse DNS path from IP address and match that to the original DNS query. As multiple
            // FQDNs may resolve to the same IP address and the reverse path may thus result in multiple FQDNs,
            // we need to keep track which of those FQDNs were queried by the Host.
            try {
                std::shared_ptr<Host> h = hC->findOrCreateHostByMac(inMac, "",
                        sourceIp);
                if (h != nullptr) {
                    h->addorupdateDnsQueryList(it.dname());
                }
                LOG(INFO) << "Adding FQDN " << it.dname() << " to DnsQueryList for "<< sourceIp;
            } catch (...) {}
        }
        delete q;
        return false;
    } else if (ifMap->isWanInterface(ifIndex) && q->answers_count() == 0) {
        // This is an outgoing query or an response to client without answers
        // Store the Query ID in a short-term cache so that incoming answers
        // can be confirmed to come in response to the query
        // FIXME: should additionally check whether source IP is from LAN or one of our own
        LOG(INFO) << "Adding query with ID " << q->id() << " to DnsQueryCache";
        hC->addorupdateDnsQueryCache(q->id());
    } else if (ifMap->isWanInterface(ifIndex) && q->answers_count() > 0) {
        // Only accept an answer if for each question there is a matching outgoing query from the DNS server
        // on which noddos runs
        if (hC->inDnsQueryCache(q->id()) == false) {
            LOG(WARNING) << "No matching entry in DnsQueryCache for " << q->id();
            delete q;
            return true;
        }

        for (auto it : q->answers()) {
            DLOG_IF(INFO, Debug) << "Query type " << it.query_type();
            uint16_t i = 0;
            char ipaddr[INET6_ADDRSTRLEN];
            if (it.query_type() != 41) { // OPT pseudo-RR
                DLOG_IF(INFO, Debug) << "Answer " << ++i << " : " << it.dname()
                                << " " << it.ttl() << " " << it.query_class() << " " <<
                                it.query_type();
                std::string dnsdata = it.data();
                switch (it.query_type()) {
                case Tins::DNS::QueryType::A: {
                    DLOG_IF(INFO, Debug) << it.dname() << " has A record: " << it.data();
                    Tins::IPv4Address ip(it.data());
                    hC->addorupdateDnsIpCache(it.dname(), ip);
                    break;
                }
                case Tins::DNS::QueryType::AAAA: {
                    Tins::IPv6Address ip(it.data());

                    hC->addorupdateDnsIpCache(it.dname(), ip);
                    DLOG_IF(INFO, Debug) << it.dname() << " has AAAA record: " << ip;
                    break;
                }
                case Tins::DNS::QueryType::CNAME: {
                    hC->addorupdateDnsCnameCache(it.dname(), dnsdata);
                    DLOG_IF(INFO, Debug) << it.dname() << " has CNAME record: " << dnsdata;
                    break;
                }
                default: {
                    DLOG_IF(INFO, Debug) << "unhandled resource record: " << dnsdata;
                    break;
                }
                }
            } else {
                DLOG_IF(INFO, Debug) << "RR OPT";
            }
        }
    }
    delete q;
    return false;
}

bool PacketSnoop::parseDhcpv4UdpPacket(unsigned char *payload, size_t size) {
    Tins::DHCP *d;
    try {
        d = new Tins::DHCP(payload, size);
    } catch (const Tins::malformed_packet &e) {
        DLOG_IF(INFO, Debug) << "Malformed DHCPv4 packet";
        if (d != nullptr) {
            delete d;
        }
        return true;
    } catch (...) {
        LOG(ERROR) << "DHCPv4 exception";
        if (d != nullptr) {
            delete d;
        }
        return true;
    }
    uint8_t msgType = d->type();

    Tins::BootP::ipaddress_type yiaddr = d->yiaddr();
    std::string clientIp = yiaddr.to_string();

    Tins::BootP::chaddr_type chaddr = d->chaddr();
    MacAddress mac (chaddr.to_string());

    std::string hostname;
    try {
        hostname = d->hostname();
    } catch (...) {
        hostname =  "";
    }

    std::string vendor = "";
    try {
        const Tins::DHCP::option *v = d->search_option(Tins::DHCP::OptionTypes::VENDOR_CLASS_IDENTIFIER);
        if (v != nullptr) {
            std::string ven((const char*) v->data_ptr(), v->data_size());
            vendor = ven;
        }
    } catch (...) {}

    if (msgType != 1 && msgType != 3 && msgType != 5 && msgType != 8) {
        LOG_IF(INFO, Debug) << "Ignoring DHCPv4 packets if they are not DISCOVER, REQUEST, ACK or INFORM";
        delete d;
        return false;
    }

    hC->addDhcpRequest(clientIp, mac, hostname, vendor);
    delete d;
    return false;
}

// thanks to http://seclists.org/lists/bugtraq/1999/Mar/0057.html
uint16_t tcpcsum(unsigned char * const packet) {
    struct tcp_pseudo pseudo;

    const struct iphdr * iph = (const struct iphdr *) (packet
            + sizeof(struct ethhdr));
    unsigned ipHdrLen = iph->ihl * 4;
    uint16_t ipPacketLen = ntohs(iph->tot_len);
    unsigned ipPayloadLen = ipPacketLen - ipHdrLen;

    // TCP header starts directly after IP header
    const struct tcphdr * tcp = (const struct tcphdr *) ((const u_char *) iph
            + ipHdrLen);

    // Build the pseudo header and checksum it
    pseudo.src_addr = iph->saddr;
    pseudo.dst_addr = iph->daddr;
    pseudo.zero = 0;
    pseudo.proto = 6;
    pseudo.length = htons(ipPayloadLen);
    uint16_t csum = in_cksum(&pseudo, (unsigned) sizeof(pseudo), 0);

    // Update the checksum by checksumming the TCP header
    // and data as if those had directly followed the pseudo header
    csum = in_cksum((void *) tcp, ipPayloadLen, (uint16_t) ~csum);

    return csum;
}

uint16_t in_cksum(void * const addr, const unsigned inlen,
        const uint16_t init) {
    uint32_t sum;
    const uint16_t * word;
    unsigned len = inlen;

    sum = init;
    word = (uint16_t *) addr;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */

    while (len >= 2) {
        sum += *(word++);
        len -= 2;
    }

    if (len > 0) {
        uint16_t tmp;

        *(uint8_t *) (&tmp) = *(uint8_t *) word;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ((uint16_t) ~sum);
}

