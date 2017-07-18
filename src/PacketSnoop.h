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

 * PacketSnoop.h
 *
 *  Created on: May 28, 2017
 *      Author: steven
 */

#ifndef PACKETSNOOP_H_
#define PACKETSNOOP_H_

#include <cstddef>
#include <cstring>
#include <memory>

#include <syslog.h>
#include <unistd.h>
#include <stdexcept>

#include <sys/ioctl.h>
#include <features.h>

#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>   /* the L2 protocols */
#else
#include <asm/types.h>
#endif
#include <linux/filter.h>
// if_ether.h causes redefinition conflicts
// #include <linux/if_ether.h>
#include <linux/ipv6.h>
// #include <linux/if.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

#include "boost/asio.hpp"

#include "tins/dns.h"
#include "tins/dhcp.h"
#include <sys/mman.h>
#include "noddos.h"
#include "iDeviceInfoSource.h"
#include "HostCache.h"
#include "TcpSnoop.h"

#define NUM_BLOCKS 2049

struct priv {
    /* unused */
};

struct tcp_pseudo /*the tcp pseudo header for checksum calculation*/
{
  __u32 src_addr;
  __u32 dst_addr;
  __u8 zero;
  __u8 proto;
  __u16 length;
};

uint16_t tcpcsum (unsigned char * const packet);
uint16_t in_cksum (void * const addr, const unsigned len, const uint16_t init);


template <class T, std::size_t N>
constexpr std::size_t size(const T (&array)[N]) noexcept
{
    return N;
}

class PacketSnoop : public iDeviceInfoSource {
private:
	int sock  = -1;
	bool Debug = false;
	HostCache *hC = nullptr;
	std::map<boost::asio::ip::address,std::map<uint16_t,std::map<boost::asio::ip::address,std::map<uint16_t,std::shared_ptr<TcpSnoop>>>>> tcpSnoops;

	// void *user;
    // rx_cb_t cb;
    uint8_t *map = nullptr;
    size_t map_sz = 0;
    sig_atomic_t cancel = 0;
    unsigned int r_idx = 0;
    unsigned int nr_blocks = 0;
    unsigned int block_sz = 0;
    size_t numBlocks;
    int ifindex = 0;

public:
	PacketSnoop(HostCache &inHc, const size_t inNumBlocks, const bool inDebug = false):	hC{&inHc}, numBlocks{inNumBlocks}, Debug{inDebug} {
		if (Debug == true) {
			syslog (LOG_DEBUG, "Constructing PacketSnoop instance");
		}
	};

	virtual ~PacketSnoop() { Close(); };
	int Open(std::string input, uint32_t inExpiration);
	int GetFileHandle() { return sock; }
	bool Close();
	bool ProcessEvent(struct epoll_event &event);
	bool Parse (unsigned char *frame);
	bool parseDnsTcpPacket(unsigned char *payload, size_t size);
	bool parseDnsPacket(const unsigned char *payload, const size_t size, const MacAddress &inMac, const std::string sourceIp, const int ifindex);
	bool parseDhcpv4UdpPacket(unsigned char *payload, size_t size);
	std::shared_ptr<TcpSnoop> getTcpSnoopInstance(const boost::asio::ip::address inSrc, const uint16_t srcPort,
			const boost::asio::ip::address inDest, const uint16_t destPort);
	void addTcpSnoopInstance(const boost::asio::ip::address inSrc, const uint16_t inSrcPort,
			const boost::asio::ip::address inDest, const uint16_t inDestPort, const std::shared_ptr<TcpSnoop> ts_ptr);
    void pruneTcpSnoopInstance(const boost::asio::ip::address inSrc, const uint16_t inSrcPort,
            const boost::asio::ip::address inDest, const uint16_t inDestPort);
    uint32_t pruneTcpSnoopInstances(const bool Force = false);
};

#endif /* PACKETSNOOP_H_ */
