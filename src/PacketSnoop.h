/*
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


#include <sys/socket.h>
#include <linux/if_packet.h>
// #include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
//#include <netpacket/packet.h>
#include <linux/filter.h>
#include <net/ethernet.h>   /* the L2 protocols */
#include <linux/ipv6.h>
// #include <linux/if.h>
#include <linux/if_packet.h>
// #include <linux/if_ether.h> /* The L2 protocols */
#include <string.h>
#include <netinet/in.h>

#include "boost/asio.hpp"

// #include <rxring.h>

#include "tins/dns.h"
#include "tins/dhcp.h"
#include <sys/mman.h>
#include "noddos.h"
#include "iDeviceInfoSource.h"
#include "HostCache.h"
#include "TcpSnoop.h"

#define NUM_BLOCKS 2049




struct tcp_pseudo /*the tcp pseudo header*/
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
    int ifindex = 0;

public:
	PacketSnoop(HostCache &inHc, const bool  inDebug = false):	hC{&inHc}, Debug{inDebug} {
		// if (Debug == true) {
			syslog (LOG_DEBUG, "Constructing PacketSnoop instance");
		//}
	};

	virtual ~PacketSnoop() { Close(); };
	int Open(std::string input, uint32_t inExpiration = 0);
	int GetFileHandle() { return sock; }
	bool Close();
	bool ProcessEvent(struct epoll_event &event);
	bool Parse (unsigned char *frame, size_t size, int _ifIndex);
	bool parseDnsTcpPacket(unsigned char *payload, size_t size);
	bool parseDnsPacket(const unsigned char *payload, const size_t size, const MacAddress &inMac, const std::string sourceIp, const int ifindex);
	bool parseDhcpUdpPacket(unsigned char *payload, size_t size);
	std::shared_ptr<TcpSnoop> getTcpSnoopInstance(const boost::asio::ip::address inSrc, const uint16_t srcPort,
			const boost::asio::ip::address inDest, const uint16_t destPort);
	void addTcpSnoopInstance(const boost::asio::ip::address inSrc, const uint16_t inSrcPort,
			const boost::asio::ip::address inDest, const uint16_t inDestPort, const std::shared_ptr<TcpSnoop> ts_ptr);
};

class DnsDecode {
private:
    uint8_t * const message = nullptr;
    uint16_t messageIndex = 0;
    uint16_t messageLength = 0;

public:
    DnsDecode (uint8_t * const inMessage, const uint16_t inLength): message{inMessage}, messageLength{inLength} {
    };
    uint8_t get8Bits () {
        if (message == nullptr) {
            throw std::domain_error("DNS message is initialized");
            return 0;
        }
        if (messageIndex >= messageLength) {
            throw std::out_of_range("DNS message already fully parsed");
            return 0;
        }
        return message[messageIndex++];
    }
    uint16_t get16Bits () {
        if (message == nullptr) {
            throw std::domain_error("DNS message not initialized");
            return 0;
        }
        if (messageIndex +1 >= messageLength) {
            throw std::out_of_range("DNS message already fully parsed");
            return 0;
        }
        uint16_t val = (message[messageIndex] << 8) + message[messageIndex+1];
        messageIndex += 2;
        return val;
    }
    bool getFlag (const uint8_t Field, const uint8_t Pos) {
        if (Pos > 7) {
            throw std::out_of_range("Position out of range");
            return false;
        }
        return  (Field >> (7-Pos)) & 1;
    }
    bool getFlag (const uint16_t Field, const uint8_t Pos) {
        if (Pos > 15) {
            throw std::out_of_range("Position out of range");
            return false;
        }
        return  (Field >> (15-Pos)) & 1;
    }
    uint8_t getBits (const uint16_t Field, const uint8_t startPos, const uint8_t endPos) {
        if (startPos >= endPos || endPos > 15) {
            throw std::out_of_range("Starting position equal or larger than ending position");
            return false;
        }
        return  (Field >> (15-endPos)) & ((1 << (endPos - startPos)) -1);
    }
};

#endif /* PACKETSNOOP_H_ */
