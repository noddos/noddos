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

#include <linux/filter.h>
// #include <linux/if_ether.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
// #include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <linux/ipv6.h>

#include "boost/asio.hpp"

#include "dns.h"
#include "noddos.h"
#include "iDeviceInfoSource.h"
#include "HostCache.h"
#include "TcpSnoop.h"

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
	int sock;
	bool Debug;
	HostCache *hC;
	std::map<boost::asio::ip::address,std::map<uint16_t,std::map<boost::asio::ip::address,std::map<uint16_t,std::shared_ptr<TcpSnoop>>>>> tcpSnoops;

public:
	PacketSnoop(HostCache &inHc, const bool  inDebug = false):	hC{&inHc}, Debug{inDebug} {
		if (Debug == true) {
			syslog (LOG_DEBUG, "Constructing PacketSnoop instance");
		}
		Open("");
	};

	virtual ~PacketSnoop() { Close(); };
	int Open(std::string input, uint32_t inExpiration = 0);
	int GetFileHandle() { return sock; }
	bool Close() { close (sock); return false; };
	bool ProcessEvent(struct epoll_event &event);
	bool Parse (unsigned char *frame, size_t size, int ifIndex);
	bool parseDnsTcpPacket(unsigned char *payload, size_t size);
	bool parseDnsPacket(const unsigned char *payload, const size_t size, const MacAddress &inMac, const std::string sourceIp, const int ifindex);
	bool parseDhcpUdpPacket(unsigned char *payload, size_t size);
	std::shared_ptr<TcpSnoop> getTcpSnoopInstance(const boost::asio::ip::address inSrc, const uint16_t srcPort,
			const boost::asio::ip::address inDest, const uint16_t destPort);
	void addTcpSnoopInstance(const boost::asio::ip::address inSrc, const uint16_t inSrcPort,
			const boost::asio::ip::address inDest, const uint16_t inDestPort, const std::shared_ptr<TcpSnoop> ts_ptr);
};


#endif /* PACKETSNOOP_H_ */
