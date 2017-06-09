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
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "boost/asio.hpp"

#include "noddos.h"
#include "iDeviceInfoSource.h"
#include "HostCache.h"
#include "TcpSnoop.h"

struct dnshdr {
    uint16_t dns_id;
    uint16_t dns_flags;
    uint16_t dns_qdc;
    uint16_t dns_anc;
    uint16_t dns_nsc;
    uint16_t dns_arc;
};

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
	PacketSnoop(HostCache &inHc, bool const inDebug = false):	hC{&inHc}, Debug{inDebug} {
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
