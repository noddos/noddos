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
#include <syslog.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "noddos.h"
#include "iDeviceInfoSource.h"
#include "HostCache.h"

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

public:
	PacketSnoop(HostCache &inHc, bool const inDebug = false):	hC{&inHc}, Debug{inDebug} {
		Open("");
	};

	virtual ~PacketSnoop() { Close(); };
	int Open(std::string input, uint32_t inExpiration = 0);
	int GetFileHandle() { return sock; }
	bool Close() { close (sock); return false; };
	bool ProcessEvent(struct epoll_event &event) { return true; }
	bool Parse (unsigned char *frame, size_t size, struct sockaddr_ll saddr, size_t saddr_size);
	bool Parse_Dns_Tcp_Packet(unsigned char *payload, size_t size);
	bool Parse_Dns_Packet(unsigned char *payload, size_t size);
	bool Parse_Dhcp_Udp_Packet(unsigned char *payload, size_t size);
};

#endif /* PACKETSNOOP_H_ */
