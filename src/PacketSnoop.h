/*
 * PacketSnoop.h
 *
 *  Created on: May 28, 2017
 *      Author: steven
 */

#ifndef PACKETSNOOP_H_
#define PACKETSNOOP_H_

#include <cstddef>
#include <syslog.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>

#include "noddos.h"
#include "iDeviceInfoSource.h"

// DNS port 53 (without specifying UDP or TCP
struct sock_filter bpfcode[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 8, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 2, 0, 0x00000084 },
	{ 0x15, 1, 0, 0x00000006 },
	{ 0x15, 0, 17, 0x00000011 },
	{ 0x28, 0, 0, 0x00000036 },
	{ 0x15, 14, 0, 0x00000035 },
	{ 0x28, 0, 0, 0x00000038 },
	{ 0x15, 12, 13, 0x00000035 },
	{ 0x15, 0, 12, 0x00000800 },
	{ 0x30, 0, 0, 0x00000017 },
	{ 0x15, 2, 0, 0x00000084 },
	{ 0x15, 1, 0, 0x00000006 },
	{ 0x15, 0, 8, 0x00000011 },
	{ 0x28, 0, 0, 0x00000014 },
	{ 0x45, 6, 0, 0x00001fff },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x48, 0, 0, 0x0000000e },
	{ 0x15, 2, 0, 0x00000035 },
	{ 0x48, 0, 0, 0x00000010 },
	{ 0x15, 0, 1, 0x00000035 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 }
};

template <class T, std::size_t N>
constexpr std::size_t size(const T (&array)[N]) noexcept
{
    return N;
}

struct sock_fprog bpf = {
	.len = size(bpfcode),
	.filter = bpfcode,
};

class PacketSnoop : public iDeviceInfoSource {
private:
	int sock;
public:
	PacketSnoop() { Open(""); };
	~PacketSnoop() { Close(); };

	int Open(std::string input, uint32_t inExpiration = 0) {
	    sock = socket( AF_PACKET, SOCK_RAW, htons(ETH_P_IP)) ;
	    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
	    if(sock < 0) {
	        //Print the error with proper message
	    	syslog(LOG_CRIT, "Socket Error");
	        exit(1);
	    }
		int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
		if (ret < 0) {
	        syslog (LOG_CRIT, "Setsockopt Error");
	        exit(1);
	    }
		return sock;
	}
	bool Close() { close (sock); return false; };
	bool ProcessEvent(struct epoll_event &event) { return true; }
	int GetFileHandle() { return sock; }
};

#endif /* PACKETSNOOP_H_ */
