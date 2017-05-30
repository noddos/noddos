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


template <class T, std::size_t N>
constexpr std::size_t size(const T (&array)[N]) noexcept
{
    return N;
}

class PacketSnoop : public iDeviceInfoSource {
private:
	int sock;

public:
	PacketSnoop() {
		Open("");
	}

	~PacketSnoop() { Close(); };


	bool Close() { close (sock); return false; };
	bool ProcessEvent(struct epoll_event &event) { return true; }
	int GetFileHandle() { return sock; }
};

#endif /* PACKETSNOOP_H_ */
