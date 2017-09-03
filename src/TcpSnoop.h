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

 * TcpSnoop.h
 *
 *  Created on: Jun 6, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef TCPSNOOP_H_
#define TCPSNOOP_H_

#include <map>
#include <memory>
#include <vector>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <syslog.h>

struct TcpSegment {
public:
	uint8_t bytesProcessed = 0;
	uint16_t payloadLength = 0;
	uint32_t sequenceNumber = 0;
	uint32_t nextSequenceNumber = 0;
	uint16_t checksum = 0;
	std::vector<unsigned char> tcpPayload;
};


class TcpSnoop {
private:
	std::map<uint32_t,struct TcpSegment> packets;
	uint32_t firstSequenceNumber = 0;
	uint32_t lastSequenceNumber = 0;
	uint32_t nextSequenceNumber = 0;
	uint16_t firstPacketOffset = 0;
	uint16_t dnsMessageLength = 0;
	uint32_t streamLength = 0;
	time_t Expiration = 0;
	bool Debug;
	// std::vector<unsigned char> tcpPayload;

public:
	TcpSnoop(const bool inDebug = false, const time_t inExpiration = 120): Debug{inDebug} {
        setExpiration(inExpiration);
		if (Debug == true) {
			syslog(LOG_DEBUG, "Constructing TcpSnoop instance");
		}
	}
	~TcpSnoop() {};

	/*
	 * addPacket
	 * input: pointer to TCP Segment, size of TCP segement, whether packet was received or sent by host
	 * output: bool on whether data might be ready for parsing with TcpSnoop:parseStream
	 */
	bool addPacket (const unsigned char *tcpSegment, const uint16_t size, const time_t inExpiration = 120) {
		setExpiration(inExpiration);
	    struct tcphdr *tcph = (struct tcphdr*) tcpSegment;

		bool finFlag = (tcph->th_flags & TH_FIN);
		bool synFlag = (tcph->th_flags & TH_SYN) >> 1;
		bool rstFlag = (tcph->th_flags & TH_RST) >> 2;
		bool pushFlag = (tcph->th_flags & TH_PUSH) >> 3;
		bool ackFlag = (tcph->th_flags & TH_ACK) >> 4;


		if (finFlag == true || rstFlag == true) {
			return true;
		}
		uint32_t packetSequenceNumber = ntohl(tcph->seq);
		if (synFlag == true) {
			firstSequenceNumber = packetSequenceNumber + 1;
		}
		uint16_t dataOffset = tcph->doff * 4;
		// Packet without payload
		if (dataOffset >= size) {
			return false;
		}
		// We only copy packets if they have payload so if we get a packet with payload but we have already stored a
		// packet with the same sequence number then it must be a duplicate
		if (packets.find(packetSequenceNumber) != packets.end()) {
			return false;
		}
		uint16_t tcpPayloadLength = size - dataOffset;

		if (Debug == true) {
			syslog (LOG_DEBUG, "TcpSnoop: Parsing packet of size %u (header %u), sequence number %u, flags fin: %u, syn %u, rst %u, push %u, ack %u",
				size, dataOffset, packetSequenceNumber, finFlag, synFlag, rstFlag, pushFlag, ackFlag);
		}

		const unsigned char *tcpPayload = tcpSegment + dataOffset;
 		packets[packetSequenceNumber].sequenceNumber = packetSequenceNumber;
		packets[packetSequenceNumber].nextSequenceNumber = packetSequenceNumber + tcpPayloadLength;
		packets[packetSequenceNumber].bytesProcessed = 0;
		packets[packetSequenceNumber].payloadLength = tcpPayloadLength;
		packets[packetSequenceNumber].tcpPayload.reserve(size - dataOffset);
		packets[packetSequenceNumber].tcpPayload = std::vector<unsigned char>(tcpPayload, tcpPayload + tcpPayloadLength);

		streamLength += (size - dataOffset);

		if (streamLength + 2 > dnsMessageLength) {
			return true;
		}
		return false;
	}

	// Returns number of bytes copied to buf, with 0 being no DNS message available from the TCP stream
	uint32_t getDnsMessage (unsigned char *buf) {
		auto it = packets.begin();
		TcpSegment &t = it->second;
		if (t.sequenceNumber != firstSequenceNumber) {
			return 0;
		}
		if (dnsMessageLength == 0) {
			uint8_t firstByte = t.tcpPayload[firstPacketOffset];
			uint8_t secondByte = t.tcpPayload[firstPacketOffset+1];
			dnsMessageLength = (firstByte << 8) + secondByte;
			firstPacketOffset += 2;
			if (Debug == true) {
				syslog (LOG_DEBUG, "TcpSnoop: DNS Message length %u", dnsMessageLength);
			}
		}

		if ((dnsMessageLength + 2) > streamLength) {
			// We haven't received enough data yet to fully read the DNS message
			return 0;
		}
		uint32_t nextSeq = firstSequenceNumber;
		uint32_t bytesAvailable = 0;
		while( it != packets.end() && (bytesAvailable - 2) < dnsMessageLength) {
			t = it->second;
			if (t.sequenceNumber != nextSeq) {
				// The network has lost a packet somewhere so we need to wait for retransmission
				return 0;
			}
			nextSeq = t.nextSequenceNumber;
			bytesAvailable = t.payloadLength;
			it++;
		}
		if ((bytesAvailable - 2) < dnsMessageLength) {
			return 0;
		}
		// We've verified enough bytes are available to read the complete DNS message
		it = packets.begin();
		uint32_t totalBytesCopied = 0;
		bool messageLengthParsed = false;
		uint32_t bytesNeeded = dnsMessageLength;
		while( bytesNeeded > 0) {
			uint8_t bytesSkipped = 0;
			auto payload_it = it->second.tcpPayload.begin();
			if (messageLengthParsed == false) {
				messageLengthParsed = true;
				bytesSkipped = 2;
				payload_it += bytesSkipped;
			}

			std::copy(payload_it, it->second.tcpPayload.end(), buf + totalBytesCopied);
			totalBytesCopied += it->second.payloadLength - bytesSkipped;
			if (totalBytesCopied > bytesNeeded) {
				// We've read all the bytes we need but there are still more bytes in the stream belonging to the next DNS message
				it->second.bytesProcessed = bytesNeeded + bytesSkipped;
				bytesNeeded = 0;
				firstSequenceNumber = it->first;
				streamLength -= it->second.bytesProcessed;
			} else {
				bytesNeeded -= it->second.payloadLength - bytesSkipped;
				firstSequenceNumber = it->second.nextSequenceNumber;
				streamLength -= it->second.payloadLength;
				it = packets.erase(it);
			}
		}
		return dnsMessageLength;
	}
	void setExpiration(const time_t inExpiration = 120) { Expiration = time(nullptr) + inExpiration; }
	bool isExpired() { return time(nullptr) > Expiration; }
};


#endif /* TCPSNOOP_H_ */
