/*
 * TcpSnoop.h
 *
 *  Created on: Jun 6, 2017
 *      Author: steven
 */

#ifndef TCPSNOOP_H_
#define TCPSNOOP_H_

#include <map>
#include <memory>
#include <netinet/tcp.h>

struct TcpSegment {
public:
	uint8_t bytesProcessed = 0;
	uint8_t payloadLength = 0;
	uint32_t sequenceNumber = 0;
	uint32_t nextSequenceNumber = 0;
	uint16_t checksum = 0;
	std::vector<unsigned char> TcpPayload;
};

class TcpSnoop {
private:
	std::map<uint32_t,struct TcpSegment> packets;
	uint16_t firstPacketOffset = 0;
	uint32_t firstSequenceNumber = 0;
	uint32_t streamLength = 0;
	time_t Expiration;

public:
	TcpSnoop() {
		Expiration = time(nullptr) + 120;
	}
	~TcpSnoop() {};

	/*
	 * addPacket
	 * input: pointer to TCP Segment, size of TCP segement, whether packet was received or sent by host
	 * output: bool on whether data might be ready for parsing with TcpSnoop:parseStream
	 */
	bool addPacket (const unsigned char *tcpSegment, const uint16_t size) {
		struct tcphdr *tcph = (struct tcphdr*) tcpSegment;

		bool finFlag = (tcph->th_flags & TH_FIN);
		bool synFlag = (tcph->th_flags & TH_SYN) >> 1;
		bool rstFlag = (tcph->th_flags & TH_RST) >> 2;

		uint32_t packetSequenceNumber = ntohl(tcph->seq);
		if (synFlag == true) {
			firstSequenceNumber = packetSequenceNumber + 1;
		}
		// Duplicate packet
		if (packets.find(packetSequenceNumber) != packets.end()) {
			return false;
		}
		// End of Stream
		if (finFlag == true || rstFlag == true) {
			return true;
		}
		// Packet without payload
		if (tcph->doff * 4 >= size) {
			return false;
		}
		uint16_t dataOffset = tcph->doff * 4;
		uint16_t tcpPayloadLength = size - dataOffset;
		packets[packetSequenceNumber].sequenceNumber = packetSequenceNumber;
		packets[packetSequenceNumber].nextSequenceNumber = packetSequenceNumber + tcpPayloadLength;
		packets[packetSequenceNumber].bytesProcessed = 0;
		packets[packetSequenceNumber].payloadLength = tcpPayloadLength;
		packets[packetSequenceNumber].TcpPayload.reserve(size - dataOffset);
		packets[packetSequenceNumber].TcpPayload = std::vector<unsigned char>(tcpSegment + dataOffset, tcpSegment + size);

		streamLength += (size - dataOffset);

		auto it = packets.begin();
		uint8_t firstByte = it->second.TcpPayload[firstPacketOffset];
		uint8_t secondByte = it->second.TcpPayload[firstPacketOffset];

		uint16_t dnsPacketLength = ntohs (it->second.TcpPayload[firstPacketOffset] << 8 + it->second.TcpPayload[firstPacketOffset+1]);
		if (packetSequenceNumber == firstSequenceNumber && (dnsPacketLength + 2) <= streamLength) {
			return true;
		}
		return false;
	}

	// Returns number of bytes copied to buf, with 0 being no DNS message available from the TCP stream
	uint32_t getDnsMessage (unsigned char *buf) {
		auto it = packets.begin();
		if (it->second.sequenceNumber != firstSequenceNumber) {
			return 0;
		}
		uint16_t dnsPacketLength = ntohs (it->second.TcpPayload[firstPacketOffset] << 8 + it->second.TcpPayload[firstPacketOffset+1]);
		if ((dnsPacketLength + 2) > streamLength) {
			return 0;
		}
		uint32_t nextSeq = firstSequenceNumber;
		uint32_t bytesAvailable = 0;
		while( it != packets.end() && (bytesAvailable + 2) < dnsPacketLength) {
			if (it->second.sequenceNumber != nextSeq) {
				// The network has lost a packet somewhere so we need to wait for retransmission
				return 0;
			}
			nextSeq = it->second.nextSequenceNumber;
			bytesAvailable = it->second.payloadLength;
			it++;
		}
		if ((bytesAvailable + 2) < dnsPacketLength) {
			return 0;
		}
		// We've verified enough bytes are available to read the complete DNS message
		it = packets.begin();
		uint32_t totalBytesCopied = 0;
		bool messageLengthParsed = false;
		uint32_t bytesNeeded = dnsPacketLength;
		while( bytesNeeded > 0) {
			uint8_t bytesSkipped = 0;
			auto payload_it = it->second.TcpPayload.begin();
			if (messageLengthParsed == false) {
				messageLengthParsed = true;
				bytesSkipped = 2;
				payload_it += bytesSkipped;
			}
			totalBytesCopied += it->second.payloadLength - bytesSkipped;

			std::copy(payload_it, it->second.TcpPayload.end(), buf + totalBytesCopied);
			totalBytesCopied += it->second.payloadLength - bytesSkipped;
			if (totalBytesCopied >= bytesNeeded) {
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
		return dnsPacketLength;
	}
};

#endif /* TCPSNOOP_H_ */
