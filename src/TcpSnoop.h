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
private:
	uint8_t dataOffset = 0;
	uint32_t sequenceNumber = 0;
	uint16_t checksum = 0;
	std::vector<unsigned char> TcpPayload;

public:
	TcpSegment(const unsigned char * tcpSegment, const uint16_t size) {
		struct tcphdr *tcph = (struct tcphdr*) tcpSegment;
		dataOffset = tcph->doff * 4;
		sequenceNumber = ntohl(tcph->seq);
		// TODO validate checksums
		// checksum = ntohs(tcph->check);
		TcpPayload.reserve(size - dataOffset);
		TcpPayload = std::vector<unsigned char>(tcpSegment + dataOffset, tcpSegment + size);
	}
};

class TcpSnoop {
private:
	std::map<uint32_t,std::shared_ptr<struct TcpSegment>> outPackets, inPackets;
	uint32_t portA = 0, portB = 0;
	uint16_t firstPacketOffset = 0;
	uint32_t inFirstSequenceNumber = 0, outFirstSequenceNumber = 0;
	uint32_t inStreamLength = 0, outStreamLength = 0;
	time_t Expiration;

public:
	TcpSnoop(const uint32_t inPortA, const uint32_t inPortB): portA{inPortA}, portB{inPortB} {
		Expiration = time(nullptr) + 120;
	}

	TcpSnoop(const uint32_t inPortA, const uint32_t inPortB, const unsigned char *tcpSegment, const uint16_t size):
			portA{inPortA}, portB{inPortB} {
		Expiration = time(nullptr) + 120;
		addPacket(inPortA, inPortB, tcpSegment, size);
	}

	~TcpSnoop() {};

	/*
	 * addPacket
	 * input: pointer to TCP Segment, size of TCP segement, whether packet was received or sent by host
	 * output: bool on whether data is ready for parsing with TcpSnoop:parseStream
	 */
	bool addPacket (const uint32_t inPortA, const uint32_t inPortB, const unsigned char *tcpSegment, const uint16_t size) {
		struct tcphdr *tcph = (struct tcphdr*) tcpSegment;

		std::map<uint32_t, std::shared_ptr<struct TcpSegment>> &p = (inPortA == portA) ? inPackets : outPackets;
		uint32_t &firstSequenceNumber = (inPortA == portA) ? inFirstSequenceNumber : outFirstSequenceNumber;
		uint32_t &streamLength = (inPortA == portA) ? inStreamLength : outStreamLength;

		bool finFlag = (tcph->th_flags & TH_FIN);
		bool synFlag = (tcph->th_flags & TH_SYN) >> 1;
		bool rstFlag = (tcph->th_flags & TH_RST) >> 2;

		uint32_t packetSequenceNumber = ntohl(tcph->seq);
		if (synFlag == true) {
			firstSequenceNumber = packetSequenceNumber;
		}
		// Duplicate packet
		if (p.find(packetSequenceNumber) != p.end()) {
			return false;
		}
		// End of Stream
		if (finFlag == true || rstFlag == true) {
			return true;
		}
		// Packet without payload
		if (tcph->doff * 4 <= size) {
			return false;
		}
		auto t = std::make_shared<TcpSegment> (tcpSegment, size);
		p[packetSequenceNumber] = t;
		streamLength += (size - t->dataOffset);

		auto it = p.begin();
		uint16_t * dnsPacketLength_ptr = (uint16_t *) *(it->second) + firstPacketOffset;
		uint16_t dnsPacketLength = ntohs (*dnsPacketLength_ptr);
		if (packetSequenceNumber == firstSequenceNumber && dnsPacketLength <= streamLength) {
			return true;
		}
		return false;
	}
};

#endif /* TCPSNOOP_H_ */
