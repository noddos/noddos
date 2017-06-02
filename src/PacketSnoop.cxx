/*
 * PacketSnoop.cxx
 *
 *  Created on: May 28, 2017
 *      Author: steven
 */

#include "PacketSnoop.h"



int PacketSnoop::Open(std::string input, uint32_t inExpiration) {
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
	struct sock_fprog bpf = {
		.len = size(bpfcode),
		.filter = bpfcode,
	};

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

bool PacketSnoop::Parse (unsigned char *frame, size_t size) {
	// Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*) (frame + sizeof(struct ethhdr));

	// TODO IPv6 support
	uint8_t af = 2;
	if (iph->version != 4) {
		af = 10;
		syslog (LOG_INFO, "Sorry, only support for IPv4 for now, not %u", iph->version);
		return true;
	}

    unsigned short iphdrlen = iph->ihl*4;

	struct sockaddr_in source,dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    //  unsigned char buf[sizeof(struct in6_addr)];
    char sourcestring[INET6_ADDRSTRLEN], deststring[INET6_ADDRSTRLEN];

    if (inet_ntop(af, &(source.sin_addr), sourcestring, INET6_ADDRSTRLEN) == nullptr) {
    	syslog (LOG_ERR, "Invalid source IP address");
    	return false;
    }
    if (inet_ntop(af, &(dest.sin_addr), deststring, INET6_ADDRSTRLEN) == nullptr) {
    	syslog (LOG_ERR, "Invalid source IP address");
    	return false;
    }



	syslog(LOG_DEBUG, "Parsing packet from %s to %s", sourcestring, deststring );

	//Check the Protocol and do accordingly...
	switch (iph->protocol) {
    	case 6: //TCP Protocol
    		{
    			struct tcphdr *tcph=(struct tcphdr*)(frame  + iphdrlen + sizeof(struct ethhdr));
    			int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    			unsigned char *payload = frame + header_size;

    	    	syslog (LOG_DEBUG, "TCP source port %u, dest port %u", ntohs(tcph->source), ntohs(tcph->dest));
    	    	if (ntohs(tcph->source) == 53 || ntohs(tcph->dest) == 53 ) {
    	    		Parse_Dns_Tcp_Packet(payload, size - header_size);
    			} else {
    				syslog(LOG_WARNING, "Received PacketSnoop TCP packet with source port %u, destination port %u", ntohs(tcph->source), ntohs(tcph->dest));
    			}
    		}
    		break;
    	case 17: //UDP Protocol
    	    {
    	    	struct udphdr *udph = (struct udphdr*)(frame + iphdrlen  + sizeof(struct ethhdr));
    	    	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    	    	unsigned char *payload = frame + header_size;

    	    	syslog (LOG_DEBUG, "UDP source port %u, dest port %u", ntohs(udph->source), ntohs(udph->dest));
    	    	if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53) {
    	    		Parse_Dns_Packet(payload, size - header_size);
    	    	} else if  (ntohs(udph->source) == 67 || ntohs(udph->dest) == 68 ||
    					ntohs(udph->source) == 68 || ntohs(udph->dest) == 68) {
    				Parse_Dhcp_Udp_Packet(payload, size - header_size);
    			} else {
    				syslog(LOG_WARNING, "Received PacketSnoop UDP packet with source port %u, destination port %u", ntohs(udph->source), ntohs(udph->dest));
    			}
    	    }
    		break;
        default: //Some Other Protocol like ARP etc.
        	syslog (LOG_ERR, "PacketSnoop received packet with protocol other than TCP or UDP");
	}
	return false;
}

bool PacketSnoop::Parse_Dns_Tcp_Packet(unsigned char *payload, size_t size) {
	// TODO
	syslog (LOG_INFO, "Ignoring DNS TCP packets for now");
	return false;
}

inline const char * const BoolToString(bool b)
{
  return b ? "true" : "false";
}

bool PacketSnoop::Parse_Dns_Packet(unsigned char *payload, size_t size) {
    if (size < 12) {
    	syslog (LOG_WARNING, "Receive DNS packet smaller than 12 bytes");
    	return true;
    }
	struct dnshdr *dnsh = (struct dnshdr*) payload;


    uint16_t id = ntohs(dnsh->dns_id);
    uint16_t questions = ntohs(dnsh->dns_qdc);
    uint16_t answers = ntohs(dnsh->dns_anc);
    uint16_t nameservers = ntohs(dnsh->dns_nsc);
    uint16_t additionalanswers = ntohs(dnsh->dns_arc);

    syslog (LOG_DEBUG, "DNS Query with Id %u, questions %u, answers %u, nameservers %u, additional answers %u", id,
    		questions, answers, nameservers, additionalanswers);
    uint8_t qr= (payload[2] & 0x0f) >> 7;
    uint8_t opcode = (payload[2] & 0x78) >> 3;
    bool aa = (payload[2] & 0x04) ? true : false;
    bool truncated = (payload[2] & 0x02) ? true : false;
    bool recursion_desired = (payload[2] & 0x01) ? true : false;
    bool recursion_enabled = (payload[3] & 0x80) ? true : false;
    uint8_t rcode = payload[3] & 0x0f;

    if (qr == 0 && opcode > 0) {
    	syslog (LOG_DEBUG, "Ignoring reverse DNS lookups and DNS server status requests: %d", opcode);
    	return false;

    }
    if (qr == 1 && rcode > 0) {
    	syslog(LOG_INFO, "Received DNS response with rcode %d", rcode);
    	return true;
    }
    if (Debug == true) {
    	syslog (LOG_DEBUG, "DNS: response? %s, opcode: %u, authorative? %s, truncated? %s, recursion desired? %s, enabled? %s, rcode: %u",
    		BoolToString(qr), opcode, BoolToString(aa), BoolToString(truncated), BoolToString(recursion_desired), BoolToString(recursion_enabled), rcode);
    }
    // DNS packet header that we've just parsed is 12 bytes so now start parsing from position 12.
    uint16_t pos = 12;
    for (int q = 0; q < questions; q++) {
    	std::string qname;
    	while (*(payload + pos)) {
    		int len = *(payload + pos);
    		if (len > 63) {
    			syslog (LOG_INFO, "Received DNS query with label length > 63");
    		}
    		qname.append((char *) payload + pos + 1, len);
    		qname.append(".");
    		pos += len + 1;
       	}
    	if (qname.length() > 255) {
    		syslog (LOG_INFO, "Received DNS query for fqdn with length > 255");
    	}
    	// Skip terminating '\0'
    	pos++;

    	// uint16_t qtype = ntohs(*((uint16_t *) payload + pos));
    	uint16_t qtype = (uint16_t) payload[pos];
    	pos += 2;

    	// uint16_t qclass = ntohs(*((uint16_t *) payload + pos));
    	uint16_t qclass = (uint16_t) payload[pos];
    	pos += 2;
    	syslog (LOG_DEBUG, "DNS Query %s, qtype %u, qclass %u", qname.c_str(), qtype, qclass);
    }


    return false;
}

bool PacketSnoop::Parse_Dhcp_Udp_Packet(unsigned char *payload, size_t size) {
	// TODO
	syslog (LOG_INFO, "Ignoring DHCP packets for now");
	return false;
}

