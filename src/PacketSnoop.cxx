/*
 * PacketSnoop.cxx
 *
 *  Created on: May 28, 2017
 *      Author: steven
 */

#include "boost/asio.hpp"

// #include "dnslib.h"
#include "InterfaceMap.h"
#include "PacketSnoop.h"
#include "TcpSnoop.h"


int PacketSnoop::Open(std::string input, uint32_t inExpiration) {
	// '(ip or ip6) and (tcp or udp) and port 53'
	struct sock_filter bpfcode[] = {
			{ 0x28, 0, 0, 0x0000000c },
			{ 0x15, 0, 10, 0x00000800 },
			{ 0x30, 0, 0, 0x00000017 },
			{ 0x15, 1, 0, 0x00000006 },
			{ 0x15, 0, 17, 0x00000011 },
			{ 0x28, 0, 0, 0x00000014 },
			{ 0x45, 15, 0, 0x00001fff },
			{ 0xb1, 0, 0, 0x0000000e },
			{ 0x48, 0, 0, 0x0000000e },
			{ 0x15, 11, 0, 0x00000035 },
			{ 0x48, 0, 0, 0x00000010 },
			{ 0x15, 9, 10, 0x00000035 },
			{ 0x15, 0, 9, 0x000086dd },
			{ 0x30, 0, 0, 0x00000014 },
			{ 0x15, 2, 0, 0x00000006 },
			{ 0x15, 6, 0, 0x0000002c },
			{ 0x15, 0, 5, 0x00000011 },
			{ 0x28, 0, 0, 0x00000036 },
			{ 0x15, 2, 0, 0x00000035 },
			{ 0x28, 0, 0, 0x00000038 },
			{ 0x15, 0, 1, 0x00000035 },
			{ 0x6, 0, 0, 0x00040000 },
			{ 0x6, 0, 0, 0x00000000 },
	};
	struct sock_fprog bpf = {
		.len = size(bpfcode),
		.filter = bpfcode,
	};

	// ETH_P_ALL is required to also capture outgoing packets
	// However, with ETH_P_ALL we get some packets twice with same sequence number but different packet size
	// https://www.spinics.net/lists/netdev/msg159788.html or something like that
	// So for now we use ETH_P_IP meaning that for TCP we can't check that an answer matches a query that was sent out if
	// we're running on a recursive DNS server .
	sock = socket( AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) ;
	if (Debug == true) {
		syslog (LOG_DEBUG, "Opened AF_PACKET SOCK_RAW with ETH_P_ALL");
	}
	//setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
	if(sock < 0) {
	    //Print the error with proper message
	 	syslog(LOG_CRIT, "Socket Error");
	}
	int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (ret < 0) {
	    syslog (LOG_CRIT, "Setsockopt Error");
	}
	return sock;
}

bool PacketSnoop::ProcessEvent(struct epoll_event &event) {
    struct sockaddr_ll saddr;
    int saddr_size = sizeof saddr;
    unsigned char buffer[65600]; // It might be big! We also may use it copy a DNS message from TCP flow

    int data_size = recvfrom(sock, buffer , 65536 , 0 , (struct sockaddr *) &saddr , (socklen_t*)&saddr_size);
    if(data_size <0 ) {
        syslog(LOG_WARNING, "Recvfrom error , failed to get packets\n");
        return true;
    }
    Parse(buffer, data_size, saddr.sll_ifindex);
    return false;
}

bool PacketSnoop::Parse (unsigned char *frame, size_t size, int ifindex) {
	syslog (LOG_DEBUG, "Parsing packet of %zu bytes", size);
	// Get the IP Header part of this packet , excluding the ethernet header
    struct ethhdr *ethh = (struct ethhdr *) frame;

	uint8_t af;
	unsigned short iphdrlen;
	unsigned short protocol;
	uint16_t payloadLength = 0;
	uint16_t ipPacketLength = 0;
   	// struct sockaddr_storage source, dest;
   	// memset(&source, 0, sizeof(source));
   	// memset(&dest, 0, sizeof(dest));
	char srcString[INET6_ADDRSTRLEN], destString[INET6_ADDRSTRLEN];

   	if (ntohs(ethh->h_proto) == 0x0800) {
		af = AF_INET;
		struct iphdr *iph = (struct iphdr*) (frame + sizeof(struct ethhdr));
		iphdrlen = iph->ihl*4;
		if (iphdrlen < sizeof(struct iphdr)) {
		    // Packet is broken!
		    // IP packets must not be smaller than the mandatory IP header.
		    return false;
		}
		if (in_cksum((void *) iph, iphdrlen, 0) != 0) {
		    // Packet is broken!
		    // Checksum of IP header does not verify, thus header is corrupt.
		    return false;
		}
		ipPacketLength = ntohs(iph->tot_len);
		if (ipPacketLength < iphdrlen) {
		    // Packet is broken!
		    // The overall packet cannot be smaller than the header.
		    return false;
		}
		payloadLength = ntohs(iph->tot_len) - iphdrlen;
		if (payloadLength < sizeof(struct tcphdr)) {
		    // Packet is broken!
		    // A TCP header doesn't even fit into the data that follows the IP header.
		    return false;
		}

		protocol = iph->protocol;
		struct sockaddr_in source, dest;
	   	memset(&source, 0, sizeof(source));
	   	memset(&dest, 0, sizeof(dest));
	   	source.sin_addr.s_addr = iph->saddr;
	   	dest.sin_addr.s_addr = iph->daddr;
	   	if (inet_ntop(af, &(source.sin_addr), srcString, INET6_ADDRSTRLEN) == nullptr) {
	   		syslog (LOG_ERR, "Invalid source IP address");
	   		return false;
	   	}
	   	if (inet_ntop(af, &(dest.sin_addr), destString, INET6_ADDRSTRLEN) == nullptr) {
	   		syslog (LOG_ERR, "Invalid destination IP address");
	   		return false;
	   	}
   	} else	if (ntohs(ethh->h_proto) == 0x86DD) {
		af = AF_INET6;
		iphdrlen = 40;
		struct ipv6hdr *ipv6h = (struct ipv6hdr*) (frame + sizeof(struct ethhdr));
		payloadLength = ntohs(ipv6h->payload_len);
		if (ipv6h->nexthdr != 6 && ipv6h->nexthdr != 17) {
			syslog (LOG_INFO, "Sorry, only support for IPv6 without optional headers for now %u", ipv6h->nexthdr);
			return true;
		}
		protocol = ipv6h->nexthdr;
 	   	if (inet_ntop(af, &(ipv6h->saddr), srcString, INET6_ADDRSTRLEN) == nullptr) {
	   		syslog (LOG_ERR, "Invalid source IP address");
	   		return false;
	   	}
	    if (inet_ntop(af, &(ipv6h->daddr), destString, INET6_ADDRSTRLEN) == nullptr) {
	    	syslog (LOG_ERR, "Invalid destination IP address");
	   		return false;
	   	}
   	} else {
		syslog (LOG_INFO, "Received Ethernet packet with unsupported protocol %u", ethh->h_proto);
		return true;
	}

    MacAddress Mac (ethh->h_source);

    if (Debug == true) {
     	syslog(LOG_DEBUG, "Parsing packet from %s to %s, protocol %u, packet size %u, header length %u from MAC %s",
     			srcString, destString, protocol, ipPacketLength, iphdrlen, Mac.c_str() );
     }


	//Check the Protocol and do accordingly...
	switch (protocol) {
    	case 6: //TCP Protocol
    		{
    			struct tcphdr *tcph=(struct tcphdr*)(frame  + iphdrlen + sizeof(struct ethhdr));
    			if (ipPacketLength < (iphdrlen + tcph->doff * 4)) {
    				if (Debug == true) {
    					syslog (LOG_DEBUG, "Invalid packet, IP packet length < ip header + tcp header");
    				}
    				return false;
    			}
    			if (tcpcsum(frame) != 0) {
    				if (Debug == true) {
    					syslog (LOG_DEBUG, "Received TCP packet with invalid checksum");
    				}
    				return false;
    			}
    			// We have to pass the TCP header to TcpSnoop so only skip ethernet and IP headers
    			int header_size =  sizeof(struct ethhdr) + iphdrlen;
    			unsigned char *payload = frame + header_size;
    			if (tcpcsum(frame) != 0) {
    				if (Debug == true) {
    					syslog(LOG_DEBUG, "Received TCP packet with invalid checksum");
    				}
    			}
    			uint16_t srcPort = ntohs(tcph->source);
    			uint16_t destPort = ntohs(tcph->dest);
    			boost::asio::ip::address src, dest;
    			src.from_string(srcString);
    			dest.from_string(destString);

    			if (Debug == true) {
    	    		syslog (LOG_DEBUG, "TCP source port %u, dest port %u", srcPort, destPort);
    	    	}
    	    	if (ntohs(tcph->source) == 53 || ntohs(tcph->dest) == 53 ) {
        			bool finFlag = (tcph->th_flags & TH_FIN);
        			bool rstFlag = (tcph->th_flags & TH_RST) >> 2;
    	    		std::shared_ptr<TcpSnoop> tsPtr = getTcpSnoopInstance(src, srcPort, dest, destPort);
    	    		if (tsPtr == nullptr) {
    	    			tsPtr = std::make_shared<TcpSnoop>(Debug);
    	    			addTcpSnoopInstance(src, srcPort, dest, destPort, tsPtr);
    	    		}
    	    		if ((tsPtr)->addPacket(payload, payloadLength)) {
    	    			uint16_t bytesRead = (tsPtr)->getDnsMessage(frame);
    	    			parseDnsPacket (frame, bytesRead, Mac, srcString, ifindex);
    	    		}
    			} else {
    				syslog(LOG_WARNING, "Received PacketSnoop TCP packet with source port %u, destination port %u", srcPort, destPort);
    			}
    		}
    		break;
    	case 17: //UDP Protocol
    	    {
    	    	struct udphdr *udph = (struct udphdr*)(frame + iphdrlen  + sizeof(struct ethhdr));
    	    	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    	    	unsigned char *payload = frame + header_size;

    	    	if (Debug == true) {
    	    		syslog (LOG_DEBUG, "UDP source port %u, dest port %u", ntohs(udph->source), ntohs(udph->dest));
    	    	}
    	    	if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53) {
    	    		parseDnsPacket(payload, payloadLength, Mac, srcString, ifindex);
    	    		// Parse_Dns_Packet(frame + sizeof(struct ethhdr) , size - sizeof(struct ethhdr));
    	    	} else if  (ntohs(udph->source) == 67 || ntohs(udph->dest) == 68 ||
    					ntohs(udph->source) == 68 || ntohs(udph->dest) == 68) {
    				parseDhcpUdpPacket(payload, payloadLength);
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

std::shared_ptr<TcpSnoop> PacketSnoop::getTcpSnoopInstance(const boost::asio::ip::address inSrc, const uint16_t inSrcPort,
	const boost::asio::ip::address inDest, const uint16_t inDestPort) {
	auto sit = tcpSnoops.find(inSrc);
	if(sit  == tcpSnoops.end()) {
		return nullptr;
	}
	auto spit = tcpSnoops[inSrc].find(inSrcPort);
	if( spit == tcpSnoops[inSrc].end()) {
		return nullptr;
	}
	auto dit = tcpSnoops[inSrc][inSrcPort].find(inDest);
	if( dit == tcpSnoops[inSrc][inSrcPort].end()) {
		return nullptr;
	}
	auto dpit = tcpSnoops[inSrc][inSrcPort][inDest].find(inDestPort);
	if( dpit == tcpSnoops[inSrc][inSrcPort][inDest].end()) {
		return nullptr;
	}
	return dpit->second;
}

void PacketSnoop::addTcpSnoopInstance(const boost::asio::ip::address inSrc, const uint16_t inSrcPort,
		const boost::asio::ip::address inDest, const uint16_t inDestPort, const std::shared_ptr<TcpSnoop> ts_ptr) {
	tcpSnoops[inSrc][inSrcPort][inDest][inDestPort] = ts_ptr;
}

bool PacketSnoop::parseDnsPacket(const unsigned char *payload, const size_t size, const MacAddress &inMac, const std::string sourceIp, const int ifIndex) {
    if (size < 12) {
    	syslog (LOG_WARNING, "Receive DNS packet smaller than 12 bytes");
    	return true;
    }
    Tins::DNS *q;
	InterfaceMap *ifMap = hC->getInterfaceMap();
	try {
		q = new Tins::DNS(payload, size);
	}
	catch (const Tins::malformed_packet &e) {
		return true;
	}

    // Note, additional resources section is not processed as this is not information a non-resursive DNS client would use

    if (Debug == true) {
    	syslog(LOG_DEBUG,"Query ID: %u on interface %u", q->id(), ifIndex);
    	syslog(LOG_DEBUG,"Questions: %u Answers: %u Additional answers: %u", q->questions_count(), q->answers_count(), q->additional_count());
    }
    // From the LAN, only accept packets with no answers
    // From the WAN, only accept packets with answers
    if (ifMap->isLanInterface(ifIndex) == true && q->answers_count() == 0 && q->additional_count() == 0) {
    	for (auto it: q->queries()) {
    		if (Debug == true) {
        		syslog(LOG_DEBUG, "Question %u : %s %u %u", q->id(), it.dname().c_str(),
        				it.query_class(), it.query_type());
    		}
    		// Here we track which DNS queries each Host has executed so when we report traffic stats, we can
    		// look at the reverse DNS path from IP address and match that to the original DNS query. As multiple
    		// FQDNs may resolve to the same IP address and the reverse path may thus result in multiple FQDNs,
    		// we need to keep track which of those FQDNs were queried by the Host.
    	    std::shared_ptr<Host> h = hC->FindOrCreateHostByMac(inMac, "", sourceIp);
    		h->addorupdateDnsQueryList(it.dname());
    	}
    	delete q;
    	return false;
    } else if (ifMap->isWanInterface(ifIndex) && q->answers_count() == 0) {
    	// This is an outgoing query or an response to client without answers
    	// Store the Query ID in a short-term cache so that incoming answers
    	// can be confirmed to come in response to the query
    	// TODO: prune this cache!
    	hC->addorupdateDnsQueryCache(q->id());
    } else if (ifMap->isWanInterface(ifIndex) && q->answers_count() > 0) {
   		// Only accept an answer if for each question there is a matching outgoing query from the DNS server
   		// on which Noddos runs
   		if (hC->inDnsQueryCache(q->id()) == false) {
   			syslog(LOG_WARNING, "No matching entry in DnsQueryCache for %u", q->id());
   			delete q;
   			return true;
    	}

    	for (auto it: q->answers()) {
    		uint16_t i = 0;
    		char ipaddr[INET6_ADDRSTRLEN];
    		if (it.query_type() != 41) { // OPT pseudo-RR
    			if (Debug == true) {
    				syslog(LOG_DEBUG, "Answer %u : %-24s %5u %u %u", ++i, it.dname().c_str(), it.ttl(),
    					it.query_class(), it.query_type());
    			}
    			std::string dnsdata = it.data();
        	    switch(it.query_type())
        	    {
        	    	case Tins::DNS::QueryType::A:
        	    		{
        	    			boost::asio::ip::address_v4::bytes_type addr4;
        	    			std::copy(&dnsdata[0], &dnsdata[0]+ addr4.size(), addr4.data());
        	    			boost::asio::ip::address_v4 ipv4(addr4);
        	    			hC->addorupdateDnsCache(it.dname(), ipv4, it.ttl());
        	    			if (Debug == true) {
        	    				syslog(LOG_DEBUG, "A record: %s", ipv4.to_string().c_str());
        	    			}
        	    		}
        	    		break;
        	      case Tins::DNS::QueryType::AAAA:
        	      	  {
        	      		  boost::asio::ip::address_v6::bytes_type addr6;
        	      		  std::copy(&dnsdata[0], &dnsdata[0] + addr6.size(), addr6.data());
        	      		  boost::asio::ip::address_v6 ipv6(addr6);

        	          	  hC->addorupdateDnsCache(it.dname(), ipv6, it.ttl());
        	          	  if (Debug == true) {
        	          		  syslog(LOG_DEBUG, "AAAA record: %s", ipv6.to_string().c_str());
        	          	  }
        	          	  break;
        	          }
        	      case Tins::DNS::QueryType::CNAME:
        	    	  hC->addorupdateDnsCache(it.dname(), dnsdata, it.ttl());
        	    	  if (Debug == true) {
        	    		  syslog(LOG_DEBUG, "CNAME record: %s", dnsdata.c_str());
        	    	  }
        	          break;
        	      default:
        	           break;
        	    }
    		} else {
    			if (Debug == true) {
    				syslog (LOG_DEBUG, "RR OPT");
    			}
    		}
    	}
    }
    delete q;
    return false;
}



bool PacketSnoop::parseDhcpUdpPacket(unsigned char *payload, size_t size) {
	// TODO
	syslog (LOG_INFO, "Ignoring DHCP packets for now");
	return false;
}

// thanx to http://seclists.org/lists/bugtraq/1999/Mar/0057.html
uint16_t tcpcsum (unsigned char * const packet) {
  struct tcp_pseudo pseudo;

  const struct iphdr * iph = (const struct iphdr *)(packet + sizeof(struct ethhdr));
  unsigned ipHdrLen = iph->ihl * 4;
  uint16_t ipPacketLen = ntohs(iph->tot_len);
  unsigned ipPayloadLen = ipPacketLen - ipHdrLen;

  // TCP header starts directly after IP header
  const struct tcphdr * tcp = (const struct tcphdr *)((const u_char *)iph + ipHdrLen);

  // Build the pseudo header and checksum it
  pseudo.src_addr = iph->saddr;
  pseudo.dst_addr = iph->daddr;
  pseudo.zero = 0;
  pseudo.proto = 6;
  pseudo.length = htons(ipPayloadLen);
  uint16_t csum = in_cksum(&pseudo, (unsigned)sizeof(pseudo), 0);

  // Update the checksum by checksumming the TCP header
  // and data as if those had directly followed the pseudo header
  csum = in_cksum((void *) tcp, ipPayloadLen, (uint16_t)~csum);

  return csum;
}

uint16_t in_cksum (void * const addr, const unsigned inlen, const uint16_t init) {
  uint32_t sum;
  const uint16_t * word;
  unsigned len = inlen;

  sum = init;
  word = (uint16_t *) addr;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */

  while (len >= 2) {
    sum += *(word++);
    len -= 2;
  }

  if (len > 0) {
    uint16_t tmp;

    *(uint8_t *)(&tmp) = *(uint8_t *)word;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ((uint16_t)~sum);
}


