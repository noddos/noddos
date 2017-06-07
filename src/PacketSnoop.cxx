/*
 * PacketSnoop.cxx
 *
 *  Created on: May 28, 2017
 *      Author: steven
 */

#include "boost/asio.hpp"

#include "dns.h"
#include "dnsmappings.h"
#include "InterfaceMap.h"
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

	// ETH_P_ALL is required to also capture outgoing packets
	sock = socket( AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) ;
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

bool PacketSnoop::ProcessEvent(struct epoll_event &event) {
    struct sockaddr_ll saddr;
    int saddr_size = sizeof saddr;
    unsigned char buffer[65536]; // It might be big!

    int data_size = recvfrom(sock, buffer , 65536 , 0 , (struct sockaddr *) &saddr , (socklen_t*)&saddr_size);
    if(data_size <0 ) {
        syslog(LOG_WARNING, "Recvfrom error , failed to get packets\n");
        return true;
    }
    Parse(buffer, data_size, saddr.sll_ifindex);
    return false;
}

bool PacketSnoop::Parse (unsigned char *frame, size_t size, int ifindex) {
	// Get the IP Header part of this packet , excluding the ethernet header
    struct ethhdr *ethh = (struct ethhdr *) frame;

	uint8_t af;
	unsigned short iphdrlen;
	unsigned short protocol;
   	// struct sockaddr_storage source, dest;
   	// memset(&source, 0, sizeof(source));
   	// memset(&dest, 0, sizeof(dest));
	char sourcestring[INET6_ADDRSTRLEN], deststring[INET6_ADDRSTRLEN];

   	if (ntohs(ethh->h_proto) == 0x0800) {
		af = AF_INET;
		struct iphdr *iph = (struct iphdr*) (frame + sizeof(struct ethhdr));
		iphdrlen = iph->ihl*4;
		protocol = iph->protocol;
		struct sockaddr_in source, dest;
	   	memset(&source, 0, sizeof(source));
	   	memset(&dest, 0, sizeof(dest));
	   	source.sin_addr.s_addr = iph->saddr;
	   	dest.sin_addr.s_addr = iph->daddr;
	   	if (inet_ntop(af, &(source.sin_addr), sourcestring, INET6_ADDRSTRLEN) == nullptr) {
	   		syslog (LOG_ERR, "Invalid source IP address");
	   		return false;
	   	}
	   	if (inet_ntop(af, &(dest.sin_addr), deststring, INET6_ADDRSTRLEN) == nullptr) {
	   		syslog (LOG_ERR, "Invalid destination IP address");
	   		return false;
	   	}
   	} else	if (ntohs(ethh->h_proto) == 0x86DD) {
		af = AF_INET6;
		iphdrlen = 40;
		struct ipv6hdr *ipv6h = (struct ipv6hdr*) (frame + sizeof(struct ethhdr));
		if (ipv6h->nexthdr != 6 && ipv6h->nexthdr != 17) {
			syslog (LOG_INFO, "Sorry, only support for IPv6 without optional headers for now %u", ipv6h->nexthdr);
			return true;
		}
		protocol = ipv6h->nexthdr;
 	   	if (inet_ntop(af, &(ipv6h->saddr), sourcestring, INET6_ADDRSTRLEN) == nullptr) {
	   		syslog (LOG_ERR, "Invalid source IP address");
	   		return false;
	   	}
	    if (inet_ntop(af, &(ipv6h->daddr), deststring, INET6_ADDRSTRLEN) == nullptr) {
	    	syslog (LOG_ERR, "Invalid destination IP address");
	   		return false;
	   	}
   	} else {
		syslog (LOG_INFO, "Received Ethernet packet with unsupported protocol %u", ethh->h_proto);
		return true;
	}

   if (Debug == true) {
    	syslog(LOG_DEBUG, "Parsing packet from %s to %s", sourcestring, deststring );
    }

    MacAddress Mac (ethh->h_source);

	//Check the Protocol and do accordingly...
	switch (protocol) {
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
    	    		Parse_Dns_Packet(payload, size - header_size, Mac, sourcestring, ifindex);
    	    		// Parse_Dns_Packet(frame + sizeof(struct ethhdr) , size - sizeof(struct ethhdr));
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

bool PacketSnoop::Parse_Dns_Packet(const unsigned char *payload, const size_t size, const MacAddress &inMac, const std::string sourceIp, const int ifIndex) {
    if (size < 12) {
    	syslog (LOG_WARNING, "Receive DNS packet smaller than 12 bytes");
    	return true;
    }
	InterfaceMap *ifMap = hC->getInterfaceMap();

    dns_decoded_t  bufresult[DNS_DECODEBUF_8K];
    size_t         bufsize = sizeof(bufresult);
    dns_packet_t reply[DNS_BUFFER_UDP];
    size_t       replysize = sizeof(reply);

    int rc = dns_decode(bufresult,&bufsize,(unsigned long int *) payload,size);
    if (rc != RCODE_OKAY) {
      syslog(LOG_INFO, "dns_decode() = (%d) %s",rc,dns_rcode_text((dns_rcode_t)rc));
      return true;
    }
    dns_query_t *q = (dns_query_t*) bufresult;

    // Note, additional resources section is not processed as this is not information a non-resursive DNS client would use

    if (Debug == true) {
    	syslog(LOG_DEBUG,"Query ID: %u --- Bytes used: %lu", q->id, (unsigned long)bufsize);
    	syslog(LOG_DEBUG,"Questions: %lu Answers: %lu Additional answers: %lu", q->qdcount, q->ancount, q->arcount);
    }
    // From the LAN, only accept packets with no answers
    // From the WAN, only accept packets with answers
    if (ifMap->isLanInterface(ifIndex) == true && q->ancount == 0 && q->arcount == 0) {
    	for (uint16_t i = 0; i < q->qdcount; i++) {
    		if (Debug == true) {
        		syslog(LOG_DEBUG, "Question %u : %s %s %s", q->id, q->questions[i].name,
        				dns_class_text(q->questions[i].dclass), dns_type_text (q->questions[i].type));
    		}
    		// Here we track which DNS queries each Host has executed so when we report traffic stats, we can
    		// look at the reverse DNS path from IP address and match that to the original DNS query. As multiple
    		// FQDNs may resolve to the same IP address and the reverse path may thus result in multiple FQDNs,
    		// we need to keep track which of those FQDNs were queried by the Host.
    	    std::shared_ptr<Host> h = hC->FindOrCreateHostByMac(inMac, "", sourceIp);
    		h->addorupdateDnsQueryList(q->questions[i].name);
    	}
    	return false;
    } else if (ifMap->isWanInterface(ifIndex) && q->ancount == 0) {
    	// This is an outgoing query or an response to client without answers
    	// Store the Query ID in a short-term cache so that incoming answers
    	// can be confirmed to come in response to the query
    	hC->addorupdateDnsQueryCache(q->id);
    } else if (ifMap->isWanInterface(ifIndex) && q->ancount > 0) {
    	for (uint16_t i = 0; i < q->qdcount; i++) {
    		// Only accept an answer if for each question there is a matching outgoing query from the DNS server
    		// on which Noddos runs
    		if (hC->inDnsQueryCache(q->id) == false) {
    			syslog(LOG_WARNING, "No matching entry in DnsQueryCache for %u", q->id);
    			return true;
    		}
    	}
    	for (uint16_t i; i < q->ancount; i++) {
    		char ipaddr[INET6_ADDRSTRLEN];
    		if (q->answers[i].generic.type != RR_OPT) {
    			if (Debug == true) {
    				syslog(LOG_DEBUG, "Answer %u : %-24s %5u %s %s", i, q->answers[i].generic.name, q->answers[i].generic.ttl,
    					dns_class_text(q->answers[i].generic.dclass), dns_type_text (q->answers[i].generic.type));
    			}
        	    switch(q->answers[i].generic.type)
        	    {
        	    	case RR_A:
        	    		{
        	    			boost::asio::ip::address_v4 ipv4(ntohl(q->answers[i].a.address));
        	    			hC->addorupdateDnsCache(q->answers[i].generic.name, ipv4, q->answers[i].generic.ttl);
        	    			if (Debug == true) {
        	    				inet_ntop(AF_INET,&q->answers[i].a.address,ipaddr,sizeof(ipaddr));
        	    				syslog(LOG_DEBUG, "%s", ipaddr);
        	    			}
        	    		}
        	    		break;
        	      case RR_AAAA:
        	      	  {
        	      		  std::array<unsigned char, 16> v6addr;
        	      		  for (int c = 0; i < 16; c++) {
        	      			  v6addr[c] = q->answers[i].aaaa.address.s6_addr[c];
        	      		  }

						  boost::asio::ip::address_v6 ipv6(v6addr);
        	          	  // q->answers[i].aaaa.address.s6_addr;
        	          	  hC->addorupdateDnsCache(q->answers[i].generic.name, ipv6, q->answers[i].generic.ttl);
        	          	  if (Debug == true) {
        	          		  inet_ntop(AF_INET6,&q->answers[i].aaaa.address,ipaddr,sizeof(ipaddr));
        	          		  syslog(LOG_DEBUG, "%s", ipaddr);
        	          	  }
        	          	  break;
        	          }
        	      case RR_CNAME:
        	    	  hC->addorupdateDnsCache(q->answers[i].generic.name, q->answers[i].cname.cname, q->answers[i].generic.ttl);
        	    	  if (Debug == true) {
        	    		  syslog(LOG_DEBUG, "%s", q->answers[i].cname.cname);
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
    return false;
}

bool PacketSnoop::Parse_Dns_Tcp_Packet(unsigned char *payload, size_t size) {
	// TODO
	syslog (LOG_INFO, "Ignoring DNS TCP packets for now");
	return false;
}

bool PacketSnoop::Parse_Dhcp_Udp_Packet(unsigned char *payload, size_t size) {
	// TODO
	syslog (LOG_INFO, "Ignoring DHCP packets for now");
	return false;
}

