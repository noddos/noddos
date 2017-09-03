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

 * HostCache.cxx
 *
 *  Created on: Mar 11, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#include <iostream>
#include <unordered_set>
#include <string>
#include <sstream>
#include <fstream>
#include <iterator>
#include <vector>
#include <cstring>
#include <memory>
#include <thread>

#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
// #include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>

#include <syslog.h>
#include <cstdio>
#include <iomanip>
#include <cstring>
#include <cstdlib>

#include <json.hpp>
using nlohmann::json;

#include <curl/curl.h>

#include "HostCache.h"

uint32_t HostCache::Prune (bool Force) {
	if (Debug == true) {
	    syslog (LOG_DEBUG, "HostCache: starting prune");
	}
	uint32_t prunedhosts = 0;
	for (auto it : hC) {
        std::string mac = it.second->MacAddress_get();
        std::string uuid = it.second->Uuid_get();
		if (it.second->Prune(Force)) {
			if(uuid != "") {
			    auto it = dpMap.find(uuid);
			    if (it != dpMap.end()) {
			        it->second->removeHost(mac);
			    }
			}
		    prunedhosts++;
		}
	}
	if (Debug == true) {
	    syslog(LOG_DEBUG, "HostCache: Pruned %u hosts", prunedhosts);
	}
	uint32_t count = pruneDnsQueryCache(Force);
    if (Debug == true) {
        syslog(LOG_DEBUG, "HostCache: Pruned %u DNS queries", count);
    }
	count = pruneDnsIpCache(Force);
    if (Debug == true) {
        syslog(LOG_DEBUG, "HostCache: Pruned %u DNS IP cache entries", count);
    }
    count = pruneDnsCnameCache(Force);
    if (Debug == true) {
        syslog(LOG_DEBUG, "HostCache: Pruned %u DNS CNAME cache entries", count);
    }
  	return prunedhosts;
}

uint32_t HostCache::Match() {
	uint32_t matched = 0;
	for (auto it : hC) {
		if (it.second->Match(dpMap)) {
			matched++;
		}
	}
	updateDeviceProfileMatchesDnsData();
	writeIptables();
	return matched;
}

bool HostCache::MatchByMac(const MacAddress &inMacAddress) {
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Starting match for MAC address %s", inMacAddress.c_str());
	}
	if (hC.find(inMacAddress.get()) != hC.end()) {
		auto &h = *(hC[inMacAddress.get()]);
		return h.Match(dpMap);
	}
	return false;
}

bool HostCache::MatchByIpAddress(const std::string inIpAddress) {
	if (Ip2MacMap.find(inIpAddress) != Ip2MacMap.end()) {
		MacAddress m(Ip2MacMap[inIpAddress]);
		return MatchByMac(m);
	}
	return false;
}

std::shared_ptr<Host> HostCache::FindHostByIp (const std::string inIp) {
	auto it = Ip2MacMap.find(inIp);
	if ( it == Ip2MacMap.end()) {
		return nullptr;
	}
	MacAddress mac(it->second);
	return FindHostByMac (mac);
}

std::shared_ptr<Host> HostCache::FindOrCreateHostByIp (const std::string inIp, const std::string Uuid) {
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Find or create host for IP %s", inIp.c_str());
	}

	if (inIp == "" || WhitelistedNodes.find(inIp) != WhitelistedNodes.end()) {
		return nullptr;
    }
	MacAddress Mac;
	auto it = Ip2MacMap.find(inIp);
	if ( it == Ip2MacMap.end()) {
		Mac = MacLookup(inIp);
		if (Mac.isValid() == false) {
			if (Debug == true) {
				syslog(LOG_DEBUG, "HostCache: Couldn't find ARP entry for %s", inIp.c_str());
			}
			return nullptr;
		}
		Ip2MacMap[inIp] = Mac.get();
	} else {
		Mac.set(it->second);
	}
	return FindOrCreateHostByMac (Mac, Uuid, inIp);
}

std::shared_ptr<Host> HostCache::FindHostByMac (const MacAddress &inMac) {
	if (inMac.isValid() == false) {
		syslog(LOG_WARNING, "HostCache: Mac Address with invalid value provided");
		return nullptr;
	}
	if (hC.find(inMac.get()) == hC.end()) {
		return nullptr;
	}
	return hC[inMac.get()];
}

std::shared_ptr<Host> HostCache::FindOrCreateHostByMac (const MacAddress inMac, const std::string Uuid, const std::string inIp) {
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Find or create host for MAC %s", inMac.c_str());
	}
	if (WhitelistedNodes.find(inMac.str()) != WhitelistedNodes.end()) {
		return nullptr;
    }
	if (inMac.isValid() == false) {
		syslog(LOG_WARNING, "HostCache: Empty Mac Address provided");
		return nullptr;
	}
	if (hC.find(inMac.get()) == hC.end()) {
		if (Debug == true) {
			syslog(LOG_DEBUG, "HostCache: Adding new Host with MAC address %s for IP %s", inMac.c_str(), inIp.c_str());
		}
		auto h = std::make_shared<Host>(inMac.str(), Uuid, Debug);
		h->IpAddress_set (inIp);
		hC[inMac.get()] = h;
		return h;
	}
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Found MAC address %s for IP %s", inMac.c_str(), inIp.c_str());
	}
	return hC[inMac.get()];
}

bool HostCache::AddByMac (const MacAddress inMacAddress, const std::string inIpAddress) {
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Creating new host for MAC %s with IP %s", inMacAddress.c_str(), inIpAddress.c_str());
	}
	if (hC.find(inMacAddress.get()) != hC.end()) {
		return false;
    }
	auto h = std::make_shared<Host>(inMacAddress, Debug);
	h->IpAddress_set (inIpAddress);
	hC[inMacAddress.get()] = h;
	Ip2MacMap[inIpAddress] = inMacAddress.get();
	return true;
}

bool HostCache::AddFlow (const std::string srcip, const uint16_t srcport, const std::string dstip, const uint16_t dstport, const uint8_t protocol, const uint32_t expiration) {
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Adding flow for host with IP %s", srcip.c_str());
	}
	// DHCP requests are sent from 0.0.0.0. As we can't associate this flow with a MAC address from the FlowTrack data,
	// we ignore the flow
	if (srcip == "0.0.0.0") {
		return false;
	}
	if (WhitelistedNodes.find(srcip) != WhitelistedNodes.end()) {
		return false;
	}

	std::shared_ptr<Host> h = FindOrCreateHostByIp(srcip);
	if (h) {
		h->FlowEntry_set(srcport, dstip, dstport, protocol, FlowExpiration);
		return true;
	}
	return false;
}


bool HostCache::AddDnsQueryIp (const std::string clientip, const std::string fqdn, const std::string ip, const uint32_t expire) {
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Adding dns query for %s for host with IP %s", fqdn.c_str(), clientip.c_str());
	}
	if (WhitelistedNodes.find(clientip) != WhitelistedNodes.end()) {
		return false;
	}

	std::shared_ptr<Host> h = FindOrCreateHostByIp(clientip);
	if (h) {
		h->addorupdateDnsQueryList(fqdn);
		return true;
	}
	return false;
}


bool HostCache::AddDhcpRequest (const std::string IpAddress, const MacAddress inMac, const std::string Hostname, const std::string DhcpVendor) {
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Adding DHCP request for host with MAC %s & IP %s", inMac.c_str(), IpAddress.c_str());
	}
	if ((IpAddress == "" || IpAddress == "0.0.0.0") && inMac.isValid() == false) {
		syslog(LOG_WARNING, "HostCache: No IpAdddress or Macaddress in DHCP request");
		return false;

	}
	if (isWhitelisted(IpAddress) || isWhitelisted(inMac.str())) {
		return false;
    }

	std::shared_ptr<Host> h;
	if (inMac.isValid() == true) {
		h = FindOrCreateHostByMac(inMac, "", IpAddress);
	} else {
		h = FindOrCreateHostByIp(IpAddress);
	}

	if (h) {
		h->Dhcp_set(IpAddress, inMac.str(), Hostname, DhcpVendor);
		return true;
	}
	return false;

}

bool HostCache::AddSsdpInfo (const std::shared_ptr<SsdpHost> sHost) {
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Adding SSDP info for host with IP %s", sHost->IpAddress.c_str());
	}
	if (sHost->IpAddress == "") {
		syslog(LOG_WARNING, "HostCache: AddSsdpInfo: no IP address provided");
		return false;
	}
	if (WhitelistedNodes.find(sHost->IpAddress) != WhitelistedNodes.end()) {
		return false;
	}

	std::shared_ptr<Host> h = FindOrCreateHostByIp(sHost->IpAddress);
	if (h) {
		h->SsdpInfo_set(sHost);
		return true;
	}
	return false;
}

// These functions are for DnsQueryCache
void HostCache::addorupdateDnsQueryCache (uint16_t id) {
	DnsQueryCache[id] = time(nullptr) + 15;
}

bool HostCache::inDnsQueryCache (uint16_t id) {
	if (DnsQueryCache.find(id) == DnsQueryCache.end()) {
		return false;
	}
	// Entry might be in the cache but is already stale
	if (DnsQueryCache[id] < time(nullptr)) {
		return false;
	}
	return true;
}

uint32_t HostCache::pruneDnsQueryCache (bool Force) {
	uint32_t deletecount = 0;
	time_t now = time(nullptr);
	auto i = DnsQueryCache.begin();
	while (i != DnsQueryCache.end()) {
		if (Force || i->second > now) {
			if (Debug == true) {
				syslog (LOG_DEBUG, "HostCache: Deleting %u from DnsQueryCache as %lu is later than %lu", i->first, i->second, now);
			}
			i = DnsQueryCache.erase(i);
			deletecount++;
		} else {
			i++;
		}
	}
	return deletecount;
}

// TODO: Lookup MAC addresses in ARP table using IOCTL now works but you need to specify the Ethernet interface and we don't have code for that yet
// so for now we'll continue doing lookups in /proc/net/arp even though that is slower
MacAddress HostCache::MacLookup (const std::string inIpAddress, const std::string inInterface, const int retries) {
	int domain;
	struct arpreq areq;
	memset(&areq, 0, sizeof(areq));
	void *addr_ptr;

	MacAddress Mac("00:00:00:00:00:00");
	if (inIpAddress.find(":") == std::string::npos ) {
		struct sockaddr_in *sin = (struct sockaddr_in *) &areq.arp_pa;
	    sin->sin_family = domain = AF_INET;
	    addr_ptr = &(sin->sin_addr);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &areq.arp_pa;
		sin6->sin6_family = domain = AF_INET6;
	    addr_ptr = &(sin6->sin6_addr);
	}
    if (not inet_pton(domain, inIpAddress.c_str(), addr_ptr)) {
		syslog (LOG_ERR, "HostCache: inet_pton failed for %s", inIpAddress.c_str());
		return Mac;
	}

	struct sockaddr_in *sin = (struct sockaddr_in *) &areq.arp_ha;
    sin->sin_family = ARPHRD_ETHER;
    strncpy(areq.arp_dev, inInterface.c_str(), 15);

    /* Get an internet domain socket. */
    int s;
	if ((s = socket(domain, SOCK_DGRAM, 0)) == -1) {
        syslog(LOG_ERR, "HostCache: Can't open socket for ARP table lookup");
        return Mac;
    }

    if (-1 == ioctl(s,SIOCGARP , (caddr_t) &areq)) {
		syslog (LOG_ERR, "HostCache: ARP lookup failure for %s", inIpAddress.c_str());
		if (retries > 0) {
			if (Debug == true) {
				syslog(LOG_DEBUG, "HostCache: Additional ARP lookup for %s", inIpAddress.c_str());
			}
			if (SendUdpPing (inIpAddress, 1900)) {
				usleep(5000);
				return MacLookup (inIpAddress, inInterface, retries - 1);
			}
		}
		return Mac;
	}
	char mA[18];
	unsigned char *ptr = (unsigned char *) areq.arp_ha.sa_data;
	sprintf(mA, "%02X:%02X:%02X:%02X:%02X:%02X",
	        (ptr[0] & 0xff), (ptr[1] & 0xff), (ptr[2] & 0xff),
	        (ptr[3] & 0xff), (ptr[4] & 0xff), (ptr[5] & 0xff));
	Mac.set(mA);
	return Mac;
}

uint32_t HostCache::getInterfaceIpAddresses() {
    if (Debug == true) {
        syslog (LOG_DEBUG, "HostCache: discovering IP addresses of network interfaces");
    }
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        syslog(LOG_ERR, "HostCache: Can't loop through local interfaces: getifaddrs");
        return 0;
    }

    // Walk through linked list, maintaining head pointer so we
    // can free list later

    for (ifa = ifaddr, n = 0; ifa != nullptr; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_name == nullptr || ifa->ifa_name == "") {
            continue;
        }
        family = ifa->ifa_addr->sa_family;

        // Display interface name and family (including symbolic
        //   form of the latter for the common families)

        if (Debug == true) {
        	syslog(LOG_DEBUG, "HostCache: Interface %-8s %s (%d)", ifa->ifa_name,
               (family == AF_PACKET) ? "AF_PACKET" :
               (family == AF_INET) ? "AF_INET" :
               (family == AF_INET6) ? "AF_INET6" : "???", family);
        }
        LocalInterfaces.insert(ifa->ifa_name);

        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                syslog(LOG_ERR, "HostCache: getnameinfo() failed: %s\n", gai_strerror(s));
                freeifaddrs(ifaddr);
                return 0;
            }

            if(Debug == true) {
            	syslog (LOG_DEBUG, "HostCache: Interface %s with IP address: %s", ifa->ifa_name, host);
            }
            LocalIpAddresses.insert(host);
        }
    }

    freeifaddrs(ifaddr);
	return 0;
}

MacAddress HostCache::MacLookup (const std::string inIpAddress, const int retries) {
	// TODO: we should cache ARP table and only refresh it if a MAC lookup fails
	if (Debug == true) {
	    syslog (LOG_DEBUG, "HostCache: deprecated MacLookup of %s", inIpAddress.c_str());
	}
	std::ifstream ifs("/proc/net/arp");
	std::string line;
	MacAddress Mac;
	while (std::getline(ifs, line)) {
		std::smatch m;
		if(std::regex_match(line, m, arp_rx)) {
			std::string ip = m.str(1);
			Mac.set(m.str(2));
			if (ip == inIpAddress && Mac.isValid() != 0) {
				ifs.close();
				return Mac;
			}
		}

	}
	ifs.close();
	if (retries > 0) {
		if (Debug == true) {
			syslog(LOG_DEBUG, "HostCache: Additional ARP lookup for %s", inIpAddress.c_str());
		}
		if (SendUdpPing (inIpAddress, 1900)) {
			usleep(5000);
			return MacLookup (inIpAddress, retries - 1);
		}
	}
	return Mac;
}

bool HostCache::SendUdpPing (const std::string DstIpAddress, const uint16_t DstPort) {
	//Structure for address of server
	struct sockaddr_in myaddr;
	int sock;

	//Construct the server sockaddr_ structure
	memset(&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family=AF_INET;
	myaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	myaddr.sin_port=htons(0);

	//Create the socket
	if((sock=socket(AF_INET, SOCK_DGRAM, 0))<0) {
		syslog(LOG_ERR, "HostCache: Failed to create socket");
		return false;
	}

	if(bind(sock,( struct sockaddr *) &myaddr, sizeof(myaddr))<0) {
		syslog(LOG_ERR, "HostCache: bind failed");
	    return false;
	}
	inet_pton(AF_INET,DstIpAddress.c_str(),&myaddr.sin_addr.s_addr);
	myaddr.sin_port=htons(1900);

	std::string s("12345678910:5/15:300.00:Visa");

	//send the message to server
	if(sendto(sock, s.c_str(), s.size(), 0, (struct sockaddr *)&myaddr, sizeof(myaddr))!=s.size()) {
		syslog(LOG_ERR, "HostCache: Mismatch in number of bytes sent");
		close (sock);
	    return false;
	}
	close (sock);
	return true;
}


bool HostCache::ExportDeviceProfileMatches(const std::string filename, bool detailed) {
	std::ofstream ofs(filename);
	json j;
	for (auto it : hC) {
		if (not isWhitelisted(*(it.second))) {
			it.second->ExportDeviceInfo(j, detailed);
		}
	}

	if (not ofs.is_open()) {
		syslog(LOG_WARNING, "HostCache: Couldn't open %s", filename.c_str());
		return false;
	}
	ofs << std::setw(4) << j << std::endl;
	ofs.close();
	return true;
}

/* TODO: Can't seem to get this to work
std::unique_ptr<std::future<uint32_t>> HostCache::test_RestApiCall_async(const std::string api, const json j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload) {
    std::future<uint32_t> f = std::async(RestApiCall, api, j, ClientApiCertFile, ClientApiKeyFile, doUpload, Debug);
    std::unique_ptr<std::future<uint32_t>> fptr = std::make_unique<std::future<uint32_t>>(f);

    return fptr;
}
*/

void HostCache::RestApiCall_async (std::vector<std::future<uint32_t>> &futures, const std::string api, const json j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload) {
     futures.emplace_back(std::async(RestApiCall, api, j, ClientApiCertFile, ClientApiKeyFile, doUpload, Debug));
    // async(launch::async, (RestApiCall(api, j, ClientApiCertFile, ClientApiKeyFile, doUpload)).detach();
}
uint32_t RestApiCall (const std::string api, const json &j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload, bool Debug) {
	std::string url = "https://api.noddos.io/" + api;

	std::string body = j.dump();
	char buf[strlen(body.c_str())+1];
	strcpy(buf, body.c_str());
	if (Debug) {
		syslog (LOG_DEBUG, "HostCache: Uploading %zu bytes of data to %s", strlen(buf), url.c_str());
		syslog (LOG_DEBUG, "HostCache: Upload using cert %s and key %s", ClientApiCertFile.c_str(), ClientApiKeyFile.c_str());
	}

	long response_code = 0;
	if (doUpload) {
		struct curl_slist *hlist = NULL;
		hlist = curl_slist_append(hlist, "Content-Type: application/json");
		if (hlist == NULL) {
			syslog(LOG_ERR, "HostCache: Couldn't create curl header for API call to %s", api.c_str());
		}

		std::string response_string;
		std::string header_string;
		double elapsed;
		auto curl = curl_easy_init();
		if (curl) {
			CURLcode ret;
			ret = curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_URL returned %d",ret);
			}
			// curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
			ret = curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_USE_SSL returned %u", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_SSLCERT, ClientApiCertFile.c_str());
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_SSLCERT returned %u", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_SSLKEY, ClientApiKeyFile.c_str());
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_SSLKEY returned %u", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "ECDHE-RSA-AES256-GCM-SHA384");
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_SSL_CIPHER_LIST returned %d", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_POSTFIELDS returned %d", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) strlen(buf));
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_POSTFIELDSIZE_LARGE returned %d", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_NOPROGRESS returned %d", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_USERAGENT, "noddos/1.0.0");
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_USERAGENT returned %u", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hlist);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_HTTPHEADER returned %d", ret);
			}
			// Curllib version on lede doesn't support HTTP 2.0
			// ret = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
			// if(ret) {
			// 	syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
			// }
			ret = curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_MAXREDIRS returned %d", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 0L);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_TCP_KEEPALIVE returned %d", ret);
			}
			// ret = curl_easy_setopt(curl, CURLOPT_TCP_FASTOPEN, 1L);
			// if(ret) {
			// 	syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
			// }
			ret = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long) 5000);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_TIMEOUT_MS returned %d", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlwriteFunction);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_WRITEDATA returned %d", ret);
			}
			ret = curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl setopt CURLOPT_HEADERDATA returned %d", ret);
			}
			if (false && Debug) {
				// TODO test on whether STDOUT is open for writing
				// 'always' disabled as this logs to STDOUT, which is normally closed
				ret = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			}


			ret = curl_easy_perform(curl);
			if(ret) {
				syslog (LOG_ERR, "HostCache: Curl easy_perform returned %d", ret);
			}
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
			curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
			curl_slist_free_all(hlist);
			curl_easy_cleanup(curl);
			curl = NULL;
			if (Debug) {
	    		syslog (LOG_DEBUG, "HostCache: Upload resulted in %lu status, data %s", response_code, response_string.c_str());
			}
		}
	}

    if (Debug == true) {
    	std::string file = api;
    	std::replace( file.begin(), file.end(), '/', '-');
    	std::time_t t = std::time(nullptr);
    	std::tm tm = *std::localtime(&t);
    	char buf[20];
    	strftime(buf,18,"%Y%m%d-%H%M%S",&tm);
    	std::string filename = "/tmp/" + file + "-" + buf;
    	std::ofstream ofs(filename);
    	if (not ofs.is_open()) {
    		syslog(LOG_WARNING, "HostCache: Couldn't open %s", filename.c_str());
    	}
    	ofs << std::setw(4) << j << std::endl;
    	ofs.close();
    }
    return (uint32_t) response_code;
}

void HostCache::UploadDeviceStats(std::vector<std::future<uint32_t>> &futures, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload) {
	uint32_t uploads = 0;
	json j;
	for (auto it : hC) {
		if ( (not isWhitelisted(*(it.second))) && not it.second->isMatched()) {
		json h;
			if (it.second->DeviceStats(h, 604800, false, false)) {
				uploads++;
				j.push_back(h);
			}
		}
	}
	if (uploads > 0) {
	    RestApiCall_async(futures, "v1/uploaddevices", j, ClientApiCertFile, ClientApiKeyFile, doUpload);
		syslog(LOG_INFO, "HostCache: Called v1/uploaddevices API with for %u devices", uploads);
	} else {
		syslog(LOG_INFO, "HostCache: Not calling v1/uploaddevices API as there is no data to report");
	}

}

void HostCache::UploadTrafficStats(std::vector<std::future<uint32_t>> &futures, const time_t interval, const bool ReportRfc1918, const std::string ClientCertFile, const std::string ClientApiKeyFile, bool doUpload) {
	uint32_t uploads = 0;
	json j;
	for (auto it : hC) {
		if ( (not isWhitelisted(*(it.second))) && it.second->isMatched()) {
			json h;
			if (it.second->TrafficStats(h, interval, ReportRfc1918, LocalIpAddresses, dCip, false)) {
				uploads++;
				j.push_back(h);
			}
		}
	}
	if (uploads > 0) {
	    RestApiCall_async(futures, "v1/uploadstats", j, ClientCertFile, ClientApiKeyFile, doUpload);
		syslog(LOG_INFO, "HostCache: Called v1/uploadstats API with for %u hosts", uploads);
	} else {
		syslog(LOG_INFO, "HostCache: Not calling v1/uploadstats API as there is no data to report");
	}
}

uint32_t HostCache::ImportDeviceProfileMatches(const std::string filename) {
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Importing Device Profile matches from %s", filename.c_str());
	}

	std::ifstream ifs(filename);
	if (not ifs.is_open()) {
		syslog(LOG_WARNING, "HostCache: Couldn't open %s", filename.c_str());
		return false;
	}
	json j;
	try {
	    ifs >> j;
	} catch (...) {
	    syslog (LOG_ERR, "HostCache: failed to parse Device Matches json data from %s", filename.c_str());
	}
	ifs.close();

	uint32_t matches = 0;
	for (auto it = j.begin(); it != j.end(); ++it) {
		if (ImportDeviceInfo(*it) == true) {
		   matches++;
	   }
	}
	syslog(LOG_INFO, "HostCache: DeviceMatches read: %u", matches);
	updateDeviceProfileMatchesDnsData();
	writeIptables();
	return matches;
}

void HostCache::updateDeviceProfileMatchesDnsData () {
    for (auto dp_it: dpMap) {
        // Now we need to update the ipset rules for Device Profiles with
        // hasAllowedEndpoints and one or more hosts matched to it
        dp_it.second->createorupdateIpsets();
        std::set<std::string> fqdns = dp_it.second->getDestinations();
        for (auto fqdn: fqdns) {
            fdpMap[fqdn].insert(dp_it.second);
            try {
                std::map<boost::asio::ip::address, time_t> p = dCip.lookupResourceRecord(fqdn);
                for (auto ip_it: p) {
                    dp_it.second->addDestination(ip_it.first, ip_it.second);
                }
            } catch (std::runtime_error &e) {
            }
            std::string cname = fqdn;
            try {
                while (1) {
                    cname = dCcname.lookupCname(cname);
                    try {
                        std::map<boost::asio::ip::address, time_t> p = dCip.lookupResourceRecord(cname);
                        for (auto ip_it: p) {
                            dp_it.second->addDestination(ip_it.first, ip_it.second);
                        }
                    } catch (std::runtime_error &e) {
                    }
                    // All traffic allowed to a FQDN is also allowed to its CNAME
                    // so if subsequently an A record is received for the CNAME,
                    // the ipsets for the device profiles must be updated
                    fdpMap[cname].insert(dp_it.second);
                }
            } catch (std::runtime_error &error) {}
        }
    }
}
bool HostCache::exportDnsCache (const std::string filename) {
    std::ofstream ofs(filename);
    if (not ofs.is_open()) {
        syslog(LOG_WARNING, "HostCache: Couldn't open %s", filename.c_str());
        return true;
    }
    json j;
    dCip.exportJson(j);
    dCcname.exportJson(j);

    ofs << std::setw(4) << j << std::endl;
    ofs.close();
    return false;
}

bool HostCache::importDnsCache (const std::string filename) {
    if (Debug == true) {
        syslog (LOG_DEBUG, "HostCache: Importing DnsCache from %s", filename.c_str());
    }
    std::ifstream ifs(filename);
    if (not ifs.is_open()) {
        syslog(LOG_WARNING, "HostCache: Couldn't open %s for reading", filename.c_str());
        return true;
    }
    json j;
    try {
        ifs >> j;
    } catch (...) {
        syslog (LOG_ERR, "HostCache: failed to parse Dns Cache json data from %s", filename.c_str());
    }

    try {
        size_t dnsRecords = dCip.importJson(j, fdpMap);
        if (Debug == true) {
            syslog(LOG_DEBUG, "HostCache: Read %zu cached DNS IP address records", dnsRecords);
        }
        dnsRecords = dCcname.importJson(j, fdpMap);
        if (Debug == true) {
            syslog(LOG_DEBUG, "HostCache: Read %zu cached DNS CNAME records", dnsRecords);
        }
    } catch (...) {
        syslog (LOG_ERR, "HostCache: Failure parsing DnsCache json data");
    }
    ifs.close();
    return false;
}

void HostCache::addorupdateDnsIpCache(const std::string inFqdn, const boost::asio::ip::address inIp, time_t inTtl) {
    dCip.addorupdateResourceRecord(inFqdn, inIp, fdpMap, inTtl);
}

void HostCache::addorupdateDnsCnameCache(const std::string inFqdn, const std::string inCname, time_t inTtl) {
    dCcname.addorupdateCname(inFqdn, inCname, fdpMap, inTtl);
}

bool HostCache::removeDeviceProfile(const std::string inUuid) {
    auto dp_it = dpMap.find(inUuid);
    if (dp_it == dpMap.end()) {
        throw std::runtime_error ("Device Profile " + inUuid + " not found");
    }
    std::set<std::string> dpFqdns = dp_it->second->getDestinations();
    for (auto Fqdn: dpFqdns) {
        std::string cname = Fqdn;
        try {
            while (1) {
                auto fdpmap_it = fdpMap.find(cname);
                if (fdpmap_it != fdpMap.end()) {
                    fdpmap_it->second.erase(dp_it->second);
                }
                cname = dCcname.lookupCname(cname);
            }
        } catch (std::runtime_error &error) {}
    }
    return false;
}

bool HostCache::ImportDeviceInfo (json &j) {
	std::string DeviceProfileUuid;
	if (j.find("DeviceProfileUuid") == j.end()) {
		if (Debug == true) {
			syslog(LOG_DEBUG, "HostCache: No DeviceProfileUuid set, ignoring this Object");
		}
		return false;
	}
	if (not j["DeviceProfileUuid"].is_string()) {
		syslog(LOG_ERR, "HostCache: DeviceProfileUuid is not a string, ignoring this Object");
		return false;
	}
	DeviceProfileUuid = j["DeviceProfileUuid"].get<std::string>();
	if (DeviceProfileUuid == "") {
		if (Debug == true) {
			syslog(LOG_DEBUG, "HostCache: DeviceProfileUuid is not set, ignoring this Object");
		}
		return false;
	}

	std::string MacAddressString;
	if (j.find("MacAddress") == j.end()) {
		syslog(LOG_ERR, "HostCache: No MacAddress set, ignoring this Object");
		return false;
	}
	if (not j["MacAddress"].is_string()) {
		syslog(LOG_ERR, "HostCache: MacAddress is not a string, ignoring this Object");
		return false;
	}
	MacAddressString = j["MacAddress"].get<std::string>();
	if (MacAddressString == "" ) {
		syslog(LOG_ERR, "HostCache: MacAddress set to empty value, ignoring this Object");
		return false;
    }

	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Importing Device Profile for UUID %s with MacAddress %s", DeviceProfileUuid.c_str(), MacAddressString.c_str());
	}
	std::string Ipv4Address = "";
	if (j.find("Ipv4Address") != j.end()) {
		if (j["Ipv4Address"].is_string()) {
			Ipv4Address = j["Ipv4Address"].get<std::string>();
		}
	}

	MacAddress Mac(MacAddressString);
	auto hit = hC.find(Mac.get());
	if (hit != hC.end()) {
		std::string uuid = hit->second->Uuid_get();
		if (uuid != DeviceProfileUuid) {
			syslog(LOG_WARNING, "HostCache: Conflicting Uuid for imported device with existing Host Cache");
			return false;
		}
	}
	if (not FindOrCreateHostByMac(Mac, DeviceProfileUuid, Ipv4Address)) {
		syslog(LOG_WARNING, "HostCache: Failed to create Host with MacAddress %s and uuid %s", MacAddressString.c_str(), DeviceProfileUuid.c_str());
		return false;
	}

	try {
	    auto it = dpMap.find(DeviceProfileUuid);
	    if (it == dpMap.end()) {
	        syslog (LOG_NOTICE, "Importing device with non-existing Device Profile UUID");
	        return false;
	    }
	    it->second->addHost(Mac);
	} catch (...) {
	    syslog (LOG_ERR, "HostCache: Ipset host:mac does not exist for device profile %s during import of DeviceMatches", DeviceProfileUuid.c_str());
	}
	return true;
}

// FIXME: need to remove IPsets for DeviceProfiles that no longer are specified in the DeviceProfiles file but only after iptables have been updated
// FIXME: need to recreate AllowedEndpoint IPsets for DeviceProfiles that have a new / higher version number

uint32_t HostCache::loadDeviceProfiles(const std::string filename) {
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Opening & reading %s", filename.c_str());
	}
	// Read the DeviceProfiles file
	std::ifstream ifs(filename);
	if (not ifs.is_open()) {
		syslog(LOG_WARNING, "HostCache: Couldn't open %s", filename.c_str());
		return 0;
	}
	json j;
    try {
        ifs >> j;
    } catch (...) {
        syslog (LOG_ERR, "HostCache: failed to parse Device Profiles json data from %s", filename.c_str());
    }

	// Track which DeviceProfileUuids were read from the file
	std::unordered_set<std::string> uuids;

	for (auto it = j.begin(); it != j.end(); ++it) {
	  std::string uuid = (*it)["DeviceProfileUuid"].get<std::string>();
	  dpMap[uuid] = std::make_shared<DeviceProfile>(*it, Debug);
	  uuids.insert (uuid);
	}
	ifs.close();

	// Delete any Device Profile already in memory that was not
	// in the file we just read and parsed
	for (auto it = dpMap.begin(); it != dpMap.end();) {
		if (uuids.find(it->first) == uuids.end()) {
			if (Debug == true) {
				syslog(LOG_DEBUG, "HostCache: Profile no longer in DeviceProfiles file: %s", it->first.c_str());
			}
			it = dpMap.erase(it);
		} else {
		    it++;
		}
	}
	auto s = uuids.size();
	if (Debug == true) {
		syslog(LOG_DEBUG, "HostCache: Profiles imported %zu", s);
	}
	return s;
}

uint32_t HostCache::Whitelists_set (const std::unordered_set<std::string>& inIpv4Addresses,
		const std::unordered_set<std::string>& inIpv6Addresses,
		const std::unordered_set<std::string>& inMacAddresses) {
    if (Debug == true) {
        syslog (LOG_DEBUG, "HostCache: set whitelists");
    }
    WhitelistedNodes.clear();
	WhitelistedNodes.insert(inIpv4Addresses.begin(), inIpv4Addresses.end());
	WhitelistedNodes.insert(inIpv6Addresses.begin(), inIpv6Addresses.end());
	WhitelistedNodes.insert(inMacAddresses.begin(), inMacAddresses.end());
	return WhitelistedNodes.size();
}

void HostCache::writeIptables()  {
    if (FirewallRulesFile == "") {
        if (Debug == true) {
            syslog(LOG_DEBUG, "Iptables: Not writing firewall rules as feature is disabled");
        }
        return;
    }
    if (Debug == true) {
        syslog(LOG_DEBUG, "Iptables: Writing firewall rules to %s", FirewallRulesFile.c_str());
    }
    std::ofstream outputfs(FirewallRulesFile);
    std::vector<std::string> ifaces = ifMap->getLanInterfaces();
    std::string action = "LOG";
    if (FirewallBlockTraffic == true) {
        action = "DROP";
    }

    outputfs << "*filter" << std::endl;

    for (auto dp_it: dpMap) {
        if (dp_it.second->hasAllowedEndpoints() && dp_it.second->hasHosts()) {
            std::string srcipset = getIpsetName(dp_it.second->getUuid(),true,false);
            std::string ipv46flag;
            std::string dstipset;
            for ( auto iface: ifaces) {
                // IPv4 permit rule
                dstipset = getIpsetName(dp_it.second->getUuid(), false, true);
                ipv46flag = "--ipv4";
                outputfs << "-A NODDOS -i " + iface + " " + ipv46flag +
                        " -m set --match-set " + srcipset + " src " +
                        "-m set --match-set " +  dstipset + " dst -j ACCEPT" << std::endl;

                // IPv6 permit rule
                dstipset = getIpsetName(dp_it.second->getUuid(), false, false);
                ipv46flag = "--ipv6";
                outputfs << "-A NODDOS -i " + iface + " " + ipv46flag +
                        " -m set --match-set " + srcipset + " src " +
                        "-m set --match-set " +  dstipset + " dst -j ACCEPT" << std::endl;

                // Block all other traffic from the MAC addresses mapped to the Device Profile
                outputfs << "-A NODDOS -i " + iface +
                        " -m set --match-set " + srcipset + " src -j " + action << std::endl;
            }
        }

    }
    for (auto iface: ifaces) {
        outputfs << "-A NODDOS -j RETURN" << std::endl;
    }
    outputfs << "COMMIT" << std::endl;
    outputfs.close();

    std::string command4 = "iptables-restore -T filter -n " + FirewallRulesFile;
    std::string command6 = "ip6tables-restore -T filter -n " + FirewallRulesFile;
    if (Debug == true) {
        syslog (LOG_DEBUG, "HostCache: updating ip(6)tables");
    }
    int rc1 = system("iptables --flush NODDOS");
    int rc2 = system(command4.c_str());
    int rc3 = system("ip6tables --flush NODDOS");
    int rc4 = system(command6.c_str());
    if (rc1 == -1 || rc2 == -1 || rc3 == -1 || rc4 == 1) {
        syslog(LOG_ERR, "HostCache: Could not create child process for 'system' call");
    }
    if (rc1 == 127|| rc2 == 127 || rc3 == 127 || rc4 == 127) {
        syslog(LOG_ERR, "HostCache: Shell could not be executed in child process for 'system' call");
    }
    if (rc1 != 0) {
        syslog(LOG_ERR, "HostCache: iptables existing with code %d", rc1);
    }
    if (rc2 != 0) {
        syslog(LOG_ERR, "HostCache: iptables-restore existing with code %d", rc2);
    }
    if (rc3 != 0) {
        syslog(LOG_ERR, "HostCache: ip6tables existing with code %d", rc3);
    }
    if (rc4 != 0) {
        syslog(LOG_ERR, "HostCache: ip6tables-restore existing with code %d", rc4);
    }
}

