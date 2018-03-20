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

#include <cstdio>
#include <iomanip>
#include <cstring>
#include <cstdlib>

#include "json.hpp"
using nlohmann::json;

#include <curl/curl.h>

#include "HostCache.h"

uint32_t HostCache::Prune (bool Force) {
    DLOG_IF(INFO, Debug) << "starting prune";
	uint32_t prunedhosts = 0;

	for (auto it = hC.begin(); it != hC.end();) {
        std::string mac = it->second->getMacAddress();
        std::string uuid = it->second->getUuid();
		it->second->Prune(Force);
		if (it->second->isExpired()) {
			if(uuid != "") {
			    auto it = dpMap.find(uuid);
			    if (it != dpMap.end()) {
			        it->second->removeHost(mac);
			    }
			}
			it = hC.erase (it);
		    prunedhosts++;
		} else {
		    it++;
		}
	}
	DLOG_IF(INFO, Debug) << "Pruned " << prunedhosts << " hosts";
	uint32_t count = pruneDnsQueryCache(Force);
	DLOG_IF(INFO, Debug) << "Pruned " << count << " DNS queries";
	count = pruneDnsIpCache(Force);
	DLOG_IF(INFO, Debug) << "Pruned " << count << " DNS IP cache entries";
    count = pruneDnsCnameCache(Force);
    DLOG_IF(INFO, Debug) << "Pruned " << count << " DNS CNAME cache entries";
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

bool HostCache::matchByMac(const MacAddress &inMacAddress) {
    DLOG_IF(INFO, Debug) << "Starting match for MAC address " << inMacAddress;
	if (hC.find(inMacAddress.get()) != hC.end()) {
		auto &h = *(hC[inMacAddress.get()]);
		return h.Match(dpMap);
	}
	return false;
}

bool HostCache::matchByIpAddress(const std::string inIpAddress) {
	if (Ip2MacMap.find(inIpAddress) != Ip2MacMap.end()) {
		MacAddress m(Ip2MacMap[inIpAddress]);
		return matchByMac(m);
	}
	return false;
}

std::shared_ptr<Host> HostCache::findHostByIp (const std::string inIp) {
	auto it = Ip2MacMap.find(inIp);
	if ( it == Ip2MacMap.end()) {
		return nullptr;
	}
	MacAddress mac(it->second);
	return findHostByMac (mac);
}

std::shared_ptr<Host> HostCache::findOrCreateHostByIp (const std::string inIp,
        const std::string Uuid) {
    DLOG_IF(INFO, Debug) << "Find or create host for IP " << inIp;

	if (inIp == "0.0.0.0" || inIp == "") {
	    LOG(INFO) << "finding host by IP address " << inIp << " is not possible";
	}
	if (inIp == "" || WhitelistedNodes.find(inIp) != WhitelistedNodes.end()) {
		return nullptr;
    }
	MacAddress Mac;
	auto it = Ip2MacMap.find(inIp);
	if ( it == Ip2MacMap.end()) {
		Mac = lookupMac(inIp);
		if (Mac.isValid() == false) {
		    DLOG_IF(INFO, Debug) << "Did not find ARP entry for " << inIp;
			return nullptr;
		}
		Ip2MacMap[inIp] = Mac.get();
	} else {
		Mac.set(it->second);
	}
	return findOrCreateHostByMac (Mac, Uuid, inIp);
}

std::shared_ptr<Host> HostCache::findHostByMac (const MacAddress &inMac) {
	if (inMac.isValid() == false) {
		LOG(WARNING) << "Mac Address with invalid value provided";
		return nullptr;
	}
	if (hC.find(inMac.get()) == hC.end()) {
		return nullptr;
	}
	return hC[inMac.get()];
}

std::shared_ptr<Host> HostCache::findOrCreateHostByMac (const MacAddress inMac,
        const std::string Uuid, const std::string inIp) {
    DLOG_IF(INFO, Debug) << "Find or create host for MAC " << inMac;
	if (WhitelistedNodes.find(inMac.str()) != WhitelistedNodes.end()) {
		return nullptr;
    }
	if (inMac.isValid() == false) {
		LOG(WARNING) << "Invalid Mac Address provided: " << inMac;
		return nullptr;
	}
	if (hC.find(inMac.get()) == hC.end()) {
	    DLOG_IF(INFO, Debug) << "Adding new Host with MAC address " << inMac
	            << " for IP " << inIp;
		auto h = std::make_shared<Host>(inMac.str(), Uuid, MinDnsTtl, Debug);
		h->setIpAddress (inIp);
		hC[inMac.get()] = h;
		return h;
	}
	DLOG_IF(INFO, Debug) << "Found MAC address " << inMac << " for IP " << inIp;
	std::shared_ptr<Host> h = hC[inMac.get()];
	if (inIp != "" && inIp != "0.0.0.0") {
	     if (h->getIpv4Address() == "0.0.0.0") {
	         h->setIpAddress(inIp);
	     }
	}
	return hC[inMac.get()];
}

bool HostCache::addByMac (const MacAddress inMacAddress, const std::string inIpAddress) {
    DLOG_IF(INFO, Debug) << "Creating new host for MAC " << inMacAddress
            << " with IP " << inIpAddress;
	if (hC.find(inMacAddress.get()) != hC.end()) {
		return false;
    }
	auto h = std::make_shared<Host>(inMacAddress, MinDnsTtl, Debug);
	h->setIpAddress (inIpAddress);
	hC[inMacAddress.get()] = h;
	Ip2MacMap[inIpAddress] = inMacAddress.get();
	return true;
}

bool HostCache::addFlow (const std::string srcip, const uint16_t srcport,
        const std::string dstip, const uint16_t dstport, const uint8_t protocol,
        const uint32_t expiration) {
    DLOG_IF(INFO, Debug) << "Adding flow for host with IP " << srcip;
	// DHCP requests are sent from 0.0.0.0. As we can't associate this flow with
    // a MAC address from the FlowTrack data, we ignore the flow
	if (srcip == "0.0.0.0") {
		return false;
	}
	if (WhitelistedNodes.find(srcip) != WhitelistedNodes.end()) {
		return false;
	}

	try {
	    std::shared_ptr<Host> h = findOrCreateHostByIp(srcip);
	    if (h != nullptr) {
	        h->setFlowEntry(srcport, dstip, dstport, protocol, MinFlowTtl);
	        return true;
	    }
	} catch (...) {}
	return false;
}


bool HostCache::addDnsQueryIp (const std::string clientip, const std::string fqdn,
        const std::string ip, const uint32_t inTtl) {
    DLOG_IF(INFO, Debug) << "Adding dns query for " << fqdn
            << " for host with IP " <<  clientip;
	if (WhitelistedNodes.find(clientip) != WhitelistedNodes.end()) {
		return false;
	}

	try {
	    std::shared_ptr<Host> h = findOrCreateHostByIp(clientip);
	    if (h != nullptr) {
	        h->addorupdateDnsQueryList(fqdn, inTtl);
	        return true;
	    }
	} catch (...) {}
	return false;
}


bool HostCache::addDhcpRequest (const std::string IpAddress, const MacAddress inMac,
        const std::string Hostname, const std::string DhcpVendor) {
    DLOG_IF(INFO, Debug) << "Adding DHCP request for host with MAC " <<
            inMac << " & IP "  << IpAddress;
	if ((IpAddress == "" || IpAddress == "0.0.0.0") && inMac.isValid() == false) {
		LOG(WARNING) << "No IpAdddress or Macaddress in DHCP request";
		return false;

	}
	if (isWhitelisted(IpAddress) || isWhitelisted(inMac.str())) {
		return false;
    }

	std::shared_ptr<Host> h;
	if (inMac.isValid() == true) {
		try {
		    h = findOrCreateHostByMac(inMac, "", IpAddress);
		} catch (...) {
		    return false;
		}
	} else {
	    try {
	        h = findOrCreateHostByIp(IpAddress);
	    } catch (...) {
	        return false;
        }
	}

	if (h != nullptr) {
		h->setDhcp(IpAddress, inMac.str(), Hostname, DhcpVendor);
		return true;
	}
	return false;

}

bool HostCache::addSsdpInfo (const std::shared_ptr<SsdpHost> sHost) {
    DLOG_IF(INFO, Debug) << "Adding SSDP info for host with IP " << sHost->IpAddress;
	if (sHost->IpAddress == "") {
		LOG(WARNING) << "AddSsdpInfo: no IP address provided";
		return false;
	}
	if (WhitelistedNodes.find(sHost->IpAddress) != WhitelistedNodes.end()) {
		return false;
	}

	try {
	    std::shared_ptr<Host> h = findOrCreateHostByIp(sHost->IpAddress);
	    if (h != nullptr) {
	        h->setSsdpInfo(sHost);
	        return true;
	    }
	} catch (...) {}
	return false;
}

bool HostCache::addWsDiscoveryInfo (const std::shared_ptr<WsDiscoveryHost> inwsdHost) {
    DLOG_IF(INFO, Debug) << "Adding WsDiscovery info for host with IP " << inwsdHost->IpAddress;
    if (inwsdHost->IpAddress == "") {
        LOG(WARNING) << "AddWsDiscoveryInfo: no IP address provided";
        return false;
    }
    if (WhitelistedNodes.find(inwsdHost->IpAddress) != WhitelistedNodes.end()) {
        return false;
    }

    try {
        std::shared_ptr<Host> h = findOrCreateHostByIp(inwsdHost->IpAddress);
        if (h != nullptr) {
            h->setWsDiscoveryInfo(inwsdHost);
            return true;
        }
    } catch (...) {}
    return false;

}

bool HostCache::addMdnsInfo (const std::shared_ptr<MdnsHost> inmdnsHost) {
    DLOG_IF(INFO, Debug) << "Adding mDNS info for host with IP " << inmdnsHost->IpAddress;
    if (inmdnsHost->IpAddress == "") {
        LOG(WARNING) << "AddMdnsInfo: no IP address provided";
        return false;
    }
    if (WhitelistedNodes.find(inmdnsHost->IpAddress) != WhitelistedNodes.end()) {
        return false;
    }

    try {
        std::shared_ptr<Host> h = findOrCreateHostByIp(inmdnsHost->IpAddress);
        if (h != nullptr) {
            h->setMdnsInfo(inmdnsHost);
            return true;
        }
    } catch (...) {}
    return false;

}


// These functions are for DnsQueryCache
void HostCache::addorupdateDnsQueryCache (uint16_t id) {
	time_t Expiration = time(nullptr) + 60;
	DLOG_IF(INFO, Debug) <<"HostCache: setting DnsQueryCache for " << id << " to " << Expiration;
	DnsQueryCache[id] = time(nullptr) + 60;
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
		if (Force || now > i->second) {
		    DLOG_IF(INFO, Debug) <<"HostCache: Deleting " << i->first << " from DnsQueryCache as " <<
		            now << " is later than " << i->second;
			i = DnsQueryCache.erase(i);
			deletecount++;
		} else {
			i++;
		}
	}
	return deletecount;
}

MacAddress HostCache::lookupMac (const std::string inIpAddress) {
    MacAddress Mac("00:00:00:00:00:00");
    if (LocalIpAddresses.find(inIpAddress) != LocalIpAddresses.end()) {
        DLOG_IF(INFO, Debug) <<"HostCache: Skipping MacLookup of local IP address " << inIpAddress;
        return Mac;
    }
    DLOG_IF(INFO, Debug) <<"HostCache: MacLookup of " << inIpAddress;
    for (auto lanInterface: ifMap->getLanInterfaces()) {
        Mac = lookupMac(inIpAddress, lanInterface, true);
        if (Mac.isValid() == true) {
            DLOG_IF(INFO, Debug) <<"HostCache: Found MAC entry " << Mac << " on interface " << lanInterface;
            return Mac;
        }
        DLOG_IF(INFO, Debug) <<"HostCache: MAC entry not found on interface " << lanInterface;
    }
    DLOG_IF(INFO, Debug) <<"HostCache: MAC entry not found on lan interfaces";
    return Mac;
}

MacAddress HostCache::lookupMac (const std::string inIpAddress, const std::string inInterface, bool Retry) {
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
        LOG(ERROR) << "inet_pton failed for " << inIpAddress;
        return Mac;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *) &areq.arp_ha;
    sin->sin_family = ARPHRD_ETHER;
    strncpy(areq.arp_dev, inInterface.c_str(), 15);

    /* Get an internet domain socket. */
    int s;
    if ((s = socket(domain, SOCK_DGRAM, 0)) == -1) {
        LOG(ERROR) << "Can't open socket for ARP table lookup for IP " << inIpAddress
                << ", domain " << domain << " on interface " << inInterface;
        return Mac;
    }

    if (-1 == ioctl(s, SIOCGARP , (caddr_t) &areq)) {
        close (s);
        if (Retry == true) {
            sendUdpPing (inIpAddress, 1900);
            lookupMac (inIpAddress, inInterface, false);
        }
        DLOG_IF(INFO, Debug) <<"HostCache: ARP lookup failure for " << inIpAddress << " on interface " << inInterface;
        return Mac;
    }
    close (s);
    char mA[18];
    unsigned char *ptr = (unsigned char *) areq.arp_ha.sa_data;
    sprintf(mA, "%02X:%02X:%02X:%02X:%02X:%02X",
            (ptr[0] & 0xff), (ptr[1] & 0xff), (ptr[2] & 0xff),
            (ptr[3] & 0xff), (ptr[4] & 0xff), (ptr[5] & 0xff));
    Mac.set(mA);
    return Mac;
}

bool HostCache::sendUdpPing (const std::string DstIpAddress, const uint16_t DstPort) {
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
           PLOG(ERROR) << "Failed to create socket";
           return false;
       }

       if(bind(sock,( struct sockaddr *) &myaddr, sizeof(myaddr))<0) {
           PLOG(ERROR) << "bind failed";
           close (sock);
           return false;
       }
       inet_pton(AF_INET,DstIpAddress.c_str(),&myaddr.sin_addr.s_addr);
       myaddr.sin_port=htons(DstPort);

       std::string s("12345678910:5/15:300.00:Visa");

       //send the message to server
       if(sendto(sock, s.c_str(), s.size(), 0, (struct sockaddr *)&myaddr, sizeof(myaddr))!=s.size()) {
           PLOG(ERROR) << "Mismatch in number of bytes sent";
           close (sock);
           return false;
       }
       usleep (1500);
       close (sock);
       return true;
}

// TODO: We should consolidate this in the IfMap data structure
uint32_t HostCache::getInterfaceIpAddresses() {
    DLOG_IF(INFO, Debug) <<"HostCache: discovering IP addresses of network interfaces";
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        PLOG(ERROR) << "Can't loop through local interfaces: getifaddrs";
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
        DLOG_IF(INFO, Debug) << "Interface " << ifa->ifa_name << " " <<
                ((family == AF_PACKET) ? "AF_PACKET" :
                        ((family == AF_INET) ? "AF_INET" :
                                ((family == AF_INET6) ? "AF_INET6" : "???"))) << "(" << family << ")";
        LocalInterfaces.insert(ifa->ifa_name);

        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                PLOG(ERROR) << "getnameinfo() failed: " << gai_strerror(s);
                freeifaddrs(ifaddr);
                return 0;
            }

            DLOG_IF(INFO, Debug) <<"HostCache: Interface " << ifa->ifa_name << " with IP address: " << host;
            LocalIpAddresses.insert(host);
        }
    }

    freeifaddrs(ifaddr);
    return 0;
}




bool HostCache::exportDeviceProfileMatches(const std::string filename, bool detailed) {
	std::ofstream ofs(filename);
	json j;
	for (auto it : hC) {
		if (not isWhitelisted(*(it.second))) {
			it.second->exportDeviceInfo(j, detailed);
		}
	}

	if (not ofs.is_open()) {
		PLOG(WARNING) << "Couldn't open " << filename;
		return false;
	}
	ofs << std::setw(4) << j << std::endl;
	ofs.close();
	return true;
}

void HostCache::callRestApi_async (std::vector<std::future<uint32_t>> &futures, const std::string api, const json j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload) {
     futures.emplace_back(std::async(callRestApi, api, j, ClientApiCertFile, ClientApiKeyFile, doUpload, Debug));
}

uint32_t callRestApi (const std::string api, const json &j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload, bool Debug) {
	std::string url = "https://api.noddos.io/" + api;

    std::string body = j.dump();
    char buf[strlen(body.c_str())+1];
    strcpy(buf, body.c_str());
    DLOG_IF(INFO, Debug) << "Uploading " << strlen(buf) << " bytes of data to " << url;
    DLOG_IF(INFO, Debug) << "Upload using cert " << ClientApiCertFile << " and key " << ClientApiKeyFile;


	long response_code = 0;
	if (doUpload) {
	    struct curl_slist *hlist = NULL;
	    hlist = curl_slist_append(hlist, "Content-Type: application/json");
	    if (hlist == NULL) {
	        LOG(ERROR) << "Couldn't create curl header for API call to " << api;
	    }

	    std::string response_string;
	    std::string header_string;
	    long response_code;
	    double elapsed;
	    auto curl = curl_easy_init();
	    if (curl) {
	        CURLcode ret;
	        ret = curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_URL returned " << ret;
	        // curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
	        ret = curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_USE_SSL returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_SSLCERT, ClientApiCertFile.c_str());
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_SSLCERT returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_SSLKEY, ClientApiKeyFile.c_str());
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_SSLKEY returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "ECDHE-RSA-AES256-GCM-SHA384");
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_SSL_CIPHER_LIST returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_POSTFIELDS returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) strlen(buf));
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_POSTFIELDSIZE_LARGE returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_NOPROGRESS returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_USERAGENT, "noddos/1.0.0");
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_USERAGENT returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hlist);
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_HTTPHEADER returned " << ret;
	        // Curllib version on lede doesn't support HTTP 2.0
	        // ret = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
	        // LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_WRITEFUNCTION returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_MAXREDIRS returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 0L);
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_TCP_KEEPALIVE returned " << ret;
	        // ret = curl_easy_setopt(curl, CURLOPT_TCP_FASTOPEN, 1L);
	        // LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_WRITEFUNCTION returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long) 5000);
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_TIMEOUT_MS returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlwriteFunction);
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_WRITEFUNCTION returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_WRITEDATA returned " << ret;
	        ret = curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
	        LOG_IF(ERROR, ret) << "Curl setopt CURLOPT_HEADERDATA returned " << ret;

	        ret = curl_easy_perform(curl);
	        LOG_IF(ERROR, ret) << "Curl easy_perform returned " << ret;
	        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
	        curl_slist_free_all(hlist);
	        curl_easy_cleanup(curl);
	        curl = NULL;
	        DLOG_IF(INFO, Debug) << "Upload resulted in " << response_code << " status, data " << response_string;
	    }

	    if (Debug) {
	        std::string file = api;
	        std::replace( file.begin(), file.end(), '/', '-');
	        std::time_t t = std::time(nullptr);
	        std::tm tm = *std::localtime(&t);
	        char buf[20];
	        strftime(buf,18,"%Y%m%d-%H%M%S",&tm);
	        std::string filename = "/tmp/" + file + "-" + buf;
	        std::ofstream ofs(filename);
	        if (not ofs.is_open()) {
	            DLOG(WARNING) << "Couldn't open" << filename;
	        }
	        ofs << std::setw(4) << j << std::endl;
	        ofs.close();
	    }
	    return (uint32_t) response_code;
	}
}

void HostCache::uploadDeviceStats(std::vector<std::future<uint32_t>> &futures, const std::string ClientApiCertFile, const std::string ClientApiKeyFile, bool doUpload) {
	uint32_t uploads = 0;
	json j;
	for (auto it : hC) {
		if ( (not isWhitelisted(*(it.second))) && not it.second->isMatched()) {
		json h;
			if (it.second->exportDeviceStats(h, 604800, false, true)) {
				uploads++;
				j.push_back(h);
			}
		}
	}
	if (uploads > 0) {
	    // TOD: Might be a race condition in RestApiCall as they both use global Curl instance
	    callRestApi_async(futures, "v1/uploaddevices", j, ClientApiCertFile, ClientApiKeyFile, doUpload);
	    // RestApiCall("v1/uploaddevices", j, ClientApiCertFile, ClientApiKeyFile, doUpload);
	    LOG(INFO) << "Called v1/uploaddevices API with for " << uploads << " devices";
	} else {
		LOG(INFO) << "Not calling v1/uploaddevices API as there is no data to report";
	}

}

void HostCache::uploadTrafficStats(std::vector<std::future<uint32_t>> &futures, const time_t interval, const bool ReportRfc1918, const std::string ClientCertFile, const std::string ClientApiKeyFile, bool doUpload) {
	uint32_t uploads = 0;
	json j;
	for (auto it : hC) {
		if ( (not isWhitelisted(*(it.second))) && it.second->isMatched()) {
			json h;
			if (it.second->exportTrafficStats(h, interval, ReportRfc1918, LocalIpAddresses, dCipv4, dCipv6, false)) {
				uploads++;
				j.push_back(h);
			}
		}
	}
	if (uploads > 0) {
        // TODO: Might be a race condition in RestApiCall as they both use global Curl instance
	    callRestApi_async(futures, "v1/uploadstats", j, ClientCertFile, ClientApiKeyFile, doUpload);
	    // RestApiCall("v1/uploadstats", j, ClientCertFile, ClientApiKeyFile, doUpload);
		LOG(INFO) << "Called v1/uploadstats API with for " << uploads << " hosts";
	} else {
		LOG(INFO) << "Not calling v1/uploadstats API as there is no data to report";
	}
}

uint32_t HostCache::importDeviceProfileMatches(const std::string filename) {
    DLOG_IF(INFO, Debug) << "Importing Device Profile matches from " << filename;

	std::ifstream ifs(filename);
	if (not ifs.is_open()) {
		PLOG(WARNING) << "Couldn't open " << filename;
		return false;
	}
	json j;
	try {
	    ifs >> j;
	} catch (...) {
	    LOG(ERROR) << "failed to parse Device Matches json data from " << filename;
	}
	ifs.close();

	uint32_t matches = 0;
	for (auto it = j.begin(); it != j.end(); ++it) {
		if (importDeviceInfo(*it) == true) {
		   matches++;
	   }
	}
	DLOG_IF(INFO, Debug) << "DeviceMatches read: " << matches;
	updateDeviceProfileMatchesDnsData();
	writeIptables();
	return matches;
}

void HostCache::updateDeviceProfileMatchesDnsData () {
    DLOG_IF(INFO, Debug) <<"HostCache: starting updateDeviceProfileMatchesDnsData";
    for (auto dp_it: dpMap) {
        // Now we need to update the ipset rules for Device Profiles with
        // hasAllowedEndpoints and one or more hosts matched to it
        DLOG_IF(INFO, Debug) <<"HostCache: updateDeviceProfileMatchesDnsData processing DP " << dp_it.second->getDeviceDescription();
        dp_it.second->createorupdateIpsets();
        std::set<std::string> fqdns = dp_it.second->getDestinations();
        for (auto fqdn: fqdns) {
            fdpMap[fqdn].insert(dp_it.second);
            DLOG_IF(INFO, Debug) <<"HostCache: updateDeviceProfileMatchesDnsData adding FQDN " << fqdn;
            try {
                std::map<Tins::IPv4Address, time_t> p = dCipv4.lookupResourceRecord(fqdn);
                for (auto ip_it: p) {
                    dp_it.second->addDestination(ip_it.first, ip_it.second);
                }
            } catch (std::runtime_error &e) {
                // No A records for FQDN
            }
            try {
                std::map<Tins::IPv6Address, time_t> p = dCipv6.lookupResourceRecord(fqdn);
                for (auto ip_it: p) {
                    dp_it.second->addDestination(ip_it.first, ip_it.second);
                }
            } catch (std::runtime_error &e) {
                // No AAAA records for FQDN
            }
            std::string cname = "";
            while (fqdn != cname) {
                std::set<std::string> cnames;
                try {
                    cnames = dCcname.getCnames(fqdn);
                } catch (std::runtime_error &e) {
                    break;
                }
                DLOG_IF(INFO, Debug) <<"HostCache: updateDeviceProfileMatchesDnsData adding CNAME " << cname <<
                        " for FQDN " << fqdn;
                try {
                    std::map<Tins::IPv4Address, time_t> p = dCipv4.lookupResourceRecord(cname.c_str());
                    for (auto ip_it: p) {
                        dp_it.second->addDestination(ip_it.first, ip_it.second);
                    }
                } catch (std::runtime_error &e) {
                    // No A records for FQDN
                }
                try {
                    std::map<Tins::IPv6Address, time_t> p = dCipv6.lookupResourceRecord(cname.c_str());
                    for (auto ip_it: p) {
                        dp_it.second->addDestination(ip_it.first, ip_it.second);
                    }
                } catch (std::runtime_error &e) {
                    // No A records for FQDN
                }
                // All traffic allowed to a FQDN is also allowed to its CNAME
                // so if subsequently an A record is received for the CNAME,
                // the ipsets for the device profiles must be updated
                fdpMap[cname].insert(dp_it.second);
                DLOG_IF(INFO, Debug) <<"HostCache: updateDeviceProfileMatchesDnsData Finishing with FQDN " << fqdn <<
                        " and CNAME " << cname;
                // On nex iteration, do a CNAME lookup for the cname we found in this iteration
                fqdn = cname;
            }
        }
    }
}
bool HostCache::exportDnsCache (const std::string filename) {
    std::ofstream ofs(filename);
    if (not ofs.is_open()) {
        LOG(WARNING) << "Couldn't open " << filename;
        return true;
    }
    json j;
    dCipv4.exportJson(j);
    dCipv6.exportJson(j);
    dCcname.exportJson(j);

    ofs << std::setw(4) << j << std::endl;
    ofs.close();
    return false;
}

bool HostCache::importDnsCache (const std::string filename) {
    DLOG_IF(INFO, Debug) << "Importing DnsCache from " << filename;
    std::ifstream ifs(filename);
    if (not ifs.is_open()) {
        PLOG(WARNING) << "Couldn't open %s for reading" << filename;
        return true;
    }
    json j;
    try {
        ifs >> j;
    } catch (...) {
        PLOG(ERROR) << "failed to parse Dns Cache json data from " << filename;
    }

    try {
        size_t dnsRecords = dCipv4.importJson(j, fdpMap);
        dnsRecords += dCipv6.importJson(j, fdpMap);
        DLOG_IF(INFO, Debug) << "Read " << dnsRecords << " cached DNS IP address records";
        dnsRecords = dCcname.importJson(j, fdpMap);
        DLOG_IF(INFO, Debug) << "Read " << dnsRecords << " cached DNS CNAME records";
    } catch (...) {
        LOG(ERROR) << "Failure parsing DnsCache json data";
    }
    ifs.close();
    return false;
}

void HostCache::addorupdateDnsIpCache(const std::string inFqdn, const Tins::IPv4Address inIp, time_t inTtl) {
    dCipv4.addorupdateResourceRecord(inFqdn, inIp, fdpMap, inTtl);
}

void HostCache::addorupdateDnsIpCache(const std::string inFqdn, const Tins::IPv6Address inIp, time_t inTtl) {
    dCipv6.addorupdateResourceRecord(inFqdn, inIp, fdpMap, inTtl);
}


void HostCache::addorupdateDnsCnameCache(const std::string inFqdn, const std::string inCname, time_t inTtl) {
    dCcname.addorupdateCname(inFqdn, inCname, fdpMap, inTtl);
}

uint32_t HostCache::pruneDnsIpCache(bool Force) {
    std::set<std::string> PrunedFqdns = dCipv4.pruneResourceRecords(Force);
    std::set<std::string> PrunedIpv6Fqdns = dCipv6.pruneResourceRecords(Force);
    PrunedFqdns.insert(PrunedIpv6Fqdns.begin(), PrunedIpv6Fqdns.end());
    for(auto Fqdn: PrunedFqdns) {
        fdpMap.erase(Fqdn);
    }
    return PrunedFqdns.size();
}

uint32_t HostCache::pruneDnsCnameCache(bool Force) {
    std::set<std::string> PrunedCnames = dCcname.pruneCnames(Force);
    for(auto Cname: PrunedCnames) {
        fdpMap.erase(Cname);
    }
    return PrunedCnames.size();
}

bool HostCache::removeDeviceProfile(const std::string inUuid) {
    auto dp_it = dpMap.find(inUuid);
    if (dp_it == dpMap.end()) {
        throw std::runtime_error ("Device Profile " + inUuid + " not found");
    }

    auto dp = dp_it->second;
    std::set<std::string> dpFqdns = dp->getDestinations();
    for (auto Fqdn: dpFqdns) {
        std::set<std::string> fqdns;
        fqdns.insert(Fqdn);
        std::set<std::string> cnames = dCcname.getCnames(Fqdn);
        fqdns.insert(cnames.begin(),cnames.end());
        for (auto fqdn: fqdns) {
            auto fdpmap_it = fdpMap.find(fqdn);
            if (fdpmap_it != fdpMap.end()) {
                fdpmap_it->second.erase(dp);
            }
        }
    }
    return false;
}

bool HostCache::importDeviceInfo (json &j) {
	std::string DeviceProfileUuid;
	if (j.find("DeviceProfileUuid") == j.end()) {
	    LOG(WARNING) << "No DeviceProfileUuid set, ignoring this Object";
		return false;
	}
	if (not j["DeviceProfileUuid"].is_string()) {
		LOG(ERROR) << "DeviceProfileUuid is not a string, ignoring this Object";
		return false;
	}
	DeviceProfileUuid = j["DeviceProfileUuid"];
	if (DeviceProfileUuid == "") {
	    LOG(ERROR) << "DeviceProfileUuid is not set, ignoring this Object";
		return false;
	}

	std::string MacAddressString;
	if (j.find("MacAddress") == j.end()) {
		LOG(ERROR) << "No MacAddress set, ignoring this Object";
		return false;
	}
	if (not j["MacAddress"].is_string()) {
		LOG(ERROR) << "MacAddress is not a string, ignoring this Object";
		return false;
	}
	MacAddressString = j["MacAddress"];
	if (MacAddressString == "" ) {
		LOG(ERROR) << "MacAddress set to empty value, ignoring this Object";
		return false;
    }

	DLOG_IF(INFO, Debug) << "Importing Device Profile for UUID " << DeviceProfileUuid <<
	        " with MacAddress " << MacAddressString;
	std::string Ipv4Address = "";
	if (j.find("Ipv4Address") != j.end()) {
		if (j["Ipv4Address"].is_string()) {
			Ipv4Address = j["Ipv4Address"];
		}
	}

	MacAddress Mac(MacAddressString);
	auto hit = hC.find(Mac.get());
	if (hit != hC.end()) {
		std::string uuid = hit->second->getUuid();
		if (uuid != DeviceProfileUuid) {
			LOG(WARNING) << "Conflicting Uuid for imported device with existing Host Cache";
			return false;
		}
	}
	try {
	    if (not findOrCreateHostByMac(Mac, DeviceProfileUuid, Ipv4Address)) {
	        LOG(WARNING) << "Failed to create Host with MacAddress " << MacAddressString
	                << "and uuid  " << DeviceProfileUuid;
	        return false;
	    }
	} catch (...) {
	    return false;
	}

	try {
	    auto it = dpMap.find(DeviceProfileUuid);
	    if (it == dpMap.end()) {
	        LOG(WARNING) << "Importing device with non-existing Device Profile UUID";
	        return false;
	    }
	    it->second->addHost(Mac);
	} catch (...) {
	    LOG(ERROR) << "Ipset host:mac does not exist for device profile " <<
	            DeviceProfileUuid << "during import of DeviceMatches" ;
	}
	return true;
}

// FIXME: need to remove IPsets for DeviceProfiles that no longer are specified in the DeviceProfiles file but only after iptables have been updated
// FIXME: need to recreate AllowedEndpoint IPsets for DeviceProfiles that have a new / higher version number

uint32_t HostCache::loadDeviceProfiles(const std::string filename) {
    DLOG_IF(INFO, Debug) << "Opening & reading " << filename;
	// Read the DeviceProfiles file
	std::ifstream ifs(filename);
	if (not ifs.is_open()) {
		PLOG(WARNING) << "Couldn't open " << filename;
		return 0;
	}
	json j;
    try {
        ifs >> j;
    } catch (...) {
        LOG(ERROR) << "failed to parse Device Profiles json data from %s";
    }

	// Track which DeviceProfileUuids were read from the file
	std::unordered_set<std::string> uuids;

	for (auto it = j.begin(); it != j.end(); ++it) {
	  std::string uuid = (*it)["DeviceProfileUuid"];
	  dpMap[uuid] = std::make_shared<DeviceProfile>(*it, Debug);
	  uuids.insert (uuid);
	}
	ifs.close();

	// Delete any Device Profile already in memory that was not
	// in the file we just read and parsed
	for (auto it = dpMap.begin(); it != dpMap.end();) {
		if (uuids.find(it->first) == uuids.end()) {
		    DLOG_IF(INFO, Debug) << "Profile no longer in DeviceProfiles file: " << it->first;
			it = dpMap.erase(it);
		} else {
		    it++;
		}
	}
	auto s = uuids.size();
	DLOG_IF(INFO, Debug) << "Profiles imported " << s;
	return s;
}

uint32_t HostCache::Whitelists_set (const std::unordered_set<std::string>& inIpv4Addresses,
		const std::unordered_set<std::string>& inIpv6Addresses,
		const std::unordered_set<std::string>& inMacAddresses) {
    DLOG_IF(INFO, Debug) << "set whitelists";
    WhitelistedNodes.clear();
	WhitelistedNodes.insert(inIpv4Addresses.begin(), inIpv4Addresses.end());
	WhitelistedNodes.insert(inIpv6Addresses.begin(), inIpv6Addresses.end());
	WhitelistedNodes.insert(inMacAddresses.begin(), inMacAddresses.end());
	return WhitelistedNodes.size();
}

void HostCache::writeIptables()  {
    if (FirewallRulesFile == "") {
        DLOG_IF(INFO, Debug) << "Iptables: Not writing firewall rules as this feature is disabled";
        return;
    }
    DLOG_IF(INFO, Debug) << "Iptables: Writing firewall rules to " << FirewallRulesFile;
    std::ofstream outputfs(FirewallRulesFile);
    std::vector<std::string> ifaces = ifMap->getLanInterfaces();
    std::string action = "LOG --log-prefix Noddos-IPtables-LOG ";
    if (FirewallBlockTraffic == true) {
        action = "DROP";
    }

    outputfs << "*filter" << std::endl;

    for (auto dp_it: dpMap) {
        DLOG_IF(INFO, Debug) << "Iptables: Processing Device Profile " << dp_it.second->getUuid() <<
                " with endpoints? " << (dp_it.second->hasAllowedEndpoints() ? "true" : "false") <<
                " and with hosts associated? " << (dp_it.second->hasHosts() ? "true" : "false");

        if (dp_it.second->hasAllowedEndpoints() && dp_it.second->hasHosts()) {
            DLOG_IF(INFO, Debug) << "Iptables: Device Profile has endpoints";
            std::string srcipset = getIpsetName(dp_it.second->getUuid(),true,false);
            std::string ipv46flag;
            std::string dstipset;
            for ( auto iface: ifaces) {
                // IPv4 permit rule
                dstipset = getIpsetName(dp_it.second->getUuid(), false, true);
                ipv46flag = "--ipv4";
                outputfs << "-A NODDOS -i " + iface + " " + ipv46flag +
                        " -m set --match-set " + srcipset + " src " +
                        "-m set --match-set " +  dstipset + " dst -j ACCEPT"
                        " -m comment --comment \"" + dp_it.second->getDeviceDescription() + "\"" << std::endl;
                // IPv6 permit rule
                dstipset = getIpsetName(dp_it.second->getUuid(), false, false);
                ipv46flag = "--ipv6";
                outputfs << "-A NODDOS -i " + iface + " " + ipv46flag +
                        " -m set --match-set " + srcipset + " src " +
                        "-m set --match-set " +  dstipset + " dst -j ACCEPT"
                        " -m comment --comment \"" + dp_it.second->getDeviceDescription() + "\"" << std::endl;

                // Block all other traffic from the MAC addresses mapped to the Device Profile
                outputfs << "-A NODDOS -i " + iface +
                        " -m set --match-set " + srcipset + " src -j " + action <<
                        " -m comment --comment \"" + dp_it.second->getDeviceDescription() + "\"" << std::endl;
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
        DLOG_IF(INFO, Debug) << "updating ip(6)tables";
    }
    int rc1 = system("iptables --flush NODDOS");
    int rc2 = system(command4.c_str());
    int rc3 = system("ip6tables --flush NODDOS");
    int rc4 = system(command6.c_str());
    if (rc1 == -1 || rc2 == -1 || rc3 == -1 || rc4 == 1) {
        PLOG(ERROR) << "Could not create child process for 'system' call";
    }
    if (rc1 == 127|| rc2 == 127 || rc3 == 127 || rc4 == 127) {
        PLOG(ERROR) << "Shell could not be executed in child process for 'system' call";
    }
    if (rc1 != 0) {
        PLOG(ERROR) << "iptables exiting with code " << rc1;
    }
    if (rc2 != 0) {
        PLOG(ERROR) << "iptables-restore existing with code " << rc2;
    }
    if (rc3 != 0) {
        PLOG(ERROR) << "ip6tables existing with code " << rc3;
    }
    if (rc4 != 0) {
        PLOG(ERROR) << "ip6tables-restore existing with code ", rc4;
    }
}

