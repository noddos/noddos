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
 *      Author: steven
 */

#include <iostream>
#include <unordered_set>
#include <string>
#include <cstring>
#include <fstream>
#include <memory>

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
#include <stdio.h>
#include <iomanip>
#include <string.h>

#include <json.hpp>
using nlohmann::json;

// #include "cpr/cpr.h"
#include <curl/curl.h>

#include "HostCache.h"


uint32_t HostCache::Prune (bool Force) {
	uint32_t prunedhosts = 0;
	for (auto it : hC) {
		if (it.second->Prune(Force)) {
			prunedhosts++;
		}
	}
	syslog(LOG_INFO, "Pruned %u hosts", prunedhosts);
	return prunedhosts;
}

uint32_t HostCache::Match() {
	uint32_t matched = 0;
	for (auto it : hC) {
		if (it.second->Match(dpMap)) {
			matched++;
		}
	}
	return matched;
}

bool HostCache::MatchByMac(const std::string inMacAddress) {
	if (hC.find(inMacAddress) != hC.end()) {
		auto &h = *(hC[inMacAddress]);
		return h.Match(dpMap);
	}

	return false;
}

bool HostCache::MatchByIpAddress(const std::string inIpAddress) {
	if (Ip2MacMap.find(inIpAddress) != Ip2MacMap.end()) {
		std::string mac = Ip2MacMap[inIpAddress];
		return MatchByMac(mac);
	}
	return false;
}

std::shared_ptr<Host> HostCache::FindOrCreateHostByMac (const std::string inMac, const std::string Uuid) {
	if (WhitelistedNodes.find(inMac) != WhitelistedNodes.end()) {
		return nullptr;
    }
	if (inMac == "") {
		syslog(LOG_WARNING, "empty Mac Address provided");
		return nullptr;
	}
	std::string Mac = inMac;
	std::transform(Mac.begin(), Mac.end(), Mac.begin(), ::tolower);
	if (hC.find(Mac) == hC.end()) {
		if (Debug) {
			syslog(LOG_DEBUG, "Adding new Host with MAC address %s", Mac.c_str());
		}
		auto h = std::make_shared<Host>(Mac, Uuid, Debug);
		hC[Mac] = h;
		return h;
	}
	return hC[Mac];
}

std::shared_ptr<Host> HostCache::FindOrCreateHostByIp (const std::string ip, const std::string Uuid) {
	if (WhitelistedNodes.find(ip) != WhitelistedNodes.end()) {
		return nullptr;
    }
	std::string MacAddress;
	auto it = Ip2MacMap.find(ip);
	if ( it == Ip2MacMap.end()) {
		MacAddress = MacLookup(ip);
		if (MacAddress == "") {
			if (Debug) {
				syslog(LOG_DEBUG, "Couldn't find ARP entry for %s", ip.c_str());
			}
			return nullptr;
		}
		Ip2MacMap[ip] = MacAddress;
	} else {
		MacAddress = it->second;
	}
	return FindOrCreateHostByMac (MacAddress, Uuid);
}

bool HostCache::AddByMac (const std::string inMacAddress, const std::string inIpAddress) {
	std::string Mac = inMacAddress;
	std::transform(Mac.begin(), Mac.end(), Mac.begin(), ::tolower);
	if (hC.find(Mac) != hC.end()) {
		return false;
    }
	auto h = std::make_shared<Host>(Mac, Debug);
	h->IpAddress_set (inIpAddress);
	hC[Mac] = h;
	Ip2MacMap[inIpAddress] = Mac;
	return true;
}

bool HostCache::AddFlow (const std::string srcip, const uint16_t srcport, const std::string dstip, const uint16_t dstport, const uint8_t protocol, const uint32_t expiration) {
	if (WhitelistedNodes.find(srcip) != WhitelistedNodes.end()) {
		return false;
	}

	std::shared_ptr<Host> h = FindOrCreateHostByIp(srcip);
	if (h) {
		h->FlowEntry_set(srcport, dstip, dstport, protocol, expiration);
		return true;
	}
	return false;
}

bool HostCache::AddDnsQueryIp (const std::string clientip, const std::string fqdn, const std::string ip, const uint32_t expire) {
	if (WhitelistedNodes.find(clientip) != WhitelistedNodes.end())
		return false;

	std::shared_ptr<Host> h = FindOrCreateHostByIp(clientip);
	if (h) {
		h->DnsLogEntry_set(fqdn, ip);
		return true;
	}
	return false;
}

bool HostCache::AddDhcpRequest (const std::shared_ptr<DhcpRequest> inDhcpRequest_sptr) {
	if (inDhcpRequest_sptr->IpAddress == "" && inDhcpRequest_sptr->MacAddress == "") {
		syslog(LOG_WARNING, "No IpAdddress or Macaddress in DHCP request");
		return false;

	}
	if (isWhitelisted(inDhcpRequest_sptr->IpAddress) || isWhitelisted(inDhcpRequest_sptr->MacAddress))
		return false;

	std::shared_ptr<Host> h;
	if (inDhcpRequest_sptr->MacAddress != "") {
		h = FindOrCreateHostByMac(inDhcpRequest_sptr->MacAddress);
	} else {
		h = FindOrCreateHostByIp(inDhcpRequest_sptr->IpAddress);
	}

	if (h) {
		h->Dhcp_set(inDhcpRequest_sptr);
		return true;
	}
	return false;
}

bool HostCache::AddDhcpRequest (const std::string IpAddress, const std::string MacAddress, const std::string Hostname, const std::string DhcpHostname, const std::string DhcpVendor) {
	if (IpAddress == "" && MacAddress == "") {
		syslog(LOG_WARNING, "No IpAdddress or Macaddress in DHCP request");
		return false;

	}
	if (isWhitelisted(IpAddress) || isWhitelisted(MacAddress))
		return false;

	std::shared_ptr<Host> h;
	if (MacAddress != "") {
		h = FindOrCreateHostByMac(MacAddress);
	} else {
		h = FindOrCreateHostByIp(IpAddress);
	}

	if (h) {
		h->Dhcp_set(IpAddress, MacAddress, Hostname, DhcpHostname, DhcpVendor);
		return true;
	}
	return false;

}

bool HostCache::AddSsdpInfo (const std::shared_ptr<SsdpHost> sHost) {
	if (sHost->IpAddress == "") {
		syslog(LOG_WARNING, "AddSsdpInfo: no IP address provided");
		return false;
	}
	if (WhitelistedNodes.find(sHost->IpAddress) != WhitelistedNodes.end())
		return false;

	std::shared_ptr<Host> h = FindOrCreateHostByIp(sHost->IpAddress);
	if (h) {
		h->SsdpInfo_set(sHost);
		return true;
	}
	return false;
}

// TODO: Lookup MAC addresses in ARP table using IOCTL now works but you need to specify the Ethernet interface and we don't have code for that yet
// so for now we'll continue doing lookups in /proc/net/arp even though that is slower
std::string HostCache::MacLookup (const std::string inIpAddress, std::string inInterface, const int retries) {
	int domain;
	struct arpreq areq;
	memset(&areq, 0, sizeof(areq));
	void *addr_ptr;

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
		syslog (LOG_ERR, "inet_pton failed for %s", inIpAddress.c_str());
		return "";
	}

	struct sockaddr_in *sin = (struct sockaddr_in *) &areq.arp_ha;
    sin->sin_family = ARPHRD_ETHER;
    strncpy(areq.arp_dev, inInterface.c_str(), 15);

    /* Get an internet domain socket. */
    int s;
	if ((s = socket(domain, SOCK_DGRAM, 0)) == -1) {
        syslog(LOG_ERR, "Can't open socket for ARP table lookup");
        return "";
    }

    if (-1 == ioctl(s,SIOCGARP , (caddr_t) &areq)) {
		syslog (LOG_ERR, "ARP lookup failure for %s", inIpAddress.c_str());
		if (retries > 0) {
			if (Debug) {
				syslog(LOG_DEBUG, "Additional ARP lookup for %s", inIpAddress.c_str());
			}
			if (SendUdpPing (inIpAddress, 1900)) {
				usleep(5000);
				return MacLookup (inIpAddress, inInterface, retries - 1);
			}
		}
		return "";
	}
	char mA[18];
	unsigned char *ptr = (unsigned char *) areq.arp_ha.sa_data;
	sprintf(mA, "%02X:%02X:%02X:%02X:%02X:%02X",
	        (ptr[0] & 0xff), (ptr[1] & 0xff), (ptr[2] & 0xff),
	        (ptr[3] & 0xff), (ptr[4] & 0xff), (ptr[5] & 0xff));
	std::string MacAddress(mA);
	return MacAddress;
}

uint32_t HostCache::getInterfaceIpAddresses() {
	/*

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	std::ifstream ifs("/proc/net/dev");
	std::string line;
	while (std::getline(ifs, line)) {
		std::smatch m;
		if(std::regex_search(line, m, dev_rx)) {
			std::string interface = m.str(1);
			struct ifreq ifr;
			// ifr.ifr_addr.sa_family = AF_INET;
			// strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ-1);
			ioctl(fd, SIOCGIFADDR, &ifr);

			}
		}

	}
	ifs.close();
	*/
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        syslog(LOG_ERR, "Can't loop through local interfaces: getifaddrs");
        return 0;
    }

    /* Walk through linked list, maintaining head pointer so we
       can free list later */

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL) {
            freeifaddrs(ifaddr);
            continue;
        }
        family = ifa->ifa_addr->sa_family;

        /* Display interface name and family (including symbolic
           form of the latter for the common families) */

        if (Debug) {
        	syslog(LOG_DEBUG, "Interface %-8s %s (%d)", ifa->ifa_name,
               (family == AF_PACKET) ? "AF_PACKET" :
               (family == AF_INET) ? "AF_INET" :
               (family == AF_INET6) ? "AF_INET6" : "???", family);
        }
        LocalInterfaces.insert(ifa->ifa_name);
        /* For an AF_INET* interface address, display the address */

        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                syslog(LOG_ERR, "getnameinfo() failed: %s\n", gai_strerror(s));
                freeifaddrs(ifaddr);
                return 0;
            }

            if(Debug) {
            	syslog (LOG_DEBUG, "Interface %s with IP address: %s", ifa->ifa_name, host);
            }
            LocalIpAddresses.insert(host);
        }
    }

    freeifaddrs(ifaddr);
	return 0;
}

std::string HostCache::MacLookup (const std::string inIpAddress, const int retries) {
	// TODO: we should cache ARP table and only refresh it if a MAC lookup fails
	std::ifstream ifs("/proc/net/arp");
	std::string line;
	while (std::getline(ifs, line)) {
		std::smatch m;
		if(std::regex_match(line, m, arp_rx)) {
			std::string ip = m.str(1);
			std::string mac = m.str(2);
			if (ip == inIpAddress && mac != "00:00:00:00:00:00") {
				ifs.close();
				return mac;
			}
		}

	}
	ifs.close();
	if (retries > 0) {
		if (Debug) {
			syslog(LOG_DEBUG, "Additional ARP lookup for %s", inIpAddress.c_str());
		}
		if (SendUdpPing (inIpAddress, 1900)) {
			usleep(5000);
			return MacLookup (inIpAddress, retries - 1);
		}
	}
	return "";
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
		syslog(LOG_ERR, "Failed to create socket");
		return false;
	}

	if(bind(sock,( struct sockaddr *) &myaddr, sizeof(myaddr))<0) {
		syslog(LOG_ERR, "bind failed");
	    return false;
	}
	inet_pton(AF_INET,DstIpAddress.c_str(),&myaddr.sin_addr.s_addr);
	myaddr.sin_port=htons(1900);

	std::string s("12345678910:5/15:300.00:Visa");

	//send the message to server
	if(sendto(sock, s.c_str(), s.size(), 0, (struct sockaddr *)&myaddr, sizeof(myaddr))!=s.size()) {
		syslog(LOG_ERR, "Mismatch in number of bytes sent");
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
		syslog(LOG_WARNING, "Couldn't open %s", filename.c_str());
		return false;
	}
	ofs << std::setw(4) << j << std::endl;
	ofs.close();
	return true;
}

uint32_t HostCache::RestApiCall (const std::string api, const json &j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile) {
	/*
    auto r = cpr::Post(
    	cpr::Url{"https://api.noddos.io/" + api},
		cpr::Header{{"Content-Type", "application/json"},{"X-Fingerprint", "1234"}},
		cpr::Body{j.dump()}
    );
    long response_code = r.status_code;
	*/
	std::string url = "https://api.noddos.io/" + api;

	std::string body = j.dump();
	char buf[strlen(body.c_str())+1];
	strcpy(buf, body.c_str());
	if (Debug) {
		syslog (LOG_DEBUG, "Uploading %lu bytes of data to %s", strlen(buf), url.c_str());
	}

	struct curl_slist *hlist = NULL;
	hlist = curl_slist_append(hlist, "Content-Type: application/json");
	if (hlist == NULL) {
		syslog(LOG_ERR, "Couldn't create curl header for API call to %s", api.c_str());
	}

    std::string response_string;
    std::string header_string;
    long response_code;
    double elapsed;
	auto curl = curl_easy_init();
	if (curl) {
		CURLcode ret;
		ret = curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_URL returned %d",ret);
		}
		// curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
		ret = curl_easy_setopt(curl, CURLOPT_SSLCERT, ClientApiCertFile.c_str());
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_SSLCERT returned %u", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_SSLKEY, ClientApiKeyFile.c_str());
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_SSLKEY returned %u", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "ECDHE-RSA-AES256-GCM-SHA384");
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_SSL_CIPHER_LIST returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_POSTFIELDS returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) strlen(buf));
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_POSTFIELDSIZE_LARGE returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_NOPROGRESS returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_USERAGENT, "noddos/1.0.0");
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_USERAGENT returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hlist);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_HTTPHEADER returned %d", ret);
		}
		// ret = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
		// if(ret) {
		// 	syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
		// }
		ret = curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_MAXREDIRS returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_TCP_KEEPALIVE returned %d", ret);
		}
		// ret = curl_easy_setopt(curl, CURLOPT_TCP_FASTOPEN, 1L);
		// if(ret) {
		// 	syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
		// }
		ret = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long) 2000);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_TIMEOUT_MS returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlwriteFunction);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEDATA returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_HEADERDATA returned %d", ret);
		}
		if (false && Debug) {
			// TODO test on whether STDOUT is open for writing
			// 'always' disabled as this logs to STDOUT, which is normally closed
			ret = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		}
	    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);


	    curl_easy_perform(curl);
	    curl_slist_free_all(hlist);
	    curl_easy_cleanup(curl);
	    curl = NULL;
	    if (Debug) {
	    		syslog (LOG_DEBUG, "Upload resulted in %lu status, data %s", response_code, response_string.c_str());
	    	}
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
    		syslog(LOG_WARNING, "Couldn't open %s", filename.c_str());
    	}
    	ofs << std::setw(4) << j << std::endl;
    	ofs.close();
    }
    return (uint32_t) response_code;
}

uint32_t HostCache::UploadDeviceStats(const std::string ClientApiCertFile, const std::string ClientApiKeyFile) {
	uint32_t uploads = 0;
	json j;
	for (auto it : hC) {
		if ( (not isWhitelisted(*(it.second))) && not it.second->isMatched() && not it.second->UploadsDisabled()) {
			json h;
			if (it.second->DeviceStats(h, 604800, false, false)) {
				uploads++;
				j.push_back(h);
			}
		}
	}
	if (uploads > 0) {
		auto r = RestApiCall ("v1/uploaddevices", j, ClientApiCertFile, ClientApiKeyFile);
		syslog(LOG_INFO, "Called v1/uploaddevices API with status_code %u", r);
	} else {
		syslog(LOG_INFO, "Not calling v1/uploaddevices API as there is no data to report");
	}
	return uploads;
}

bool HostCache::UploadTrafficStats(const time_t interval, const bool ReportRfc1918, const std::string ClientCertFile, const std::string ClientApiKeyFile) {
	uint32_t uploads = 0;
	json j;
	for (auto it : hC) {
		if ( (not isWhitelisted(*(it.second))) && it.second->isMatched()) {
			json h;
			if (it.second->TrafficStats(h, interval, ReportRfc1918, LocalIpAddresses, false)) {
				uploads++;
				j.push_back(h);
			}
		}
	}
	if (uploads > 0) {
		auto r = RestApiCall ("v1/uploadstats", j, ClientCertFile, ClientApiKeyFile);
		syslog(LOG_INFO, "Called v1/uploadstats API with status_code %u", r);
	} else {
		syslog(LOG_INFO, "Not calling v1/uploadstats API as there is no data to report");
	}
	return uploads;
}

bool HostCache::ImportDeviceProfileMatches(const std::string filename) {
	if (Debug) {
		syslog(LOG_DEBUG, "Opening & reading %s", filename.c_str());
	}

	std::ifstream ifs(filename);
	if (not ifs.is_open()) {
		syslog(LOG_WARNING, "Couldn't open %s", filename.c_str());
		return false;
	}
	json j;
	ifs >> j;

	uint32_t matches = 0;
	for (auto it = j.begin(); it != j.end(); ++it) {
	   ImportDeviceInfo(*it);
	   matches++;
	}
	ifs.close();
	syslog(LOG_INFO, "DeviceMatches read: %u", matches);
	return true;
}

bool HostCache::ImportDeviceInfo (json &j) {
	std::string DeviceProfileUuid;
	if (j.find("DeviceProfileUuid") == j.end()) {
		syslog(LOG_ERR, "No DeviceProfileUuid set, ignoring this Object");
		return false;
	}
	if (not j["DeviceProfileUuid"].is_string()) {
		syslog(LOG_ERR, "DeviceProfileUuid is not a string, ignoring this Object");
		return false;
	}
	if (DeviceProfileUuid != j["DeviceProfileUuid"].get<std::string>()) {
		return false;
    }
	std::string MacAddress;
	if (j.find("MacAddress") == j.end()) {
		syslog(LOG_ERR, "No MacAddress set, ignoring this Object");
		return false;
	}
	if (not j["MacAddress"].is_string()) {
		syslog(LOG_ERR, "MacAddress is not a string, ignoring this Object");
		return false;
	}
	if (MacAddress != j["MacAddress"].get<std::string>()) {
		return false;
    }
	if (Debug) {
		syslog(LOG_DEBUG, "Importing Device Profile for UUID %s with MacAddress %s", DeviceProfileUuid.c_str(), MacAddress.c_str());
	}

	auto hit = hC.find(MacAddress);
	if (hit != hC.end()) {
		std::string uuid = hit->second->Uuid_get();
		if (uuid != DeviceProfileUuid) {
			syslog(LOG_WARNING, "Conflicting Uuid for imported device with existing Host Cache");
			return false;
		}
	}
	if (not FindOrCreateHostByMac(MacAddress, DeviceProfileUuid)) {
		syslog(LOG_WARNING, "Failed to create Host with MacAddress %s and uuid %s", MacAddress.c_str(), DeviceProfileUuid.c_str());
		return false;
	}
	return true;
}
uint32_t HostCache::DeviceProfiles_load(const std::string filename) {
	if (Debug) {
		syslog(LOG_DEBUG, "Opening & reading %s", filename.c_str());
	}
	// Read the DeviceProfiles file
	std::ifstream ifs(filename);
	if (not ifs.is_open()) {
		syslog(LOG_WARNING, "Couldn't open %s", filename.c_str());
		return 0;
	}
	json j;
	ifs >> j;

	// Track which DeviceProfileUuids were read from the file
	std::unordered_set<std::string> uuids;

	// for (json::iterator it = j.begin(); it != j.end(); ++it) {
	for (auto it = j.begin(); it != j.end(); ++it) {
	  std::string uuid = (*it)["DeviceProfileUuid"].get<std::string>();
	  dpMap[uuid] = std::make_shared<DeviceProfile>(*it, Debug);
	  uuids.insert (uuid);
	}
	ifs.close();

	for (auto &kv : dpMap) {
		if (uuids.find(kv.first) == uuids.end()) {
			if (Debug) {
				syslog(LOG_DEBUG, "Profile no longer in DeviceProfiles file: %s", kv.first.c_str());
			}
			dpMap.erase(kv.first);
		}
	}
	auto s = uuids.size();
	if (Debug) {
		syslog(LOG_DEBUG, "Profiles imported %lu", s);
	}
	return s;
}

uint32_t HostCache::Whitelists_set (const std::unordered_set<std::string>& inIpv4Addresses,
		const std::unordered_set<std::string>& inIpv6Addresses,
		const std::unordered_set<std::string>& inMacAddresses) {
	WhitelistedNodes.clear();
	WhitelistedNodes.insert(inIpv4Addresses.begin(), inIpv4Addresses.end());
	WhitelistedNodes.insert(inIpv6Addresses.begin(), inIpv6Addresses.end());
	WhitelistedNodes.insert(inMacAddresses.begin(), inMacAddresses.end());
	return WhitelistedNodes.size();
}

uint32_t HostCache::HostDnsQueryCount (std::string IpAddress) {
	auto it = Ip2MacMap.find(IpAddress);
	if ( it == Ip2MacMap.end()) {
		return 0;
	}
	auto Mac = it->second;
	auto &h = hC[Mac];
	return h->DnsLogEntryCount();

}
