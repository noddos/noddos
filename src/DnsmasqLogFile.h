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

 * DnsmasqLogFile.h
 *
 *  Created on: Mar 4, 2017
 *      Author: steven
 */

#ifndef DNSMASQLOGFILE_H_
#define DNSMASQLOGFILE_H_

#include <string>

#include <map>
#include <regex>
#include <cstdio>
// #include <fstream>
#include <ctime>

#include <sys/inotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory>
#include <syslog.h>
// #include "log/Log.h"


#include "DnsLogEntry.h"
#include "HostCache.h"
#include "iDeviceInfoSource.h"
#include "iCache.h"
#include "noddos.h"

#define DNSMASQDEFAULTEXPIRATION 86400

struct DnsQuery {
	std::string Fqdn;
	time_t Expiration;
};

/*
 * Class to parse dnsmasq log files to extract data on DNS queries and DHCP leases
 */
class DnsmasqLogFile : public iDeviceInfoSource, public iCache {
private:
	std::map<unsigned long long, std::shared_ptr<DnsLogEntry>> DnsQueryMap;
    std::map<unsigned long long, std::shared_ptr<DhcpRequest>> DhcpRequestMap;

    FILE *fp = nullptr;
    HostCache &hCache;
    std::string FileName;
    // std::ifstream ifs;
    std::regex dhcp_vendor_rx, dhcp_ack_rx, dhcp_clientprovidedname_rx;
    std::regex dhcp_rx;
    std::regex dns_rx;
    int inotify_fd = -1;
    int inotify_watch = -1;
    uint32_t lines_parsed = 0;
    bool Debug;

    void load_regexes() {
		dns_rx = std::regex(R"delim(dnsmasq\[\d+?\]: (\d+?) ([abcdef\d\.\:]+?)\/\d+? (\D\S*?) (\S+?) (is|from) (\S+?)$)delim",
   			std::regex_constants::ECMAScript | std::regex_constants::icase);
        dhcp_rx = std::regex(R"delim(dnsmasq-dhcp\[\d+?\]: (\d+?) (.*)$)delim",
       		std::regex_constants::ECMAScript | std::regex_constants::icase);
		dhcp_ack_rx = std::regex(R"delim(DHCPACK\(.*?\) ([\d.]*?) ([\w\:]+?)( (\S+))?$)delim",
       		std::regex_constants::ECMAScript | std::regex_constants::icase);
        dhcp_vendor_rx = std::regex(R"delim(vendor class: (.*)$)delim",
      		std::regex_constants::ECMAScript | std::regex_constants::icase);
        dhcp_clientprovidedname_rx = std::regex(R"delim(client provides name: (.*)$)delim",
       		std::regex_constants::ECMAScript | std::regex_constants::icase);
    }
    int GetLogLine ();
    bool ParseDnsLine (const std::string line);
    bool ParseDhcpLine (const std::string line);
   	uint32_t PruneDhcpRequestMap(bool Force = false);
   	uint32_t PruneDnsQueryMap(bool Force = false);


public:
    DnsmasqLogFile (const std::string inFileName, HostCache &inhCache, const uint32_t inCacheExpiration = 0, const bool inDebug = false)
		:hCache{inhCache}, Debug{inDebug} {
		load_regexes();
		if(Debug) {
			syslog (LOG_DEBUG, "Calling inotify_init");
		}
  	    if ((inotify_fd = inotify_init()) == -1) {
   	    	syslog (LOG_ERR, "Inotify init failed");
   	        perror ("inotify_init");
   	    	exit(1);
   	    } else {
   	    	if(Debug) {
   	    		syslog (LOG_DEBUG, "Inotify main FD %d", inotify_fd);
   	    	}
   	    }
   	    if (Open(inFileName, inCacheExpiration) < 0) {
			syslog(LOG_ERR, "Opening log file failed");
   	    }
   	    int flags;
   	    if (-1 == (flags = fcntl(inotify_fd, F_GETFL, 0)))
   	    	flags = 0;
   	    if (fcntl(inotify_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
   	    	syslog(LOG_ERR, "Set O_NONBLOCK on log file");
   	    }
   	}
    virtual ~DnsmasqLogFile() {
    	Close();
    	if(Debug) {
    		syslog (LOG_DEBUG, "Destroying DnsmasqLogFile instance: %s", FileName.c_str());
    	}

    	PruneDhcpRequestMap(true);
    	PruneDnsQueryMap(true);
    }

    uint32_t LinesParsed() { return lines_parsed; }
   	// iDeviceInfoSource interface methods
   	int Open(std::string inFileName, uint32_t inExpiration = DNSMASQDEFAULTEXPIRATION);
   	bool Close();
   	int GetFileHandle();
   	bool ProcessEvent(struct epoll_event &event);

   	// iCache interface methods.
    time_t Expiration_set (time_t inExpiration = DNSMASQDEFAULTEXPIRATION) {
       	return iCache::Expires = time(nullptr) + inExpiration;
    }
    time_t Expiration_get () { return iCache::Expires; }
    bool isExpired() { return time(nullptr) >= iCache::Expires; }
    uint32_t Prune (bool Force = false) { return PruneDhcpRequestMap(Force) + PruneDnsQueryMap(Force); }
};


#endif /* DNSMASQLOGFILE_H_ */
