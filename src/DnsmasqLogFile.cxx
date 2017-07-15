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

 * DnsmasqLogFile.cxx
 *
 *  Created on: Apr 1, 2017
 *      Author: steven
 */

#include <string>
#include <unordered_set>
#include <ctime>
#include <vector>
#include <iostream>
#include <fstream>
#include <regex>

#include <syslog.h>
#include <stdio.h>
#include <sys/epoll.h>



#include "noddos.h"
#include "DnsmasqLogFile.h"


/*
 * Reads line from dnsmasq log file
 * Returns -1 on file read failure, 0 on line read but did not match regexes, 1 line read that matched dns or dhcp regex
 */
int DnsmasqLogFile::GetLogLine () {
	if (ferror(fp)) {
	    syslog(LOG_ERR, "file handle for log file has error");
		return -1;
	}

	char cline[300];
	if (fgets(cline, 300, fp) == NULL) {
		return -1;
    }
	cline[strcspn(cline, "\n")] = 0;
	std::string line = cline;

	// TODO: only process log lines if they are not older than `CacheExpiration'
	if(Debug) {
		syslog(LOG_DEBUG, "%s", line.c_str());
	}

	if (ParseDnsLine(line)) {
		return 1;
    }

	if (ParseDhcpLine(line)) {
		return 1;
    }

	return 0;
}

//! Parses DHCP info from line in dnsmasq logfile
bool DnsmasqLogFile::ParseDhcpLine (const std::string line) {
	std::smatch m;

	if (not std::regex_search(line, m, dhcp_rx)) {
		return false;
    }
	if(m.empty()) {
		return false;
    }


	unsigned long long querynumber = std::stoll(m.str(1));
	auto dhcpmessage = m.str(2);
	if(Debug) {
		syslog(LOG_DEBUG, "DHCP logline for query %llu : %s", querynumber, dhcpmessage.c_str());
	}

	bool cachedQuery =  DhcpRequestMap.find(querynumber) != DhcpRequestMap.end();


	std::smatch ack_m;
	if (std::regex_match(dhcpmessage, ack_m, dhcp_ack_rx)) {
		if (not cachedQuery) {
			DhcpRequestMap[querynumber] = std::make_shared<DhcpRequest>();
			if(Debug) {
				syslog(LOG_DEBUG, "creating entry in QueryMap for query number %llu", querynumber);
			}
		}
		DhcpRequestMap[querynumber]->IpAddress = ack_m.str(1);
		DhcpRequestMap[querynumber]->Mac.set(ack_m.str(2));
		if(Debug) {
			syslog(LOG_DEBUG, "Parsed DHCP Ack %s : %s",
				DhcpRequestMap[querynumber]->IpAddress.c_str(),
				DhcpRequestMap[querynumber]->Mac.c_str()
			);
		}
		// The DHCP Ack is the last message for a DHCP query that we collect info from so now we can poplate the Host entity
		hCache.AddDhcpRequest(
				DhcpRequestMap[querynumber]->IpAddress,
				DhcpRequestMap[querynumber]->Mac,
				DhcpRequestMap[querynumber]->Hostname,
				DhcpRequestMap[querynumber]->DhcpVendor
		);
		if (DhcpRequestMap.erase(querynumber) < 1) {
			if(Debug) {
				syslog (LOG_WARNING, "Erasing of DHCP requestmap entry for %llu failed", querynumber);
			}
		}
		if(Debug) {
			syslog (LOG_DEBUG, "ParseDhcpLine: Erasing DHCP with querynumber %llu", querynumber);
		}
	} else {
		std::smatch vendor_m;
		if (std::regex_match(dhcpmessage, vendor_m, dhcp_vendor_rx)) {
			if (not cachedQuery) {
				DhcpRequestMap[querynumber] = std::make_shared<DhcpRequest>();
				if(Debug) {
					syslog(LOG_DEBUG, "creating entry in QueryMap for query number %llu for DHCP vendor rx", querynumber);
				}
			}
			DhcpRequestMap[querynumber]->DhcpVendor = vendor_m.str(1);
			if(Debug) {
				syslog(LOG_DEBUG, "Parsed DHCP Vendor %s", DhcpRequestMap[querynumber]->DhcpVendor.c_str());
			}
		} else {
			std::smatch client_m;
			if (std::regex_match(dhcpmessage, client_m, dhcp_clientprovidedname_rx)) {
				if (not cachedQuery) {
					DhcpRequestMap[querynumber] = std::make_shared<DhcpRequest>();
					if(Debug) {
						syslog(LOG_DEBUG, "creating entry in QueryMap for query number %llu for DHCP Client Provided Name ", querynumber);
					}
				}
				DhcpRequestMap[querynumber]->Hostname = client_m.str(1);
				if(Debug) {
					syslog(LOG_DEBUG, "Parsed DHCP Client provided hostname %s", DhcpRequestMap[querynumber]->Hostname.c_str());
				}
			}
		}
	}
	return true;
}

//! Prunes DHCP data that has not been associated with a Host instance

// Some DhcpRequest objects may have been created without them being assigned to a Host
// for example if the Dhcp ACK log line gets lost. Here we delete such entries to prevent
// memory leaks. Given this is a rather esotheric edge case, we don't have to prune very often
uint32_t DnsmasqLogFile::PruneDhcpRequestMap (bool Force) {
	uint32_t deletecount = 0;

	auto iter = DhcpRequestMap.begin();
	while (iter != DhcpRequestMap.end()) {
		auto erasediter = iter;
		iter++;
		auto & dRequest = erasediter->second;
		if (erasediter->second != nullptr && (Force || dRequest->isExpired())) {
			if(Debug) {
				syslog (LOG_DEBUG, "PruneDhcpRequestMap: Erasing DHCP with querynumber %llu as expiration is %ld and now is %ld",
						erasediter->first, dRequest->Expiration_get(), time(nullptr));
			}
			DhcpRequestMap.erase(erasediter->first);
			deletecount++;
		}
	}
	return deletecount;
}

//! Parse DNS data from a line from a dnsmasq log file


bool DnsmasqLogFile::ParseDnsLine (const std::string line) {
	std::smatch m;

	if (not std::regex_search(line, m, dns_rx)) {
		return false;
	}
	if(m.empty()) {
		return false;
	}

	unsigned long long querynumber = std::stoll(m.str(1));
	auto clientip = m.str(2);
	auto fqdn = m.str(4);
	std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);
	auto isfrom = m.str(5);
	auto ip = m.str(6);
	if(Debug) {
		syslog(LOG_DEBUG, "dns_rx matched, query number %llu for DNS client ip %s", querynumber, clientip.c_str());
	}

	std::string queried_fqdn = fqdn;
	// Do we already have data with this query number?
	if (DnsQueryMap.find(querynumber) == DnsQueryMap.end()) {
		if (isfrom == "is") {
			// We missed the original query in the logfile, which contained the requested FQDN
			// The lines with results may actually be pointing to a CNAME, which doesn't allow
			// us to match DeviceProfile match conditions with queries
			// So we're going to ignore this log entry
			syslog(LOG_INFO, "Missed query, ignoring data");
			return true;
		}
		DnsQueryMap[querynumber] = std::make_shared<DnsLogEntry>(fqdn);
		if(Debug) {
			syslog(LOG_DEBUG, "creating entry in QueryMap for %s", fqdn.c_str());
		}
	} else {
		// The FQDN in the log line may be a CNAME for the original FQDN that the client queried for
		queried_fqdn = DnsQueryMap[querynumber]->Fqdn_get();
	}

	if (isfrom == "is") {
		if (ip == "<CNAME>" || ip == "NODATA-IPv6" || ip == "NXDOMAIN") {
			if(Debug) {
				syslog(LOG_DEBUG, "Skipping DNS query log didn't return an IP address");
			}
		} else if ( std::isdigit(ip.at(0)) == 0 ) {
			if(Debug) {
				syslog(LOG_DEBUG, "Skipping DNS query log for reverse lookups");
			}
		} else {
			if(Debug) {
				syslog(LOG_DEBUG, "Adding IP address %s for %s", ip.c_str(), queried_fqdn.c_str());
			}
			hCache.AddDnsQueryIp(clientip, queried_fqdn, ip);
		}
	}
	return true;
}

//! Prune expired (or all if Force == true) DNS log entries from the DnsQueryMap
uint32_t DnsmasqLogFile::PruneDnsQueryMap (bool Force) {
	uint32_t deletecount = 0;

	auto iter = DnsQueryMap.begin();
	while(iter != DnsQueryMap.end()) {
		auto erasediter = iter;
		iter++;
		auto d = erasediter->second;
		if (Force || d->isExpired()) {
			// delete d;
			if (Debug) {
				syslog(LOG_DEBUG, "Expiring DNS Query with expiration %ld while now is %ld", d->Expiration_get (), time(nullptr));
			}
			DnsQueryMap.erase(erasediter);
			deletecount++;
		}
	}
	return deletecount;
}


//! Open the dnsmasq log file
int DnsmasqLogFile::Open(std::string inFileName, uint32_t inExpiration) {
	if(Debug) {
		syslog(LOG_DEBUG, "Opening dnsmasq logfile at %s", inFileName.c_str());
	}
	if (inFileName == "") {
		return -1;
	}
	if ((fp = fopen (inFileName.c_str(),"r")) != NULL) {
		FileName = inFileName;
    	if (not inExpiration) {
    		fseek(fp, 0, SEEK_END);
    	} else {
    		int parsed;
    		while ((parsed = GetLogLine()) > -1 ) {
    			lines_parsed += parsed;
    		}
    	}
    } else {
    	syslog(LOG_ERR, "Can't open log file");
    	return -1;
    }

    if ((inotify_watch = inotify_add_watch(inotify_fd, FileName.c_str(),IN_CLOSE_NOWRITE|IN_DELETE_SELF|IN_MODIFY)) == -1)
    {
    	syslog(LOG_ERR, "Inotify add_watch failed");
    	Close();
    	return lines_parsed;
    }

    return lines_parsed;
}

//! Close the dnsmasq log file
bool DnsmasqLogFile::Close() {
	if (inotify_watch > -1) {
		if (inotify_fd > -1) {
			if (inotify_rm_watch (inotify_fd, inotify_watch) < 0) {
				syslog(LOG_ERR, "Remove inotify watch for log file");
            }
        }
    }
	inotify_watch = -1;

	if (fp != NULL) {
		if (fclose(fp) < 0) {
			syslog(LOG_ERR,  "Close log file");
        }
		fp = NULL;
    }

	return true;
}

int DnsmasqLogFile::GetFileHandle() {
	return inotify_fd;
}

bool DnsmasqLogFile::ProcessEvent(struct epoll_event &epoll_event) {
	char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;

	char *ptr;
	for (;;) {
	    ssize_t len = read(inotify_fd, buf, 4096);
        if (len == -1 && errno != EAGAIN) {
            syslog(LOG_ERR, "read on inotify_fd");
            Close();
            return false;
        }
        if (len <= 0) {
        	break;
        }
        for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *) ptr;
            if ((event->mask & IN_CLOSE_NOWRITE) || (event->mask & IN_DELETE_SELF)) {
            	Close();
            	Open(FileName, 0);
            }
            if (event->mask & IN_MODIFY) {
            	int parsed = 0;
            	while ((parsed = GetLogLine()) > -1) {
            		lines_parsed += parsed;
            	}
            }
        }
	}
	return false;
}

