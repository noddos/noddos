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

 * FlowTrack.h
 *
 *  Created on: Mar 19, 2017
 *      Author: steven
 */

#ifndef FLOWTRACK_H_
#define FLOWTRACK_H_


#include <ctime>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/stat.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

// #include "log/Log.h"

#include "iDeviceInfoSource.h"
#include "HostCache.h"

int netfilter_cb2(const struct nlmsghdr *nlh, enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data);
int netfilter_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data);

struct Flow {
	struct sockaddr_storage src, dst;
	uint8_t flowstatus;
	uint8_t connectionstatus;
	uint8_t protocol;

};


class FlowTrack : public iDeviceInfoSource {
private:
    struct nfct_handle *h = nullptr;
    struct nfct_filter *filter = nullptr;
    HostCache &hC;
    const Config &config;
    bool useNfct = false;
    FILE * ctFilePointer = nullptr;
    bool Debug = false;


public:
	FlowTrack(HostCache & inhC, Config &inConfig): hC{inhC}, config{inConfig}, Debug{inConfig.Debug} {
        if (Debug) {
            syslog (LOG_DEBUG, "FlowTrack: constructing instance");
        }
	}
	virtual int Open (std::string input = "", uint32_t inExpiration = 0) {
        if (Debug) {
            syslog (LOG_DEBUG, "FlowTrack: open");
        }
		// We don't care about Open parameters in this Class derived from iDeviceInfoSource
		input = "";
		inExpiration = 0;

		struct stat buf;
		if (config.UseNfConntrack == true && stat ("/proc/net/nf_conntrack", &buf) == 0) {
			if (Debug == true) {
				syslog (LOG_DEBUG, "FlowTrack: /proc/net/nf_conntrack exists, using it");
			}
			if ((ctFilePointer = fopen ("/proc/net/nf_conntrack","r")) != NULL) {
				int flags;
				int nf_fd = fileno(ctFilePointer);
				if (-1 == (flags = fcntl(nf_fd, F_GETFL, 0)))
					flags = 0;
				if (fcntl(nf_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
					syslog(LOG_ERR, "FlowTrack: Set O_NONBLOCK on conntrack log file");
		            throw std::system_error(errno, std::system_category());
				} else {
					useNfct = false;
					return 0;
				}
			}
		}
		useNfct = true;
		if (config.Debug) {
			syslog (LOG_DEBUG, "FlowTrack: Opening NFCT");
		}

        h = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW |
                                 NF_NETLINK_CONNTRACK_UPDATE);
        if (!h) {
       		syslog(LOG_ERR, "FlowTrack: nfct_open");
       		throw std::system_error(errno, std::system_category());
        }
        int on = 1;

        setsockopt(nfct_fd(h), SOL_NETLINK, NETLINK_BROADCAST_SEND_ERROR, &on, sizeof(int));

        setsockopt(nfct_fd(h), SOL_NETLINK, NETLINK_NO_ENOBUFS, &on, sizeof(int));

        filter = nfct_filter_create();
        if (!filter) {
            syslog(LOG_ERR, "nfct_create_filter");
            throw std::system_error(errno, std::system_category());
        }
        // TODO  add other protocols
        nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_UDP);
        nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_TCP);

        // We're interested in all TCP states
        struct nfct_filter_proto filter_proto = {
                .proto = IPPROTO_TCP,
                .state = TCP_CONNTRACK_ESTABLISHED
        };
        nfct_filter_add_attr(filter, NFCT_FILTER_L4PROTO_STATE, &filter_proto);

/*
        struct nfct_filter_proto filter_proto = {
                .proto = IPPROTO_UDP,
                .state = UDP_CONNTRACK_ESTABLISHED
        };
*/
        nfct_filter_add_attr(filter, NFCT_FILTER_L4PROTO_STATE, &filter_proto);

        for (auto it: config.WhitelistedIpv4Addresses) {
        	/* BSF always wants data in host-byte order */
        	struct nfct_filter_ipv4 filter_ipv4 = {
                .addr = ntohl(inet_addr(it.c_str())),
                .mask = 0xffffffff,
        	};

        	nfct_filter_set_logic(filter,
        		NFCT_FILTER_SRC_IPV4,
                NFCT_FILTER_LOGIC_NEGATIVE);

        	nfct_filter_add_attr(filter, NFCT_FILTER_SRC_IPV4, &filter_ipv4);

        	nfct_filter_set_logic(filter,
        		NFCT_FILTER_DST_IPV4,
                NFCT_FILTER_LOGIC_NEGATIVE);

        	nfct_filter_add_attr(filter, NFCT_FILTER_DST_IPV4, &filter_ipv4);
        }

        // TODO set up filterlist for IPv6 addresses
       	/* BSF always wants data in host-byte order */
       	struct nfct_filter_ipv6 filter_ipv6 = {
                .addr = { 0x0, 0x0, 0x0, 0x1 },
                .mask = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff },
       	};

       	/* ignore whatever that comes from ::1 (loopback) */
       	nfct_filter_set_logic(filter,
       		NFCT_FILTER_SRC_IPV6,
           	NFCT_FILTER_LOGIC_NEGATIVE);

       	nfct_filter_add_attr(filter, NFCT_FILTER_SRC_IPV6, &filter_ipv6);

        if (nfct_filter_attach(nfct_fd(h), filter) == -1) {
            syslog(LOG_ERR, "nfct_filter_attach");
            throw std::system_error(errno, std::system_category());
        }

        nfct_callback_register(h, NFCT_T_ALL, netfilter_cb, &hC);
        if (Debug) {
            syslog (LOG_DEBUG, "FlowTrack: open competed succesfully");
        }

        return 0;
	}

	virtual ~FlowTrack() {
		Close();
		if (config.Debug) {
			syslog (LOG_DEBUG, "FlowTrack: destructing instance");
		}
	}
	// iDeviceInfoSource interface methods
	virtual bool Close () {
		if (useNfct == false) {
			if (ctFilePointer == nullptr) {
				syslog(LOG_WARNING, "FlowTrack: Closing closed conntrack file pointer");
				return false;
			}
			if (config.Debug == true) {
			    syslog(LOG_DEBUG, "FlowTrack: Closing conntrack file pointer");
			}
			return fclose(ctFilePointer);
		}
		// useNfct == true
		if (h == nullptr) {
			syslog(LOG_WARNING, "FlowTrack: Closing closed conntrack handler");
			return false;
		}
		if (config.Debug == true) {
			syslog(LOG_DEBUG, "FlowTrack: Closing conntrack handler");
		}
		// valgrind thinks nfct_close is buggy
		// return nfct_close(h);
		return true;
	}

	virtual int getFileHandle() {
		if (useNfct == false) {
			return fileno(ctFilePointer);
		}
		return nfct_fd(h);
	}

	virtual bool processEvent(struct epoll_event &event) {
		char buf [24];
		auto rawtime = time (nullptr);
		struct tm * timeinfo = localtime (&rawtime);
		strftime (buf, 20, "%x %X", timeinfo);

		int rt = -1;
		if (useNfct == true) {
			rt = nfct_catch(h);
			if (rt < 0) {
				syslog(LOG_ERR, "nfct_catch: %s ", strerror(errno));
			}
			if (config.Debug) {
				syslog(LOG_DEBUG, "Conntrack event read at %s with status %d", buf, rt);
			}
		} else {
        	while ((parseLogLine()) > -1) {}
		}
        return true;
	}
	int parseLogLine();
};


#endif /* FLOWTRACK_H_ */
