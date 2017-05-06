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
    struct nfct_handle *h;
    struct nfct_filter *filter;
    HostCache &hC;
    const Config &config;

public:
	FlowTrack(HostCache & inhC, Config &inConfig): hC{inhC}, config{inConfig} {
		h = nullptr;
		Open();
	}
	virtual int Open (std::string input = "", uint32_t inExpiration = 0) {
		// We don't care about Open parameters in this Class derived from iDeviceInfoSource
		input = "";
		inExpiration = 0;

		if (config.Debug) {
			syslog (LOG_DEBUG, "Opening NFCT");
		}

        h = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW |
                                 NF_NETLINK_CONNTRACK_UPDATE);
        if (!h) {
            perror ("nfct_open");
       		syslog(LOG_ERR, "nfct_open");
            exit(1);
            return -1;
        }

        filter = nfct_filter_create();
        if (!filter) {
                syslog(LOG_ERR, "nfct_create_filter");
                return -1;
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
                return -1;
        }

        nfct_callback_register(h, NFCT_T_ALL, netfilter_cb, &hC);

        return 0;
	}

	virtual ~FlowTrack() {
		Close();
		if (config.Debug) {
			syslog (LOG_DEBUG, "Destroying FlowTrack instance");
		}
	}
	// iDeviceInfoSource interface methods
	virtual bool Close () {
		if (!h) {
			syslog(LOG_WARNING, "Closing closed conntrack handler");
			return -1;
		}
		if (config.Debug) {
			syslog(LOG_DEBUG, "Closing conntrack handler");
		}
		return nfct_close(h);
	}

	virtual int GetFileHandle() { return nfct_fd(h); }

	virtual bool ProcessEvent(struct epoll_event &event) {
		auto rt = nfct_catch(h);
		if (rt < 0) {
			syslog(LOG_ERR, "nfct_catch: %s ", strerror(errno));
		}
		char buf [24];
		auto rawtime = time (nullptr);
		struct tm * timeinfo = localtime (&rawtime);
		strftime (buf, 20, "%x %X", timeinfo);
		if (config.Debug) {
			syslog(LOG_DEBUG, "Conntrack event read at %s with status %d", buf, rt);
		}
        return true;
	}
};


#endif /* FLOWTRACK_H_ */
