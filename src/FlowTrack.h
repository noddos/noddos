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
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef FLOWTRACK_H_
#define FLOWTRACK_H_


#include <ctime>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

#include <glog/logging.h>

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include "iDeviceInfoSource.h"
#include "HostCache.h"

int netfilter_cb2(const struct nlmsghdr *nlh, enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data);
int netfilter_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data);

/*! \struct Flow
 *  \brief tracks a connection between a source and a destination
 */
struct Flow {
    struct sockaddr_storage src, dst;
    uint8_t flowstatus;
    uint8_t connectionstatus;
    uint8_t protocol;

};

/*! \class FlowTrack
 *  \brief Tracks communication flows between pairs of hosts using the NetFilter Connection Tracking feature
 *  FlowTrack uses either /proc/net/nf_conntrack or the nfct libraries to track flows between hosts. The latter
 *  requires root privileges but allows kernel-level filters to specify which flows will be reported to userspace
 *  FlowTrack implements the iDeviceInfoSource interface so can be used to asyncronously receive messages, process
 *  these and update the HostCache
 */
class FlowTrack : public iDeviceInfoSource {
private:
    struct nfct_handle *h = nullptr;
    struct nfct_filter *filter = nullptr;
    HostCache &hC; //!< Reference to the HostCache
    const Config &config; //!< Reference to the Noddos configuration
    bool useNfct = false; //!< is NFCT used (true) or /proc/net/nf_conntrack (false)
    FILE * ctFilePointer = nullptr; //!< Filepointer to /proc/net/nf_conntrack
    bool Debug = false; //!< Log debug messages?
    std::set<std::string> localIpAddresses; //!< List of local IP addresses used to filter out NFCT messages

public:
    /*! \brief Constructer for FlowTrack
     *
     */
	FlowTrack(HostCache & inhC, Config &inConfig,std::set<std::string> & inlocalIpAddresses):
	        hC{inhC}, config{inConfig}, Debug{inConfig.Debug && inConfig.DebugFlowTrack}, localIpAddresses{inlocalIpAddresses} {
        DLOG_IF(INFO, Debug) << "constructing instance";
	}

    /*! \brief Destructor for FlowTrack
     *
     */
	virtual ~FlowTrack() {
	    Close();
	    DLOG_IF(INFO, Debug) << "destructing instance";
	}

	// iDeviceInfoSource interface methods

	/*! \brief Open either /proc/net/nf_conntrack or call NFCT SDK otherwise
	 * If /proc/net/nf_conntrack is available and UseNfConntrack is True in the Noddos configuration file then user it
	 * Otherwise use NFCT SDK
	 */
	virtual int Open (std::string input = "", uint32_t inExpiration = 0) {
	    DLOG_IF(INFO, Debug) << "open";
	    // We don't care about Open parameters in this Class derived from iDeviceInfoSource
	    input = "";
	    inExpiration = 0;

	    struct stat buf;
	    if (config.UseNfConntrack == true && stat ("/proc/net/nf_conntrack", &buf) == 0) {
	        DLOG_IF(INFO, Debug) << "/proc/net/nf_conntrack exists, using it";
	        if ((ctFilePointer = fopen ("/proc/net/nf_conntrack","r")) != NULL) {
	            int flags;
	            int nf_fd = fileno(ctFilePointer);
	            if (-1 == (flags = fcntl(nf_fd, F_GETFL, 0)))
	                flags = 0;
	            if (fcntl(nf_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
	                PLOG(ERROR) << "Set O_NONBLOCK on conntrack log file";
	                throw std::system_error(errno, std::system_category());
	            } else {
	                useNfct = false;
	                return 0;
	            }
	        }
	    }
	    // Use NFCT SDK
	    useNfct = true;

	    LOG_IF(INFO, Debug) << "Opening NFCT";

	    h = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW |
	            NF_NETLINK_CONNTRACK_UPDATE);
	    if (!h) {
	        PLOG(ERROR) << "nfct_open";
	        throw std::system_error(errno, std::system_category());
	    }
	    int on = 1;

	    if (setsockopt(nfct_fd(h), SOL_NETLINK, NETLINK_BROADCAST_SEND_ERROR, &on, sizeof(int)) == -1) {
	        PLOG(ERROR) << "setsockopt NETLINK_BROADCAST_SEND_ERROR";
	        throw std::system_error(errno, std::system_category());
	    }

	    if (setsockopt(nfct_fd(h), SOL_NETLINK, NETLINK_NO_ENOBUFS, &on, sizeof(int)) == -1) {
	        PLOG(ERROR) << "setsockopt NETLINK_NO_ENOBUFS";
	        throw std::system_error(errno, std::system_category());
	    }

	    filter = nfct_filter_create();
	    if (!filter) {
	        PLOG(ERROR) << "nfct_create_filter";
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

	    std::unordered_set<std::string> ignoreIpAddresses = config.WhitelistedIpv4Addresses;
	    for (auto ipaddress: localIpAddresses) {
	        try {
	            Tins::IPv4Address a(ipaddress);
	            ignoreIpAddresses.insert(ipaddress);
	        } catch (...) {}
	    }
	    for (auto it: ignoreIpAddresses) {
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
	        PLOG(ERROR) << "nfct_filter_attach";
	        throw std::system_error(errno, std::system_category());
	    }

	    nfct_callback_register(h, NFCT_T_ALL, netfilter_cb, &hC);

	    DLOG_IF(INFO, Debug) << "open competed succesfully";

	    return 0;
	}

	/*! \brief Close either the file handle to /proc/net/nf_conntract or the NFCT file handle
	 *
	 */
	virtual bool Close () {
	    if (useNfct == false) {
	        if (ctFilePointer == nullptr) {
	            LOG(WARNING) << "Closing closed conntrack file pointer";
	            return false;
	        }
	        DLOG_IF(INFO, config.DebugFlowTrack) << "Closing conntrack file pointer";
	        return fclose(ctFilePointer);
	    }
	    // useNfct == true
	    if (h == nullptr) {
	        LOG(WARNING) << "Closing closed conntrack handler";
	        return false;
	    }
	    DLOG_IF(INFO, config.DebugFlowTrack) << "Closing conntrack handler";
	    // valgrind thinks nfct_close is buggy
	    // return nfct_close(h);
	    return true;
	}

	/*! \brief Return the file handle
	 *  \return file handle for the object
	 */
	virtual int getFileHandle() {
	    if (useNfct == false) {
	        return fileno(ctFilePointer);
	    }
	    return nfct_fd(h);
	}

	/* \brief Process an event that occured during epoll on the filehandle
	 * \param [in] event constant reference to a struct epoll_event object
	 * \return always true
	 */
	virtual bool processEvent(struct epoll_event &event) {
	    char buf [24];
	    auto rawtime = time (nullptr);
	    struct tm * timeinfo = localtime (&rawtime);
	    strftime (buf, 20, "%x %X", timeinfo);

	    int rt = -1;
	    if (useNfct == true) {
	        rt = nfct_catch(h);
	        if (rt < 0) {
	            PLOG(ERROR) << "nfct_catch";
	        }
	        DLOG_IF(INFO, config.DebugFlowTrack) << "Conntrack event read at " << buf << " with status " << rt;
	    } else {
	        while ((parseLogLine()) > -1) {}
	    }
	    return true;
	}
	int parseLogLine();
};

#endif /* FLOWTRACK_H_ */
