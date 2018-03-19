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

 * FlowTrack.cxx
 *
 *  Created on: Mar 19, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#include <regex>
#include <string>
#include <iostream>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include <cstdio>

#include <glog/logging.h>

#include "FlowTrack.h"
#include "HostCache.h"

/*! \function netfilter_cb2
 *  WARNING: dead code, this function is currently not used. For nfct, netfilter_cb is used
 */
int netfilter_cb2(const struct nlmsghdr *nlh, enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
	HostCache & hC = *(static_cast<HostCache *>(data));
	// TODO: parse protocols other than TCP and UDP, i.e. ICMP
	static const auto ct_rx = std::regex(R"delim(^\s+?\[(\w+?)\]\s+?(\w+?)\s+?(\d+?)\s+?(\d+?)\s+?(\S+?)?\s*src=(\S+?)\s+?dst=(\S+?)\s+?sport=(\d+?)\s+?dport=(\d+?)\s+?(\[(\w+?)\])?.+(\[(\w+)\])?$)delim",
	        	std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);

	char buf[1024];
    nfct_snprintf(buf, sizeof(buf), ct, type, NFCT_O_PLAIN, NFCT_OF_TIME);
    std::string line = buf;
	std::smatch m;
	if (std::regex_search(line, m, ct_rx)) {
		// std::string connstatus = m.str(1);
		// std::string protocol = m.str(2);
		uint8_t protocol = std::stoi(m.str(3));
		uint32_t expiration = std::stoi(m.str(4));
		// std::string flowstatus = m.str(5);
		std::string srcip = m.str(6);
		std::string dstip = m.str(7);
		uint16_t srcport = std::stoi(m.str(8));
		uint16_t dstport = std::stoi(m.str(9));
		// std::string bidirectional = m.str(10);
		// std::string assured = m.str(12);
		DLOG_IF(INFO, hC.getDebug()) << "Flowtrack matched " << srcip << ":" << srcport << " "
		        << dstip << ":" << dstport << " protcol " << protocol
		        << " expiration " << expiration;
		hC.addFlow(srcip, srcport, dstip, dstport, protocol, expiration);
	} else {
	    DLOG_IF(INFO, hC.getDebug()) << "not matched " << line;
	}

    // return NFCT_CB_CONTINUE;
	return NFCT_CB_STOP;
}

/*! \function netfilter_cb
 * Call-back function for NFCT to pass messages. For that reason, it can't be a method of a class.
 * The call-back is registered in FlowTrack::Open
 * \param [in] type enum of nf_conntrack_msg_type
 * \param [in] ct poiter to struct nf_conntrack object
 * \param [out] data void * that will be statically case to a reference to class HostCache object
 * \return integer NFCT_CB_STOP
 */
int netfilter_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
	HostCache & hC = *(static_cast<HostCache *>(data));
	// TODO: parse protocols other than TCP and UDP, i.e. ICMP
	static const auto ct_rx = std::regex(R"delim(^\s+?\[(\w+?)\]\s+?(\w+?)\s+?(\d+?)\s+?(\d+?)\s+?(\S+?)?\s*src=(\S+?)\s+?dst=(\S+?)\s+?sport=(\d+?)\s+?dport=(\d+?)\s+?(\[(\w+?)\])?.+(\[(\w+)\])?$)delim",
	        	std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);

	char buf[1024];
    nfct_snprintf(buf, sizeof(buf), ct, type, NFCT_O_PLAIN, NFCT_OF_TIME);
    std::string line = buf;
	std::smatch m;
	if (std::regex_search(line, m, ct_rx)) {
		// std::string connstatus = m.str(1);
		// std::string protocol = m.str(2);
		uint8_t protocol = std::stoi(m.str(3));
		uint32_t expiration = std::stoi(m.str(4));
		// std::string flowstatus = m.str(5);
		std::string srcip = m.str(6);
		std::string dstip = m.str(7);
		uint16_t srcport = std::stoi(m.str(8));
		uint16_t dstport = std::stoi(m.str(9));
		// std::string bidirectional = m.str(10);
		// std::string assured = m.str(12);
        DLOG_IF(INFO, hC.getDebug()) << "Flowtrack matched " << srcip << ":" << srcport << " "
                << dstip << ":" << dstport << " protcol " << protocol
                << " expiration " << expiration;
		hC.addFlow(srcip, srcport, dstip, dstport, protocol, expiration);
	} else {
	    DLOG_IF(INFO, hC.getDebug()) << "not matched " << line;
	}

    // return NFCT_CB_CONTINUE;
	return NFCT_CB_STOP;
}

/*! \brief Parse line of /proc/net/nf_conntract
 *  \return 0 for success, -1 for read failure
 */
int FlowTrack::parseLogLine() {
	static const auto nf_rx = std::regex(R"delim(^(ipv\d)\s+?(\d+?)\s+?(\w+?)\s+?(\d+?)\s(\d+?)\s(\S+?)?\s?src=(\S+?)\s+dst=(\S+?)\s+sport=(\d+)\s+dport=(\d+))delim",
			std::regex_constants::ECMAScript | std::regex_constants::icase | std::regex_constants::optimize);
	char cline[300];
	if (fgets(cline, 300, ctFilePointer) == NULL) {
		PLOG(ERROR) << "fgets";
		return -1;
	}
	cline[strcspn(cline, "\n")] = 0;
	std::string line = cline;
	std::smatch m;
	if (std::regex_search(line, m, nf_rx)) {
		// std::string ipversion = m.str(1);
		uint8_t ipversionnumber = std::stoi(m.str(2));
		// std::string ipproto = m.str(3);
		uint8_t ipprotonumber= std::stoi(m.str(4));
		uint32_t expiration = std::stoi(m.str(5));
		// std::string flowstatus = m.str(6);
		std::string srcip = m.str(7);
		std::string dstip = m.str(8);
		uint16_t srcport = std::stoi(m.str(9));
		uint16_t dstport = std::stoi(m.str(10));
        DLOG_IF(INFO, hC.getDebug()) << "Flowtrack matched " << srcip << ":" << srcport << " "
                << dstip << ":" << dstport << " protcol " << ipprotonumber
                << " expiration " << expiration;
		hC.addFlow(srcip, srcport, dstip, dstport, ipprotonumber, expiration);
	} else {
        DLOG_IF(INFO, hC.getDebug()) << "not matched " << line;
	}
	return 0;
}
