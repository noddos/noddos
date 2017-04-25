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
 *      Author: steven
 */

#include <regex>
#include <string>
#include <iostream>
#include <syslog.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>


// #include <plog/Log.h>
#include "FlowTrack.h"

#include "HostCache.h"

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
		struct Flow f;
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
		if (hC.Debug_get()) {
			syslog(LOG_DEBUG, "Conntrack matched: %s:%u %s:%u %u expiration: %u", srcip.c_str(), srcport, dstip.c_str(), dstport, protocol, expiration);
		}
		hC.AddFlow(srcip, srcport, dstip, dstport, protocol, expiration);
	} else {
		if (hC.Debug_get()) {
			syslog(LOG_DEBUG, "Conntrack not matched: %s", line.c_str());
		}
	}

    // return NFCT_CB_CONTINUE;
	return NFCT_CB_STOP;
}

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
		struct Flow f;
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
		if (hC.Debug_get()) {
			syslog(LOG_DEBUG, "Conntrack matched: %s:%u - %s:%u %u exp %u", srcip.c_str(), srcport, dstip.c_str(), dstport, protocol, expiration);
		}
		hC.AddFlow(srcip, srcport, dstip, dstport, protocol, expiration);
	} else {
		if (hC.Debug_get()) {
			syslog(LOG_DEBUG, "Conntrack not matched: %s", line.c_str());
		}
	}

    // return NFCT_CB_CONTINUE;
	return NFCT_CB_STOP;
}

