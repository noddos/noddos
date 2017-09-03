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

 * FlowEntry.h
 *
 *  Created on: Mar 22, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef FLOWENTRY_H_
#define FLOWENTRY_H_


#include <syslog.h>

#include "iCache.h"
#include "noddos.h"

class FlowEntry : public iCache {
public:
	uint16_t DstPort;
	uint16_t SrcPort;
	uint8_t Protocol;
	bool Debug;

	FlowEntry(bool inDebug = false): Debug{inDebug}, SrcPort{0}, DstPort{0}, Protocol{0}
		{ setExpiration(); iCache::FirstSeen = iCache::LastSeen = iCache::LastModified = time(nullptr);};
	FlowEntry(uint16_t inSrcPort, uint16_t inDstPort, uint8_t inProtocol): SrcPort{inSrcPort}, DstPort{inDstPort}, Protocol{inProtocol}
		{ setExpiration(); iCache::FirstSeen = iCache::LastSeen = iCache::LastModified = time(nullptr);};
	bool operator == (const FlowEntry &rhs) const {
		return DstPort == rhs.DstPort &&
				SrcPort == rhs.SrcPort &&
				Protocol == rhs.Protocol;
	}
	uint32_t FlowStats (json & j, uint32_t time_interval) {
		if (! Fresh(time_interval))
			return 0;
		auto flowentries = 0;

		j["SrcPort"] = SrcPort;
		j["DstPort"] = DstPort;
		j["Protocol"] = Protocol;
		return 1;
	}
    // iCache interface methods.
    time_t setExpiration( time_t inExpiration = FLOWDEFAULTEXPIRATION) {
    	if (Debug == true) {
    		syslog (LOG_DEBUG, "Setting flow expiration to %ld", inExpiration);
    	}
    	return iCache::Expires = (time(nullptr) + inExpiration);
    }
    time_t getExpiration () { return iCache::Expires; }
    bool isExpired() {
    	auto n = time(nullptr);
    	if (Debug == true) {
    		syslog (LOG_DEBUG, "Now: %ld, expiration at %ld", n, iCache::Expires );
    	}
    	return n >= iCache::Expires;
    }

    uint32_t Prune (bool Force = false) {
    	return 0;
    }
};

#endif /* FLOWENTRY_H_ */
