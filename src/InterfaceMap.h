/*
 * InterfaceMap.h
 *
 *  Created on: Jun 4, 2017
 *      Author: steven
 */

#ifndef INTERFACEMAP_H_
#define INTERFACEMAP_H_

#include <unordered_set>
#include <unordered_map>
#include <fstream>

#include <net/if.h>
#include "syslog.h"

class InterfaceMap {
private:
	std::unordered_map<uint32_t, std::string> lanInterfaceMap;
	std::unordered_map<uint32_t, std::string> wanInterfaceMap;
	bool Debug;

	bool LoadInterfaces (std::unordered_set<std::string> &set, std::unordered_map<uint32_t, std::string> &map) {
	    set.clear();
        uint32_t index;
        bool failure = false;
        for (auto i : set) {
            if (Debug == true) {
                syslog(LOG_DEBUG, "InterfaceMap: Looking up interface %s", i.c_str());
            }
            if ((index = if_nametoindex(i.c_str())) > 0) {
                if (Debug == true) {
                    syslog(LOG_DEBUG, "Interface: %s -> Index %d", i.c_str(), index);
                }
                map[index] = i;
            } else {
                syslog (LOG_ERR, "Can't find interface %s", i.c_str());
                failure = true;
            }
        }
        return failure;
	}

public:
	InterfaceMap (bool inDebug = false): Debug{inDebug} {};
	InterfaceMap(std::unordered_set<std::string> inLanInterfaces, std::unordered_set<std::string> inWanInterfaces, bool inDebug = false): Debug{inDebug} {
		if (Debug == true) {
		    syslog (LOG_DEBUG, "InterfaceMap: constructing instance");
		}
	    Load(inLanInterfaces, inWanInterfaces);
	}
	~InterfaceMap() {
	    if (Debug == true) {
	        syslog (LOG_DEBUG, "InterfaceMap: deleting instance");
	    }
	};

	bool Load (std::unordered_set<std::string> &inLanInterfaces, std::unordered_set<std::string> &inWanInterfaces) {
		if (Debug == true) {
		    syslog (LOG_DEBUG, "InterfaceMap: loading interfaces");
		}
	    bool failure = false;
		failure |= LoadInterfaces(inLanInterfaces, lanInterfaceMap);
        failure |= LoadInterfaces(inWanInterfaces, wanInterfaceMap);
		return failure;
	}
	bool isLanInterface (int ifIndex) {
		if (lanInterfaceMap.find(ifIndex) == lanInterfaceMap.end()) {
			return false;
		}
		return true;
	}
	bool isWanInterface (int ifIndex) {
		if (wanInterfaceMap.find(ifIndex) == wanInterfaceMap.end()) {
			return false;
		}
		return true;
	}
};

#endif /* INTERFACEMAP_H_ */
