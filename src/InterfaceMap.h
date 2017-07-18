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

public:
	InterfaceMap (bool inDebug = false): Debug{inDebug} {};
	InterfaceMap(std::unordered_set<std::string> inLanInterfaces, std::unordered_set<std::string> inWanInterfaces, bool inDebug = false): Debug{inDebug} {
		Load(inLanInterfaces, inWanInterfaces);
	}
	~InterfaceMap() {};

	bool Load (std::unordered_set<std::string> inLanInterfaces, std::unordered_set<std::string> inWanInterfaces) {
		bool failure = false;
		// We may have received SIGHUP so clear the interface map first if interfaces in the system has changed
		lanInterfaceMap.clear();
		wanInterfaceMap.clear();
		uint32_t index;
		{
			for (auto i : inLanInterfaces) {
				if ((index = if_nametoindex(i.c_str())) > 0) {
					if (Debug == true) {
						syslog(LOG_DEBUG, "Interface: %s -> Index %d", i.c_str(), index);
					}
					lanInterfaceMap[index] = i;
				} else {
					syslog (LOG_ERR, "Can't find LAN interface %s", i.c_str());
					failure = true;
				}
			}
		}
		{
			for (auto i : inWanInterfaces) {
				if ((index = if_nametoindex(i.c_str())) > 0) {
					if (Debug == true) {
						syslog(LOG_DEBUG, "Interface: %s -> Index %d", i.c_str(), index);
					}
					wanInterfaceMap[index] = i;
				} else {
					syslog (LOG_ERR, "Can't find WAN interface %s", i.c_str());
					failure = true;
				}
			}
		}
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
