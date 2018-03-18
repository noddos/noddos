/*
 * InterfaceMap.h
 *
 *  Created on: Jun 4, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef INTERFACEMAP_H_
#define INTERFACEMAP_H_

#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <fstream>

#include <net/if.h>
#include "glog/logging.h"

class InterfaceMap {
private:
	std::unordered_map<uint32_t, std::string> lanInterfaceMap;
	std::unordered_map<uint32_t, std::string> wanInterfaceMap;
	bool Debug;

	bool LoadInterfaces (std::unordered_set<std::string> &set, std::unordered_map<uint32_t, std::string> &map) {
	    map.clear();
        uint32_t index;
        bool failure = false;
        for (auto i : set) {
            DLOG_IF(INFO, Debug) << "InterfaceMap: Looking up interface " << i;
            if ((index = if_nametoindex(i.c_str())) > 0) {
                DLOG_IF(INFO, Debug) << "Interface: " << i << " -> Index " << index;
                map[index] = i;
            } else {
                LOG(ERROR) << "Can't find interface " << i;
                failure = true;
            }
        }
        return failure;
	}

public:
	InterfaceMap (bool inDebug = false): Debug{inDebug} {};
	InterfaceMap(std::unordered_set<std::string> inLanInterfaces, std::unordered_set<std::string> inWanInterfaces, bool inDebug = false): Debug{inDebug} {
		DLOG_IF(INFO, Debug) << "InterfaceMap: constructing instance";
	    Load(inLanInterfaces, inWanInterfaces);
	}
	~InterfaceMap() {
	    DLOG_IF(INFO, Debug) << "InterfaceMap: deleting instance";
	};

	bool Load (std::unordered_set<std::string> &inLanInterfaces, std::unordered_set<std::string> &inWanInterfaces) {
		DLOG_IF(INFO, Debug) << "InterfaceMap: loading interfaces";
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
	std::vector<std::string> getLanInterfaces() {
	    std::vector<std::string> ifaces;
	    for (auto iface: lanInterfaceMap) {
	        ifaces.push_back(iface.second);
	    }
	    return ifaces;

	}
};

#endif /* INTERFACEMAP_H_ */
