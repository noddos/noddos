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

 * Config.h
 *
 *  Created on: Apr 3, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <string>
#include <unordered_set>
#include <ctime>
#include <vector>
#include <fstream>
#include <list>

#include <syslog.h>

#include <json.hpp>
using nlohmann::json;

// From opensslfingerprint.cxx (valgrind claims there is a memory leak)
// std::string getCertFingerprint(const std::string certfile, const bool Debug = false);

enum UploadMode {Anonymous, Account};

class Config {

public:
	std::string DeviceProfilesFile = "/var/lib/noddos/DeviceProfiles.json";
	std::string MatchFile = "/etc/noddos/DeviceMatches.json";
	std::string DumpFile = "/var/lib/noddos/DeviceDump.json";
    std::string DnsCacheFile = "/var/lib/noddos/DnsCache.json";
	std::string ClientApiCertFile = "/etc/noddos/noddosapiclient.pem";
	std::string ClientApiKeyFile = "/etc/noddos/noddosapiclient.key";
	std::string SignatureCertFile = "/etc/noddos/noddossignature.pem";
    std::string FirewallRulesFile = "/var/lib/noddos/iptables.rules";
    bool FirewallBlockTraffic = false;
	std::string PidFile = "/var/lib/noddos/noddos.pid";
	bool UseNfConntrack = false;
	std::string User = "";
	std::string Group = "";
	std::unordered_set<std::string> WhitelistedIpv4Addresses;
	std::unordered_set<std::string> WhitelistedIpv6Addresses;
	std::unordered_set<std::string> WhitelistedMacAddresses;
	std::unordered_set<std::string> LanInterfaces;
	std::unordered_set<std::string> WanInterfaces;
	std::time_t TrafficReportInterval = 3600; // Value in seconds, use 0 if no traffic stats should be uploaded
	std::time_t DeviceReportInterval = 14400; // Value in seconds, use 0 if no device stats should be uploaded
	bool ReportTrafficToRfc1918 = false;
	std::time_t WsDiscoveryProbeInterval = 3600;
	std::time_t MatchInterval = 300;
	std::time_t PruneInterval = 3600;
	std::time_t ExpireHost = 7776000;
	UploadMode uMode = Anonymous;
	bool Debug, DebugHostCache, DebugHost, DebugFlowTrack, DebugDhcp, DebugDns, DebugSsdp,
	    DebugWsDiscovery, DebugMdns, DebugPacketSnoop, DebugTcpSnoop;
	static const std::string ApiFqdn;

	Config(std::string inConfigFile = "/etc/noddos/noddos.conf", bool inDebug = false): Debug{inDebug} {
		if (Debug == true) {
		    syslog (LOG_DEBUG, "Config: constructing instance");
		}
		DebugHostCache = DebugHost = DebugFlowTrack = DebugDhcp = DebugDns = DebugSsdp =
		        DebugWsDiscovery = DebugMdns = DebugPacketSnoop = DebugTcpSnoop = false;
	    Load(inConfigFile);
	}
	~Config() {
		if (Debug) {
			syslog (LOG_DEBUG, "Config: destructing instance");
		}
	}
	bool Load(std::string inConfigFile) {
		if (Debug == true) {
			syslog(LOG_DEBUG, "Config: opening & reading config file %s", inConfigFile.c_str());
		}
		bool configfailure=false;

		std::ifstream ifs(inConfigFile);
		if (!ifs.is_open()) {
			syslog(LOG_CRIT, "Config: Couldn't open %s", inConfigFile.c_str());
			configfailure = true;
		}
		std::string newDeviceProfilesFile = DeviceProfilesFile;
		std::string newMatchFile = DeviceProfilesFile;
		std::string newDumpFile = DumpFile;
        std::string newDnsCacheFile = DnsCacheFile;
		std::string newClientApiCertFile = ClientApiCertFile;
		std::string newClientApiKeyFile = ClientApiKeyFile;
		std::string newSignatureCertFile = SignatureCertFile;
	    std::string newFirewallRulesFile = FirewallRulesFile;
	    bool newFirewallBlockTraffic = FirewallBlockTraffic;
	    std::string newPidFile = PidFile;
		bool newUseNfConntrack = UseNfConntrack;
		std::string newUser = User;
		std::string newGroup = Group;
		std::unordered_set<std::string> newWhitelistedIpv4Addresses = WhitelistedIpv4Addresses;
		std::unordered_set<std::string> newWhitelistedIpv6Addresses = WhitelistedIpv6Addresses;
		std::unordered_set<std::string> newWhitelistedMacAddresses = WhitelistedMacAddresses;
		std::unordered_set<std::string> newLanInterfaces = LanInterfaces;
		std::unordered_set<std::string> newWanInterfaces = WanInterfaces;
        time_t newWsDiscoveryProbeInterval = WsDiscoveryProbeInterval;
		time_t newTrafficReportInterval = TrafficReportInterval;
		time_t newDeviceReportInterval = DeviceReportInterval;
		bool newReportTrafficToRfc1918 = ReportTrafficToRfc1918;
		time_t newMatchInterval = MatchInterval;
		time_t newPruneInterval = PruneInterval;
		time_t newExpireHost = ExpireHost;
		UploadMode newuMode = uMode;
		bool newDebugHostCache = DebugHostCache;
		bool newDebugFlowTrack = DebugFlowTrack;
		bool newDebugSsdp = DebugSsdp;
		bool newDebugWsDiscovery = DebugWsDiscovery;
		bool newDebugMdns = DebugMdns;
		bool newDebugPacketSnoop = DebugPacketSnoop;

		json j;
	    try {
	        ifs >> j;
	    } catch (...) {
	        syslog (LOG_ERR, "HostCache: failed to parse Config json data from %s", inConfigFile.c_str());
	    }
		ifs.close();
		try {
			if (j.count("DeviceProfilesFile")) {
				newDeviceProfilesFile = j["DeviceProfilesFile"].get<std::string>();
			}
			if (j.count("MatchFile")) {
				newMatchFile = j["MatchFile"].get<std::string>();
			}
			if (j.count("DumpFile")) {
				newDumpFile = j["DumpFile"].get<std::string>();
			}
            if (j.count("DnsCacheFile")) {
                newDnsCacheFile = j["DnsCacheFile"].get<std::string>();
            }
			if (j.count("ClientApiCertFile")) {
				newClientApiCertFile = j["ClientApiCertFile"].get<std::string>();
			}
			if (j.count("ClientApiKeyFile")) {
				newClientApiKeyFile = j["ClientApiKeyFile"].get<std::string>();
			}
			if (j.count("SignatureCertFile")) {
				newSignatureCertFile = j["SignatureCertFile"].get<std::string>();
			}
            if (j.count("FirewallRulesFile")) {
                newFirewallRulesFile = j["FirewallRulesFile"].get<std::string>();
            }
            if (j.count("FirewallBlockTraffic")) {
                 newFirewallBlockTraffic = j["FirewallBlockTraffic"].get<bool>();
            }
            if (j.count("PidFile")) {
				newPidFile = j["PidFile"].get<std::string>();
			}
			if (j.count("UseNfConntrack")) {
				newUseNfConntrack = j["UseNfConntrack"].get<bool>();
			}
			if (j.count("User")) {
				newUser = j["User"].get<std::string>();
			}
			if (j.count("Group")) {
				newGroup = j["Group"].get<std::string>();
			}
			if (j.count("WhitelistedIpv4Addresses")) {
				newWhitelistedIpv4Addresses = j["WhitelistedIpv4Addresses"].get<std::unordered_set<std::string>>();
			}
			if (j.count("WhitelistedIpv6Addresses")) {
				newWhitelistedIpv6Addresses = j["WhitelistedIpv6Addresses"].get<std::unordered_set<std::string>>();
			}
			if (j.count("WhitelistedMacAddresses")) {
				newWhitelistedMacAddresses = j["WhitelistedMacAddresses"].get<std::unordered_set<std::string>>();
			}
			if (j.count("LanInterfaces")) {
				newLanInterfaces = j["LanInterfaces"].get<std::unordered_set<std::string>>();
			}
			if (j.count("WanInterfaces")) {
				newWanInterfaces = j["WanInterfaces"].get<std::unordered_set<std::string>>();
			}
            if (j.count("WsDiscoveryProbeInterval")) {
                newWsDiscoveryProbeInterval = j["WsDiscoveryProbeInterval"].get<uint32_t>();
            }
			if (j.count("TrafficReportInterval")) {
				newTrafficReportInterval = j["TrafficReportInterval"].get<uint32_t>();
			}
			if (j.count("DeviceReportInterval")) {
				newDeviceReportInterval = j["DeviceReportInterval"].get<uint32_t>();
			}
			if (j.count("ReportTrafficToRfc1918")) {
				newReportTrafficToRfc1918 = j["ReportTrafficToRfc1918"].get<bool>();
			}
			if (j.count("PruneInterval")) {
				newPruneInterval = j["PruneInterval"].get<uint32_t>();
			}
			if (j.count("MatchInterval")) {
				newMatchInterval = j["MatchInterval"].get<uint32_t>();
			}
			if (j.count("ExpireHost")) {
				newExpireHost = j["ExpireHost"].get<uint32_t>();
			}
			// FIXME: upload mode not currently implemented
			if (j.count("UploadMode")) {
				auto v = j["UploadMode"].get<std::string>();
				if (v == "Account") {
					newuMode = Account;
				} else if (v == "Anonymous") {
					newuMode = Anonymous;
				}
			}
            if (j.count("DebugHostCache")) {
                newDebugHostCache = j["DebugHostCache"].get<bool>();
            }
            if (j.count("DebugFlowTrack")) {
                newDebugFlowTrack = j["DebugFlowTrack"].get<bool>();
            }
            if (j.count("DebugSsdp")) {
                newDebugSsdp = j["DebugSsdp"].get<bool>();
            }
            if (j.count("DebugWsDiscovery")) {
                newDebugWsDiscovery = j["DebugWsDiscovery"].get<bool>();
            }
            if (j.count("DebugMdns")) {
                newDebugMdns = j["DebugMdns"].get<bool>();
            }
            if (j.count("DebugPacketSnoop")) {
                newDebugPacketSnoop = j["DebugPacketSnoop"].get<bool>();
            }
		}
		catch (...) {
			syslog (LOG_ERR, "Config: Failure to parse json data from Config file, ignoring its contents: %s", inConfigFile.c_str());
			return configfailure;
		}
		DeviceProfilesFile = newDeviceProfilesFile;
		MatchFile = newMatchFile;
		DumpFile = newDumpFile;
        DnsCacheFile = newDnsCacheFile;
		ClientApiCertFile = newClientApiCertFile;
		ClientApiKeyFile = newClientApiKeyFile;
		SignatureCertFile = newSignatureCertFile;
		FirewallRulesFile = newFirewallRulesFile;
		PidFile = newPidFile;
		UseNfConntrack = newUseNfConntrack;
		User = newUser;
		Group = newGroup;
		WhitelistedIpv4Addresses = newWhitelistedIpv4Addresses;
		WhitelistedIpv6Addresses = newWhitelistedIpv6Addresses;
		WhitelistedMacAddresses = newWhitelistedMacAddresses;
		LanInterfaces = newLanInterfaces;
		WanInterfaces = newWanInterfaces;
		WsDiscoveryProbeInterval = newWsDiscoveryProbeInterval;
		TrafficReportInterval = newTrafficReportInterval;
		DeviceReportInterval = newDeviceReportInterval;
		ReportTrafficToRfc1918 = newReportTrafficToRfc1918;
		MatchInterval = newMatchInterval;
		PruneInterval = newPruneInterval;
		ExpireHost = newExpireHost;
		uMode = newuMode;
        DebugHostCache = newDebugHostCache;
        DebugFlowTrack = newDebugFlowTrack;
        DebugSsdp = newDebugSsdp;
        DebugWsDiscovery = newDebugWsDiscovery;
        DebugMdns = newDebugMdns;
        DebugPacketSnoop = newDebugPacketSnoop;
		return configfailure;
	}

};

#endif /* CONFIG_H_ */
