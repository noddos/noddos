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

#include <yaml-cpp/yaml.h>
// #include <json.hpp>
// using nlohmann::json;

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
	bool Debug, DebugHostCache, DebugFlowTrack, DebugDhcp, DebugDns, DebugSsdp,
	    DebugWsDiscovery, DebugMdns, DebugPacketSnoop, DebugTcpSnoop, DebugEvents;
	static const std::string ApiFqdn;

    Config(bool inDebug = false): Debug{inDebug} {
        if (Debug == true) {
            syslog (LOG_DEBUG, "Config: constructing instance");
        }
        DebugHostCache = DebugFlowTrack = DebugDhcp = DebugDns = DebugSsdp =
                DebugWsDiscovery = DebugMdns = DebugPacketSnoop = DebugTcpSnoop = DebugEvents = false;
    }
    Config(std::string inConfigFile, bool inDebug = false): Debug{inDebug} {
		if (Debug == true) {
		    syslog (LOG_DEBUG, "Config: constructing instance");
		}
		DebugHostCache = DebugFlowTrack = DebugDhcp = DebugDns = DebugSsdp =
		        DebugWsDiscovery = DebugMdns = DebugPacketSnoop = DebugTcpSnoop = DebugEvents = false;
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

		YAML::Node config  = YAML::LoadFile(inConfigFile);

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
		bool newDebugEvents = DebugEvents;

		// json j;

		try {
			if (config["DeviceProfilesFile"]) {
				newDeviceProfilesFile = config["DeviceProfilesFile"].as<std::string>();
			}
			if (config["MatchFile"]) {
				newMatchFile = config["MatchFile"].as<std::string>();
			}
			if (config["DumpFile"]) {
				newDumpFile = config["DumpFile"].as<std::string>();
			}
            if (config["DnsCacheFile"]) {
                newDnsCacheFile = config["DnsCacheFile"].as<std::string>();
            }
			if (config["ClientApiCertFile"]) {
				newClientApiCertFile = config["ClientApiCertFile"].as<std::string>();
			}
			if (config["ClientApiKeyFile"]) {
				newClientApiKeyFile = config["ClientApiKeyFile"].as<std::string>();
			}
			if (config["SignatureCertFile"]) {
				newSignatureCertFile = config["SignatureCertFile"].as<std::string>();
			}
            if (config["FirewallRulesFile"]) {
                newFirewallRulesFile = config["FirewallRulesFile"].as<std::string>();
            }
            if (config["FirewallBlockTraffic"]) {
                 newFirewallBlockTraffic = config["FirewallBlockTraffic"].as<bool>();
            }
            if (config["PidFile"]) {
				newPidFile = config["PidFile"].as<std::string>();
			}
			if (config["UseNfConntrack"]) {
				newUseNfConntrack = config["UseNfConntrack"].as<bool>();
			}
			if (config["User"]) {
				newUser = config["User"].as<std::string>();
			}
			if (config["Group"]) {
				newGroup = config["Group"].as<std::string>();
			}
			if (config["WhitelistedIpv4Addresses"].IsSequence()) {
			    for (YAML::const_iterator it=config["WhitelistedIpv4Addresses"].begin();it!=config["WhitelistedIpv4Addresses"].end();++it) {
			        newWhitelistedIpv4Addresses.emplace(it->as<std::string>());
			    }
			}
			if (config["WhitelistedIpv6Addresses"].IsSequence()) {
                for (YAML::const_iterator it=config["WhitelistedIpv6Addresses"].begin();it!=config["WhitelistedIpv6Addresses"].end();++it) {
                    newWhitelistedIpv6Addresses.emplace(it->as<std::string>());
                }
			}
			if (config["WhitelistedMacAddresses"].IsSequence()) {
                for (YAML::const_iterator it=config["WhitelistedMacAddresses"].begin();it!=config["WhitelistedMacAddresses"].end();++it) {
                    newWhitelistedMacAddresses.emplace(it->as<std::string>());
                }
			}
			if (config["LanInterfaces"].IsSequence()) {
                for (YAML::const_iterator it=config["LanInterfaces"].begin();it!=config["LanInterfaces"].end();++it) {
                    newLanInterfaces.emplace(it->as<std::string>());
                }
			}
			if (config["WanInterfaces"].IsSequence()) {
                for (YAML::const_iterator it=config["WanInterfaces"].begin();it!=config["WanInterfaces"].end();++it) {
                    newWanInterfaces.emplace(it->as<std::string>());
                }
			}
            if (config["WsDiscoveryProbeInterval"]) {
                newWsDiscoveryProbeInterval = config["WsDiscoveryProbeInterval"].as<uint32_t>();
            }
			if (config["TrafficReportInterval"]) {
				newTrafficReportInterval = config["TrafficReportInterval"].as<uint32_t>();
			}
			if (config["DeviceReportInterval"]) {
				newDeviceReportInterval = config["DeviceReportInterval"].as<uint32_t>();
			}
			if (config["ReportTrafficToRfc1918"]) {
				newReportTrafficToRfc1918 = config["ReportTrafficToRfc1918"].as<bool>();
			}
			if (config["PruneInterval"]) {
				newPruneInterval = config["PruneInterval"].as<uint32_t>();
			}
			if (config["MatchInterval"]) {
				newMatchInterval = config["MatchInterval"].as<uint32_t>();
			}
			if (config["ExpireHost"]) {
				newExpireHost = config["ExpireHost"].as<uint32_t>();
			}
			// FIXME: upload mode not currently implemented
			if (config["UploadMode"]) {
				auto v = config["UploadMode"].as<std::string>();
				if (v == "Account") {
					newuMode = Account;
				} else if (v == "Anonymous") {
					newuMode = Anonymous;
				}
			}
            if (config["DebugHostCache"]) {
                newDebugHostCache = config["DebugHostCache"].as<bool>();
            }
            if (config["DebugFlowTrack"]) {
                newDebugFlowTrack = config["DebugFlowTrack"].as<bool>();
            }
            if (config["DebugSsdp"]) {
                newDebugSsdp = config["DebugSsdp"].as<bool>();
            }
            if (config["DebugWsDiscovery"]) {
                newDebugWsDiscovery = config["DebugWsDiscovery"].as<bool>();
            }
            if (config["DebugMdns"]) {
                newDebugMdns = config["DebugMdns"].as<bool>();
            }
            if (config["DebugPacketSnoop"]) {
                newDebugPacketSnoop = config["DebugPacketSnoop"].as<bool>();
            }
            if (config["DebugEvents"]) {
                newDebugEvents = config["DebugEvents"].as<bool>();
            }
		}
		catch (...) {
			syslog (LOG_ERR, "Config: Failure to parse yaml data from Config file, ignoring its contents: %s", inConfigFile.c_str());
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
        DebugEvents = newDebugEvents;
		return configfailure;
	}

};

#endif /* CONFIG_H_ */
