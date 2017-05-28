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
 *      Author: steven
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
	std::string ClientApiCertFile = "/etc/noddos/noddosapiclient.pem";
	std::string ClientApiKeyFile = "/etc/noddos/noddosapiclient.key";
	// std::string ClientApiCertFingerprint = "";
	std::string SignatureCertFile = "/etc/noddos/noddossignature.pem";
	std::string PidFile = "/var/lib/noddos/noddos.pid";
	std::string DnsmasqLogFile = "/var/log/dnsmasq.log";
	std::string User = "";
	std::string Group = "";
	std::unordered_set<std::string> WhitelistedIpv4Addresses;
	std::unordered_set<std::string> WhitelistedIpv6Addresses;
	std::unordered_set<std::string> WhitelistedMacAddresses;
	std::unordered_set<std::string> ListenIpAddresses;
	std::unordered_set<std::string> ListenInterfaces;
	std::time_t TrafficReportInterval = 3600; // Value in seconds, use 0 if no traffic stats should be uploaded
	std::time_t DeviceReportInterval = 14400; // Value in seconds, use 0 if no device stats should be uploaded
	bool ReportTrafficToRfc1918 = false;
	std::time_t MatchInterval = 300;
	std::time_t PruneInterval = 3600;
	std::time_t ExpireDnsQuery = 86400;
	std::time_t ExpireHost = 604800;
	UploadMode uMode = Anonymous;
	bool Debug;
	static const std::string ApiFqdn;

	Config(std::string inConfigFile = "/etc/noddos/noddos.conf", bool inDebug = false): Debug{inDebug} {
		Load(inConfigFile);
	}
	~Config() {
		if (Debug) {
			syslog (LOG_DEBUG, "Destroying Config instance");
		}
	}
	bool Load(std::string inConfigFile) {
		if (Debug == true) {
			syslog(LOG_DEBUG, "Opening & reading config file %s", inConfigFile.c_str());
		}
		bool configfailure=false;

		std::ifstream ifs(inConfigFile);
		if (!ifs.is_open()) {
			syslog(LOG_CRIT, "Couldn't open %s", inConfigFile.c_str());
			configfailure = true;
		}
		std::string newDeviceProfilesFile = DeviceProfilesFile;
		std::string newMatchFile = DeviceProfilesFile;
		std::string newDumpFile = DumpFile;
		std::string newClientApiCertFile = ClientApiCertFile;
		std::string newClientApiKeyFile = ClientApiKeyFile;
		std::string newSignatureCertFile = SignatureCertFile;
		std::string newPidFile = PidFile;
		std::string newDnsmasqLogFile = DnsmasqLogFile;
		std::string newUser = User;
		std::string newGroup = Group;
		std::unordered_set<std::string> newWhitelistedIpv4Addresses = WhitelistedIpv4Addresses;
		std::unordered_set<std::string> newWhitelistedIpv6Addresses = WhitelistedIpv6Addresses;
		std::unordered_set<std::string> newWhitelistedMacAddresses = WhitelistedMacAddresses;
		std::unordered_set<std::string> newListenIpAddresses = ListenIpAddresses;
		std::unordered_set<std::string> newListenInterfaces = ListenInterfaces;
		time_t newTrafficReportInterval = TrafficReportInterval;
		time_t newDeviceReportInterval = DeviceReportInterval;
		bool newReportTrafficToRfc1918 = ReportTrafficToRfc1918;
		time_t newMatchInterval = MatchInterval;
		time_t newPruneInterval = PruneInterval;
		time_t newExpireDnsQuery = ExpireDnsQuery;
		time_t newExpireHost = ExpireHost;
		UploadMode newuMode = uMode;

		json j;
		ifs >> j;
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
			if (j.count("ClientApiCertFile")) {
				newClientApiCertFile = j["ClientApiCertFile"].get<std::string>();
			}
			if (j.count("ClientApiKeyFile")) {
				newClientApiKeyFile = j["ClientApiKeyFile"].get<std::string>();
			}
			if (j.count("SignatureCertFile")) {
				newSignatureCertFile = j["SignatureCertFile"].get<std::string>();
			}
			if (j.count("PidFile")) {
				newPidFile = j["PidFile"].get<std::string>();
			}
			if (j.count("DnsmasqLogFile")) {
				newDnsmasqLogFile = j["DnsmasqLogFile"].get<std::string>();
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
			// FIXME: ListenIpAddresses not currently implemented (for multicast joins)
			if (j.count("ListenIpAddresses")) {
				newListenIpAddresses = j["ListenIpAddresses"].get<std::unordered_set<std::string>>();
			}
			// FIXME: ListenInterfaces not currently implemented (for multicast joins)
			if (j.count("ListenInterfaces")) {
				newListenInterfaces = j["ListenInterfaces"].get<std::unordered_set<std::string>>();
			}
			if (j.count("TrafficReportInterval")) {
				newTrafficReportInterval= j["TrafficReportInterval"].get<uint32_t>();
			}
			if (j.count("DeviceReportInterval")) {
				newDeviceReportInterval= j["DeviceReportInterval"].get<uint32_t>();
			}
			if (j.count("ReportTrafficToRfc1918")) {
				newReportTrafficToRfc1918 = j["ReportTrafficToRfc1918"].get<bool>();
			}
			if (j.count("PruneInterval")) {
				newPruneInterval= j["PruneInterval"].get<uint32_t>();
			}
			if (j.count("MatchInterval")) {
				newMatchInterval= j["MatchInterval"].get<uint32_t>();
			}
			if (j.count("ExpireDnsQuery")) {
				newExpireDnsQuery= j["ExpireDnsQuery"].get<uint32_t>();
			}
			if (j.count("ExpireHost")) {
				newExpireHost= j["ExpireHost"].get<uint32_t>();
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
		}
		catch (...) {
			syslog (LOG_ERR, "Failure to load configuration file, ignoring its contents");
			return configfailure;
		}
		DeviceProfilesFile = newDeviceProfilesFile;
		MatchFile = newMatchFile;
		DumpFile = newDumpFile;
		ClientApiCertFile = newClientApiCertFile;
		ClientApiKeyFile = newClientApiKeyFile;
		// ClientApiCertFingerprint = getCertFingerprint(ClientApiCertFile, Debug);
		// if (Debug) {
		//	syslog (LOG_DEBUG, "Certificate fingerprint %s", ClientApiCertFingerprint.c_str());
		// }
		SignatureCertFile = newSignatureCertFile;
		PidFile = newPidFile;
		DnsmasqLogFile = newDnsmasqLogFile;
		User = newUser;
		Group = newGroup;
		WhitelistedIpv4Addresses = newWhitelistedIpv4Addresses;
		WhitelistedIpv6Addresses = newWhitelistedIpv6Addresses;
		WhitelistedMacAddresses = newWhitelistedMacAddresses;
		ListenIpAddresses = newListenIpAddresses;
		ListenInterfaces = newListenInterfaces;
		TrafficReportInterval = newTrafficReportInterval;
		DeviceReportInterval = newDeviceReportInterval;
		ReportTrafficToRfc1918 = newReportTrafficToRfc1918;
		MatchInterval = newMatchInterval;
		PruneInterval = newPruneInterval;
		ExpireDnsQuery = newExpireDnsQuery;
		ExpireHost = newExpireHost;
		uMode = newuMode;
		return configfailure;
	}

};

#endif /* CONFIG_H_ */
