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

 * Host_test.cxx
 *
 *  Created on: Mar 27, 2017
 *      Author: steven
 */

#include <iostream>
#include <memory>
#include <syslog.h>

#include "noddos.h"
#include "HostCache.h"
#include "Host.h"

static std::string deviceprofilesfile = "tests/DeviceProfiles.json";

int main () {

	openlog("Host_test", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
	HostCache hC;
	hC.DeviceProfiles_load(deviceprofilesfile);
	hC.AddByMac ("00:00:00:00:00:01", "192.168.1.232");
	hC.AddByMac ("00:00:00:00:00:02", "192.168.1.98");
	hC.AddByMac ("00:00:00:00:00:03", "192.168.1.99");
	hC.AddByMac ("00:00:00:00:00:04", "192.168.1.235");
	hC.AddByMac ("00:00:00:00:00:05", "192.168.1.241");
	hC.AddByMac ("00:00:00:00:00:05", "192.168.1.251");
	hC.AddByMac ("00:00:00:00:00:06", "192.168.1.234");
	hC.AddByMac ("00:00:00:00:00:07", "192.168.1.240");

	auto sh = std::make_shared<SsdpHost>();
	sh->IpAddress = "192.168.1.234";
	sh->Manufacturer = "Amazon.com, Inc.";
	sh->ModelName = "FireTV";
	hC.AddSsdpInfo(sh);

	auto res = hC.MatchByIpAddress("192.168.1.234");
	std::cout << "Host with SsdpManufacturer " << sh->Manufacturer << " and SsdpModelName " << sh->ModelName << " matched " << res << " times" << std::endl;

	auto dr = std::make_shared<DhcpRequest>();
	dr->DhcpHostname = "udhcp 0.9.9-pre";
	dr->IpAddress = "192.168.1.98";
	hC.AddDhcpRequest(dr);
	hC.AddDnsQueryIp("192.168.1.98", "control2.tvinteractive.tv", "1.1.1.1");
	hC.AddDnsQueryIp("192.168.1.98", "bis-tv-widgets.secure.yahoo.com", "1.1.1.2");
	auto res2 = hC.MatchByIpAddress("192.168.1.98");
	std::cout << "Host with DhcpHostname" << dr->DhcpHostname << " and DnsQuery for " << "control2.tvinteractive.tv" << " matched " << res2 << " times" << std::endl;

	hC.AddDnsQueryIp("192.168.1.241", "init.itunes.apple.com", "2.2.2.2");
	hC.AddDnsQueryIp("192.168.1.241", "apps.itunes.com", "2.2.2.3");
	hC.AddDnsQueryIp("192.168.1.241", "time-ios.g.aaplimg.com", "2.2.2.4");
	auto res3 = hC.MatchByIpAddress("192.168.1.241");
	std::cout << "Host with Dnsqueries init.itunes.apple.com apps.itunes.com apps.itunes.com matched " << res3 << " times" << std::endl;

	dr->DhcpHostname = "kindle-a40752280";
	dr->IpAddress = "192.168.1.251";
	hC.AddDhcpRequest(dr);
	hC.AddDnsQueryIp("192.168.1.251", "api.amazon.com", "1.1.1.5");
	auto res4 = hC.MatchByIpAddress("192.168.1.251");
	std::cout << "Host with DhcpHostname " << dr->DhcpHostname << " and DnsQuery for " << "api.amazon.com" << " matched " << res4 << " times" << std::endl;

	bool testfailed = false;
	auto h = Host("01:01:01:01:01:01", true);
	if (h.inRfc1918("11.0.0.0")) {
		std::cout << "11.0.0.0 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (h.inRfc1918("9.255.255.255")) {
		std::cout << "9.255.255.255 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (h.inRfc1918("172.15.255.255")) {
		std::cout << "172.15.255 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (h.inRfc1918("172.24.0.0")) {
		std::cout << "172.24.0.0 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (h.inRfc1918("192.167.255.255")) {
		std::cout << "192.167.255.255 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (h.inRfc1918("192.169.0.0")) {
		std::cout << "192.169.0.0 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (not h.inRfc1918("192.168.1.1")) {
		std::cout << "192.168.1.1 is RFC1918" << std::endl;
		testfailed = true;
	}
	if (not h.inRfc1918("172.20.1.1")) {
		std::cout << "172.20.1.1 is RFC1918" << std::endl;
		testfailed = true;
	}
	if (not h.inRfc1918("10.255.1.1")) {
		std::cout << "10.255.1.1 is RFC1918" << std::endl;
		testfailed = true;
	}
	if (testfailed) {
		exit(1);
	}
	return 0;
}


