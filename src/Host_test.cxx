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
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#include <iostream>
#include <memory>
#include <syslog.h>

#include "noddos.h"
#include "HostCache.h"
#include "Host.h"

static std::string deviceprofilesfile = "../tests/DeviceProfiles.json";

int main () {
	bool testfailed = false;
	openlog("Host_test", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
	InterfaceMap ifMap;
	HostCache hC(ifMap, "", 0, "", false, true);
	hC.loadDeviceProfiles(deviceprofilesfile);
	hC.AddByMac (MacAddress("00:00:00:00:00:01"), "192.168.1.232");
	hC.AddByMac (MacAddress("00:00:00:00:00:02"), "192.168.1.98");
	hC.AddByMac (MacAddress("00:00:00:00:00:03"), "192.168.1.99");
	hC.AddByMac (MacAddress("00:00:00:00:00:04"), "192.168.1.235");
	hC.AddByMac (MacAddress("00:00:00:00:00:05"), "192.168.1.241");
	hC.AddByMac (MacAddress("00:00:00:00:00:20"), "192.168.1.251");
	hC.AddByMac (MacAddress("00:00:00:00:00:06"), "192.168.1.234");
	hC.AddByMac (MacAddress("00:00:00:00:00:07"), "192.168.1.240");

	hC.AddByMac (MacAddress("00:00:00:00:00:08"), "192.168.1.227");
	hC.AddByMac (MacAddress("00:00:00:00:00:09"), "192.168.1.226");
	hC.AddByMac (MacAddress("00:00:00:00:00:10"), "192.168.1.80");
	hC.AddByMac (MacAddress("00:00:00:00:00:11"), "192.168.1.225");
	hC.AddByMac (MacAddress("00:00:00:00:00:12"), "192.168.1.242");
	hC.AddByMac (MacAddress("00:00:00:00:00:14"), "192.168.1.231");
	hC.AddByMac (MacAddress("00:00:00:00:00:15"), "192.168.1.133");
	hC.AddByMac (MacAddress("00:00:00:00:00:16"), "192.168.1.238");
	hC.AddByMac (MacAddress("00:00:00:00:00:17"), "192.168.1.146");
	hC.AddByMac (MacAddress("00:00:00:00:00:18"), "192.168.1.224");
	hC.AddByMac (MacAddress("00:00:00:00:00:19"), "192.168.1.239");

    hC.AddDhcpRequest("192.168.1.226", MacAddress("00:00:00:00:00:09"), "android-49e3daef3e116688", "android-dhcp-7.1.1");
    hC.AddDnsQueryIp("192.168.1.226", "android.clients.google.com", "1.1.1.1");
    hC.AddDnsQueryIp("192.168.1.226", "play.googleapis.com", "1.1.1.2");
    auto resa = hC.MatchByIpAddress("192.168.1.226");
    if (resa != true) {
        std::cout << "Test failure: Host with Hostname android-49e3daef3e116688 and DhcpVendor android-dhcp-7.1.1 did not match" << std::endl;
        testfailed = true;
    }

	auto sh = std::make_shared<SsdpHost>();
	sh->IpAddress = "192.168.1.234";
	sh->Manufacturer = "Amazon.com, Inc.";
	sh->ModelName = "FireTV";
	hC.AddSsdpInfo(sh);


	auto res = hC.MatchByIpAddress("192.168.1.234");
	if (res != true) {
		std::cout << "Test failure: Host with SsdpManufacturer " << sh->Manufacturer << " and SsdpModelName " << sh->ModelName << " did not match " << std::endl;
		testfailed = true;
	}

	// This should match with 2ae4a61f-75f7-481f-b28c-e3534ee1e04b
	hC.AddDhcpRequest("192.168.1.98", MacAddress("00:00:00:00:00:02"), "", "udhcp 0.9.9-pre" );
	hC.AddDnsQueryIp("192.168.1.98", "control-zoo-dtsprod.tvinteractive.tv", "1.1.1.1");
	hC.AddDnsQueryIp("192.168.1.98", "control2.tvinteractive.tv", "1.1.1.1");
	hC.AddDnsQueryIp("192.168.1.98", "bis-tv-widgets.secure.yahoo.com", "1.1.1.2");
	auto res2 = hC.MatchByIpAddress("192.168.1.98");
	if (res2 != true) {
		std::cout << "Test failure: Host with DhcpVendor " << "udhcp 0.9.9-pre" << " and DnsQuery for " << "control2.tvinteractive.tv" << " did not match" << std::endl;
		testfailed = true;
	}

	hC.AddDnsQueryIp("192.168.1.241", "init.itunes.apple.com", "2.2.2.2");
	hC.AddDnsQueryIp("192.168.1.241", "iosapps.itunes.apple.com", "2.2.2.3");
	hC.AddDnsQueryIp("192.168.1.241", "sync.itunes.apple.com", "2.2.2.4");
    hC.AddDnsQueryIp("192.168.1.241", "time-ios.apple.com", "2.2.2.5");
	auto res3 = hC.MatchByIpAddress("192.168.1.241");
	if (res3 != true) {
		std::cout << "Test failure: Host with Dnsqueries init.itunes.apple.com apps.itunes.com apps.itunes.com did not match" << std::endl;
		testfailed = true;
	}

	hC.AddDhcpRequest("192.168.1.251", MacAddress("00:00:00:00:00:20"), "kindle-a40752280", "");
	hC.AddDnsQueryIp("192.168.1.251", "api.amazon.com", "1.1.1.5");
	auto res4 = hC.MatchByIpAddress("192.168.1.251");
	if (res4 != true) {
		std::cout << "Test failure: Host with DhcpHostname kindle-a40752280 and DnsQuery for " << "api.amazon.com" << " did not match" << std::endl;
	}

	auto h = Host(MacAddress("01:01:01:01:01:01"), true);
	if (h.inPrivateAddressRange("11.0.0.0")) {
		std::cout << "Test failure: 11.0.0.0 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (h.inPrivateAddressRange("9.255.255.255")) {
		std::cout << "Test failure: 9.255.255.255 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (h.inPrivateAddressRange("172.15.255.255")) {
		std::cout << "Test failure: 172.15.255 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (h.inPrivateAddressRange("172.24.0.0")) {
		std::cout << "Test failure: 172.24.0.0 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (h.inPrivateAddressRange("192.167.255.255")) {
		std::cout << "Test failure: 192.167.255.255 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (h.inPrivateAddressRange("192.169.0.0")) {
		std::cout << "Test failure: 192.169.0.0 is not RFC1918" << std::endl;
		testfailed = true;
	}
	if (not h.inPrivateAddressRange("192.168.1.1")) {
		std::cout << "Test failure: 192.168.1.1 is RFC1918" << std::endl;
		testfailed = true;
	}
	if (not h.inPrivateAddressRange("172.20.1.1")) {
		std::cout << "Test failure: 172.20.1.1 is RFC1918" << std::endl;
		testfailed = true;
	}
	if (not h.inPrivateAddressRange("10.255.1.1")) {
		std::cout << "Test failure: 10.255.1.1 is RFC1918" << std::endl;
		testfailed = true;
	}
	if (testfailed) {
		exit(1);
	}
	return 0;
}


