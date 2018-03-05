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

 *  Created on: Mar 30, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#include <iostream>
#include <csignal>
#include <map>
#include <string>
#include <memory>


#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include <gtest/gtest.h>

#include "noddos.h"
#include "WsDiscovery.h"
#include "DnsCache.h"
#include "Config.h"
#include "DeviceProfile.h"
#include "HostCache.h"
#include "MacAddress.h"
#include "Host.h"
#include "InterfaceMap.h"
#include "Mdns.h"
#include "SsdpServer.h"
#include "SsdpLocation.h"
#include "WsDiscovery.h"
#include "MacAddress.h"

bool Debug = false;

int main(int argc, char **argv) {
    int debug_flag = 0;
    while (1) {
        static struct option long_options[] = {
            {"debug",       no_argument,       &debug_flag, 1},
            {0, 0, 0, 0}
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;
        int c = getopt_long (argc, argv, "dnpfhc:", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1) {
            break;
        }
        switch (c) {
            case 0:
                break;
            case 'd':
                debug_flag = 1;
                Debug = true;
                break;
            case '?':
            case 'h':
            default:
                printf ("noddos_test usage: -d/--debug\n");
                exit (0);
        }
    }
    if (debug_flag) {
        openlog(argv[0], LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
    }
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(WsDiscoveryHostTest, Comparison) {
    struct WsDiscoveryHost h1, h2;
    ASSERT_TRUE(h1 == h2);
    h1.IpAddress = "192.168.1.1";
    ASSERT_FALSE(h1 == h2);
    h1.wsdTypes = "simpletest";
    ASSERT_FALSE(h1 == h2);
    h1.wsdXAddrs = "192.168.1.2";
    ASSERT_FALSE(h1 == h2);
    h2.IpAddress = "192.168.1.1";
    ASSERT_FALSE(h1 == h2);
    h2.wsdTypes = "simpletest";
    ASSERT_FALSE(h1 == h2);
    h2.wsdXAddrs = "192.168.1.2";
    ASSERT_TRUE(h1 == h2);
}

TEST(   HostTest, Comparison) {
    struct MdnsHost h1, h2;
    ASSERT_TRUE(h1 == h2);
    h1.IpAddress = "192.168.1.1";
    ASSERT_FALSE(h1 == h2);
    h1.Hostname = "simpletest";
    ASSERT_FALSE(h1 == h2);
    h1.Os = "linux";
    ASSERT_FALSE(h1 == h2);
    h1.Hw = "hardware";
    ASSERT_FALSE(h1 == h2);
    h1.DeviceUrl = "http://192.168.1.3/testmodel";
    ASSERT_FALSE(h1 == h2);
    h1.Manufacturer = "someco";
    ASSERT_FALSE(h1 == h2);
    h1.ModelName= "somedevice";
    ASSERT_FALSE(h1 == h2);

    h2.IpAddress = "192.168.1.1";
    ASSERT_FALSE(h1 == h2);
    h2.Hostname = "simpletest";
    ASSERT_FALSE(h1 == h2);
    h2.Os = "linux";
    ASSERT_FALSE(h1 == h2);
    h2.Hw = "hardware";
    ASSERT_FALSE(h1 == h2);
    h2.DeviceUrl = "http://192.168.1.3/testmodel";
    ASSERT_FALSE(h1 == h2);
    h2.Manufacturer = "someco";
    ASSERT_FALSE(h1 == h2);
    h2.ModelName= "somedevice";
    ASSERT_TRUE(h1 == h2);
}

TEST(SsdpHostTest, Comparison) {
    struct SsdpHost h1, h2;
    ASSERT_TRUE(h1 == h2);
    h1.IpAddress = "192.168.1.1";
    ASSERT_FALSE(h1 == h2);
    h1.Manufacturer = "simpletest";
    ASSERT_FALSE(h1 == h2);
    h1.ManufacturerUrl = "http://192.168.1.2/test";
    ASSERT_FALSE(h1 == h2);
    h1.ModelName = "testmodel";
    ASSERT_FALSE(h1 == h2);
    h1.ModelUrl = "http://192.168.1.3/testmodel";
    ASSERT_FALSE(h1 == h2);
    h1.DeviceType = "sometype";
    ASSERT_FALSE(h1 == h2);
    h1.SerialNumber = "1234";
    ASSERT_FALSE(h1 == h2);
    h1.UserAgent = "Agent";
    ASSERT_FALSE(h1 == h2);
    h1.Server = "server";
    ASSERT_FALSE(h1 == h2);
    h1.Location = "http://192.168.1.1/SsdpServer";
    ASSERT_FALSE(h1 == h2);

    h2.IpAddress = "192.168.1.1";
    ASSERT_FALSE(h1 == h2);
    h2.Manufacturer = "simpletest";
    ASSERT_FALSE(h1 == h2);
    h2.ManufacturerUrl = "http://192.168.1.2/test";
    ASSERT_FALSE(h1 == h2);
    h2.ModelName = "testmodel";
    ASSERT_FALSE(h1 == h2);
    h2.ModelUrl = "http://192.168.1.3/testmodel";
    ASSERT_FALSE(h1 == h2);
    h2.DeviceType = "sometype";
    ASSERT_FALSE(h1 == h2);
    h2.SerialNumber = "1234";
    ASSERT_FALSE(h1 == h2);
    h2.UserAgent = "Agent";
    ASSERT_FALSE(h1 == h2);
    h2.Server = "server";
    ASSERT_FALSE(h1 == h2);
    h2.Location = "http://192.168.1.1/SsdpServer";
    ASSERT_TRUE(h1 == h2);
}

/*
 * A FQDN with a CNAME record
 */
TEST(DnsCacheTest, addCname) {
    DnsCache <std::string> c(14400, true);
    c.addorupdateCname ("originalfqdn", "cnamefqdn", 3600);

    ASSERT_EQ(c.getFqdns("cnamefqdn").count("originalfqdn"),1);
    ASSERT_EQ(c.getCnames("originalfqdn").count("cnamefqdn"),1);
}

/*
 * An FQDN with a CNAME record that has a CNAME record
 */
TEST(DnsCacheTest, addLinkedCname) {
    DnsCache <std::string> c(14400, true);
    c.addorupdateCname ("originalfqdn", "cnamefqdn", 3600);
    c.addorupdateCname ("cnamefqdn", "anothercnamefqdn", 3600);

    ASSERT_EQ(c.getFqdns("anothercnamefqdn").count("originalfqdn"),1);
    ASSERT_EQ(c.getFqdns("anothercnamefqdn").count("cnamefqdn"),1);
    ASSERT_EQ(c.getCnames("originalfqdn").count("anothercnamefqdn"),1);
    ASSERT_EQ(c.getCnames("originalfqdn").count("cnamefqdn"),1);
}

/*
 * One FQDN with two CNAME records
 */
TEST(DnsCacheTest, twoCname) {
    DnsCache <std::string> c(14400, true);
    c.addorupdateCname ("originalfqdn", "cnamefqdn", 3600);
    c.addorupdateCname ("originalfqdn", "newcnamefqdn", 3600);

    ASSERT_EQ(c.getFqdns("newcnamefqdn").count("originalfqdn"),1);
    ASSERT_EQ(c.getFqdns("cnamefqdn").count("originalfqdn"),1);
    ASSERT_EQ(c.getCnames("originalfqdn").count("newcnamefqdn"),1);
    ASSERT_EQ(c.getCnames("originalfqdn").count("cnamefqdn"),1);
}

/*
 * Two FQDNs with the same CNAME record
 */
TEST(DnsCacheTest, sameCname) {
    DnsCache <std::string> c(14400, true);
    c.addorupdateCname ("originalfqdn", "cnamefqdn", 3600);
    c.addorupdateCname ("anotherfqdn", "cnamefqdn", 3600);

    ASSERT_EQ(c.getFqdns("cnamefqdn").count("originalfqdn"),1);
    ASSERT_EQ(c.getFqdns("cnamefqdn").count("anotherfqdn"),1);
    ASSERT_EQ(c.getCnames("originalfqdn").count("cnamefqdn"),1);
    ASSERT_EQ(c.getCnames("anotherfqdn").count("cnamefqdn"),1);
}
/*
 * One FQDN with two CNAME records
 */
TEST(DnsCacheTest, pruneCnameRecords) {
    DnsCache <std::string> c(1, true);
    c.addorupdateCname ("originalfqdn", "cnamefqdn", 1);
    c.addorupdateCname ("originalfqdn", "newcnamefqdn", 1);

    ASSERT_EQ(c.getFqdns("newcnamefqdn").count("originalfqdn"),1);
    ASSERT_EQ(c.getFqdns("cnamefqdn").count("originalfqdn"),1);
    ASSERT_EQ(c.getCnames("originalfqdn").count("newcnamefqdn"),1);
    ASSERT_EQ(c.getCnames("originalfqdn").count("cnamefqdn"),1);

    c.pruneCnames(false);

    ASSERT_EQ(c.getFqdns("newcnamefqdn").count("originalfqdn"),1);
    ASSERT_EQ(c.getFqdns("cnamefqdn").count("originalfqdn"),1);
    ASSERT_EQ(c.getCnames("originalfqdn").count("newcnamefqdn"),1);
    ASSERT_EQ(c.getCnames("originalfqdn").count("cnamefqdn"),1);

    sleep (2);
    c.pruneCnames(false);

   {
        try {
            std::set<std::string> fqdns = c.getFqdns("newcnamefqdn");
            ASSERT_EQ(fqdns.find("originalfqdn") != fqdns.end() ? 1 : 0, 0);
        }
        catch (...) {}
    }
    {
        try {
            std::set<std::string> fqdns = c.getFqdns("cnamefqdn");
            ASSERT_EQ(fqdns.find("originalfqdn") != fqdns.end() ? 1 : 0, 0);
        }
        catch (...) {}
    }
    {
        try {
            std::set<std::string> cnames = c.getCnames("originalfqdn");
            ASSERT_EQ(cnames.find("newcnamefqdn") != cnames.end() ? 1 : 0, 0);
            ASSERT_EQ(cnames.find("cnamefqdn") != cnames.end() ? 1 : 0, 0);
        }
        catch (...) {}
    }
}

TEST(DnsTest, importCnameRecords) {
    FqdnDeviceProfileMap fdpMap;
    DnsCache <std::string> c(true);

    std::string filename = "tests/DnsCache.json";
    std::ifstream ifs(filename);
    ASSERT_TRUE(ifs.is_open());

    json k;
    ifs >> k;
    ifs.close();

    size_t importedRecords = c.importJson(k,fdpMap);
    ASSERT_EQ(importedRecords, 85);

    std::ofstream ofs("/tmp/DnsCache.json");
    ASSERT_TRUE(ofs.is_open());

    json j;

    auto exportRecords = c.exportJson(j);
    ASSERT_EQ(exportRecords, 85);

    ofs << std::setw(4) << j << std::endl;
    ofs.close();
    unlink("/tmp/DnsCache.json");

    std::set<std::string> PrunedCnames = c.pruneCnames(true);
    size_t pruned = PrunedCnames.size();
    ASSERT_EQ(pruned, 130);
}

TEST(DnsCacheTest, importARecords) {
    FqdnDeviceProfileMap fdpMap;
    DnsCache <Tins::IPv4Address> i(true);
    DnsCache <Tins::IPv6Address> isix(true);

    std::string filename = "tests/DnsCache.json";
    std::ifstream ifs(filename);
    ASSERT_TRUE(ifs.is_open());

    json k;
    ifs >> k;
    ifs.close();

    size_t importedRecords = i.importJson(k, fdpMap);
    ASSERT_EQ(importedRecords, 564);

    importedRecords = isix.importJson(k, fdpMap);
    ASSERT_EQ(importedRecords, 7);

    Tins::IPv4Address ip4("23.41.176.89");
    std::vector<std::string> fqdns = i.getAllFqdns(ip4);
    ASSERT_EQ(fqdns.size(), 1);

    std::ofstream ofs("/tmp/DnsCache.json");
    ASSERT_TRUE(ofs.is_open());

    json j;
    auto exportRecords = i.exportJson(j);
    ASSERT_EQ(exportRecords, 74);
    ofs << std::setw(4) << j << std::endl;
    ofs.close();
    unlink("/tmp/DnsCache.json");

    std::set<std::string> PrunedFqdns = i.pruneResourceRecords(true);
    size_t pruned_fqdns = PrunedFqdns.size();
    ASSERT_EQ(pruned_fqdns, 74);
}

TEST(DnsCacheTest, addARecord) {
    DnsCache <Tins::IPv4Address> i(3600, true);
    auto now = time(nullptr);
    Tins::IPv4Address t("10.0.0.1");

    i.addorupdateResourceRecord("www.test.com", t, 2);
    std::map<Tins::IPv4Address, time_t> rrs = i.lookupResourceRecord("www.test.com");
    size_t s = rrs.size();
    ASSERT_EQ(s, 1);
    time_t ttl = rrs[t];
    ASSERT_GE(ttl, now + 1);
}

TEST(ConfigTest, readConfig) {
    // all we are testing here is that no exception is thrown while parsing the yml
    Config c("tests/noddos.yml");
}

bool test_match (std::string inIp, std::string inDpUuid, HostCache &hc);

TEST(DeviceProfileTest, matchTest) {
    std::string DeviceProfilesFile = "tests/DeviceProfiles.json";
    std::map<std::string, std::shared_ptr<DeviceProfile>> DeviceProfiles;
    std::ifstream ifs(DeviceProfilesFile);
    json j;
    ifs >> j;
    for (json::iterator it = j.begin(); it != j.end(); ++it) {
        std::cout << *it << std::endl;
        std::string uuid = (*it)["DeviceProfileUuid"].get<std::string>();
        DeviceProfiles[uuid] = std::make_shared<DeviceProfile>(*it);
        ASSERT_TRUE(DeviceProfiles[uuid]->isValid());
    }
    InterfaceMap ifMap;
    HostCache hc(ifMap, "", 0, 0, "", false, true);
    hc.AddByMac (MacAddress("00:00:00:00:00:01"), "192.168.1.232");
    hc.AddByMac (MacAddress("00:00:00:00:00:02"), "192.168.1.98");
    hc.AddByMac (MacAddress("00:00:00:00:00:03"), "192.168.1.99");
    hc.AddByMac (MacAddress("00:00:00:00:00:04"), "192.168.1.235");
    hc.AddByMac (MacAddress("00:00:00:00:00:05"), "192.168.1.241");
    hc.AddByMac (MacAddress("00:00:00:00:00:06"), "192.168.1.251");
    hc.AddByMac (MacAddress("00:00:00:00:00:07"), "192.168.1.234");
    hc.AddByMac (MacAddress("00:00:00:00:00:08"), "192.168.1.240");
    hc.AddByMac (MacAddress("00:00:00:00:00:09"), "192.168.1.238");
    hc.AddByMac (MacAddress("00:00:00:00:00:10"), "192.168.1.234");
    hc.AddByMac (MacAddress("00:00:00:00:00:13"), "192.168.1.80");
    hc.AddByMac (MacAddress("00:00:00:00:00:11"), "192.168.1.225");
    hc.AddByMac (MacAddress("00:00:00:00:00:12"), "192.168.1.242");
    hc.AddByMac (MacAddress("00:00:00:00:00:14"), "192.168.1.231");
    hc.AddByMac (MacAddress("00:00:00:00:00:15"), "192.168.1.133");
    hc.AddByMac (MacAddress("00:00:00:00:00:16"), "192.168.1.238");
    hc.AddByMac (MacAddress("00:00:00:00:00:17"), "192.168.1.146");
    hc.AddByMac (MacAddress("00:00:00:00:00:18"), "192.168.1.224");
    hc.AddByMac (MacAddress("00:00:00:00:00:19"), "192.168.1.239");
    hc.AddByMac (MacAddress("00:00:00:00:00:20"), "192.168.1.11");
    hc.AddByMac (MacAddress("00:00:00:00:00:21"), "192.168.1.227");
    hc.AddByMac (MacAddress("00:00:00:00:00:22"), "192.168.1.226");
    hc.AddByMac (MacAddress("00:00:00:00:00:23"), "192.168.1.248");
    hc.AddByMac (MacAddress("00:00:00:00:00:24"), "192.168.1.243");
    hc.AddByMac (MacAddress("00:00:00:00:00:25"), "192.168.1.229");
    hc.loadDeviceProfiles(DeviceProfilesFile);


    // pending good test data for dnsmasq.log that allows the matching of most of these.
    // testfailed |= ! test_match ("192.168.1.235", "694e8c7e-69f0-400f-824d-b94af7c7b7cc", hc);
    // testfailed |= ! test_match ("192.168.1.244", "dff464bf-c954-43d2-8b5a-87ef4b632da5", hc);
    // testfailed |= ! test_match ("192.168.1.251", "6e617357-5a44-4f5a-8675-5ecba34055be", hc);
    // testfailed |= ! test_match ("192.168.1.248", "7d8f2ed0-38f9-455d-a816-89a1daeb6ae2", hc);
    // testfailed |= ! test_match ("192.168.1.225", "5ec4dd66-22ee-4cd6-beed-fa4fdfd38c34", hc);
    // testfailed |= ! test_match ("192.168.1.243", "7b50c7cd-d7b9-40ad-980d-0b520ad3d05e", hc);
    // testfailed |= ! test_match ("192.168.1.229", "b2e13a63-c40b-4448-b524-3c2852bc1cb7", hc);
    // testfailed |= ! test_match ("192.168.1.227", "2ae4a61f-75f7-481f-b28c-e3534ee1e04b", hc);
    // testfailed |= ! test_match ("192.168.1.226", "76905373-748b-4e25-a550-296b3e1c7086", hc);
}

bool test_match (std::string inIp, std::string inDpUuid, HostCache &hc) {
    try {
        std::shared_ptr<Host> h_ptr = hc.FindHostByIp(inIp);
        if (h_ptr == nullptr) {
            std::cout << "IP address " << inIp << " not found in HostCache" << std::endl;
            return false;
            std::string uuid = h_ptr->getUuid ();
            if (uuid != inDpUuid) {
                if (uuid == "") {
                    std::cout << inIp << " did not match with profile " << inDpUuid << std::endl;
                } else {
                    std::cout << inIp << " did not match with profile " << inDpUuid << " but with " << uuid << std::endl;
                }
                json j;
                h_ptr->DeviceStats(j, true, true);
                std::cout << j << std::endl;
                return false;

            } else {
                std::cout << inIp << " MATCHED " << inDpUuid << std::endl;
                return true;
            }
        }
        h_ptr->Match(hc.getDeviceProfilesMap());
    } catch (...) { }
    return false;
}

TEST(HostCacheTest, importDeviceProfileMatches) {
    InterfaceMap ifMap;
    HostCache hC(ifMap, "", 0, 0, "", false, true);
    hC.loadDeviceProfiles("tests/DeviceProfiles.json");
    auto  matches = hC.ImportDeviceProfileMatches("tests/DeviceMatches.json");
    ASSERT_EQ(matches, 9);
}

TEST(HostCacheTest, MacAddressTest) {
    Config c(true);
    c.Load("tests/noddos.yml");
    InterfaceMap ifMap(c.LanInterfaces, c.WanInterfaces, true);
    HostCache hC(ifMap, "", 0, 0, "", false, true);
    MacAddress Mactest ("00:00:00:00:00:03");
    hC.AddByMac (Mactest, "192.168.1.99");

    std::string s;
    auto h = hC.FindOrCreateHostByIp("192.168.1.99");
    ASSERT_EQ(h->getMacAddress(), "00:00:00:00:00:03");

    // Test only makes sense on local LAN, not in CI
    ASSERT_EQ(hC.MacLookup("192.168.1.1").str(), "00:01:2E:6F:E0:F3");

    MacAddress Mac = hC.MacLookup("99.99.99.99");
    ASSERT_FALSE(Mac.isValid());

    // Test only makes sense on local LAN, not in CI
    // ASSERT_EQ(hC.MacLookup("192.168.1.240", "enp0s31f6"), "00:01:2e:6f:e0:f3");
}

TEST(MacAddressTest, compareMac) {
    std::string MacString = "AA:22:CC:44:EE:66";

    MacAddress m(MacString);

    std::string res = m.str();
    ASSERT_EQ(res, MacString);
}

TEST(MdnsTest, parseMdnsInfo) {
    std::string msg = "^txtvers=1^priority=30^ty=EPSON XP-410 Series^usb_MFG=EPSON^usb_MDL=XP-410 Series^product=(EPSON XP-410 Series)^pdl=application/octet-stream,image/urf,image/jpeg^rp=ipp/print^qtotal=1&adminurl=http://EPSON410.local.:80/PRESENTATION/BONJOUR^note=^Color=T^Duplex=F^Fax=F^Scan=T^URF=CP1,MT1-3-8-10-11-12,PQ4-5,OB9,OFU0,RS360,SRGB24,W8,IS1,V1.2^UUID=cfe92100-67c4-11d4-a45f-ac1826841a46";
    msg[0] = 9;
    msg[10] = 11;
    msg[22] = 22;
    msg[45] = 13;
    msg[59] = 21;
    msg[81] = 29;
    msg[111] = 49;
    msg[161] = 12;
    msg[174] = 8;
    msg[183] = 55;
    msg[239] = 5;
    msg[245] = 7;
    msg[253] = 8;
    msg[262] = 5;
    msg[268] = 6;
    msg[275] = 64;
    msg[340] = 41;

    InterfaceMap ifMap;
    HostCache hC(ifMap, "", 0, 14400, "", false, true);

    auto Host = std::make_shared<MdnsHost>();

    Mdns m(hC, 86400);
    m.parseTxtRr(Host, msg);

    ASSERT_EQ(Host->Manufacturer, "EPSON");
    ASSERT_EQ(Host->ModelName, "XP-410 Series");
    ASSERT_EQ(Host->DeviceUrl, "http://EPSON410.local.:80/PRESENTATION/BONJOUR");
}

TEST(SsdpServerTest, ssdpLocation) {
    InterfaceMap ifMap;
    HostCache hC(ifMap, "", 0, 1400, "", false, true);
    auto sHost = std::make_shared<SsdpHost>();
    sHost->Location="http://192.168.1.248:49152/rootDesc.xml";
    sHost->IpAddress = "192.168.1.249";
    ASSERT_TRUE(SsdpLocation::Get(*sHost, true));
    ASSERT_EQ(sHost->FriendlyName, "SAMSUNG-SNH-E6440BN-BC66411075FD");
    ASSERT_EQ(sHost->Manufacturer, "SAMSUNG");
    ASSERT_EQ(sHost->ManufacturerUrl, "http://www.samsungtechwin.com/");
    ASSERT_EQ(sHost->ModelName, "SNH-E6440BN");
    ASSERT_EQ(sHost->ModelUrl, "http://www.samsungtechwin.com/");
    ASSERT_EQ(sHost->SerialNumber, "KJ2J69MFB010NKP");
}

TEST(SsdpServerTest, parseSsdpMessage) {
    InterfaceMap ifMap;
    HostCache hC(ifMap, "", 0, 1400, "", false, true);
    SsdpServer sServer(hC, 86400);
    char msg[300] = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=60\r\nlOCATION: http://192.168.1.248:49152/rootDesc.xml\r\nSERVER: Linux 3.0.8 UPnP/1.1 MiniUPnPd/1.7\r\nupnp:rootdevice\r\nuuid:Upnp-BasicDevice-1_0-BC66411075FD::upnp:rootdevice\r\n\01-NLS: 1\r\nBOOTID.UPNP.ORG: 1\r\nCONFIGID.UPNP.ORG: 1337\r\n";
    auto sHost = std::make_shared<SsdpHost>();
    ASSERT_TRUE(sServer.ParseSsdpMessage(sHost, msg, strlen(msg)) == true);
    ASSERT_EQ(sHost->Location, "http://192.168.1.248:49152/rootDesc.xml");
    ASSERT_EQ(sHost->Server, "Linux 3.0.8 UPnP/1.1 MiniUPnPd/1.7");
    ASSERT_EQ(sHost->UserAgent, "");
}

TEST(WsDiscoveryTest, parseWsDiscoveryMessage) {
    InterfaceMap ifMap;
    HostCache hC(ifMap, "", 0, 1400, "", false, true);
    WsDiscovery wServer(hC, 86400);

    unsigned char WsDiscoveryResponse[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:wprt=\"http://schemas.microsoft.com/windows/2006/08/wdp/print\" xmlns:wscn=\"http://schemas.microsoft.com/windows/2006/08/wdp/scan\"><soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action><wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To><wsa:MessageID>urn:uuid:0af48d00-a033-11b2-b522-ac1826841a46</wsa:MessageID><wsa:RelatesTo>urn:uuid:4ed84e57-4743-412a-ab29-e7887ce6f587</wsa:RelatesTo><wsd:AppSequence  InstanceId=\"271\" MessageNumber=\"10\"></wsd:AppSequence></soap:Header><soap:Body><wsd:ProbeMatches><wsd:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:uuid:cfe92100-67c4-11d4-a45f-ac1826841a46</wsa:Address></wsa:EndpointReference><wsd:Types>wsdp:Device wscn:ScanDeviceType wprt:PrintDeviceType</wsd:Types><wsd:XAddrs>http://192.168.1.245:80/WSD/DEVICE</wsd:XAddrs><wsd:MetadataVersion>207</wsd:MetadataVersion></wsd:ProbeMatch></wsd:ProbeMatches></soap:Body></soap:Envelope>";
    size_t len = strlen((char *) WsDiscoveryResponse);
    auto Host = std::make_shared<WsDiscoveryHost>();
    ASSERT_TRUE(wServer.ParseWsDiscoveryMessage(Host, WsDiscoveryResponse, len));
}

TEST(HostTest, matchHostsToDeviceProfile) {
    std::string deviceprofilesfile = "tests/DeviceProfiles.json";

    InterfaceMap ifMap;
    HostCache hC(ifMap, "", 0, 14400, "", false, true);
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

    ASSERT_TRUE(hC.MatchByIpAddress("192.168.1.226"));

    auto sh = std::make_shared<SsdpHost>();
    sh->IpAddress = "192.168.1.234";
    sh->Manufacturer = "Amazon.com, Inc.";
    sh->ModelName = "FireTV";
    hC.AddSsdpInfo(sh);
    ASSERT_TRUE(hC.MatchByIpAddress("192.168.1.234"));

    // This should match with 2ae4a61f-75f7-481f-b28c-e3534ee1e04b
    hC.AddDhcpRequest("192.168.1.98", MacAddress("00:00:00:00:00:02"), "", "udhcp 0.9.9-pre" );
    hC.AddDnsQueryIp("192.168.1.98", "control-zoo-dtsprod.tvinteractive.tv", "1.1.1.1");
    hC.AddDnsQueryIp("192.168.1.98", "control2.tvinteractive.tv", "1.1.1.1");
    hC.AddDnsQueryIp("192.168.1.98", "bis-tv-widgets.secure.yahoo.com", "1.1.1.2");
    ASSERT_TRUE(hC.MatchByIpAddress("192.168.1.98"));

    hC.AddDnsQueryIp("192.168.1.241", "init.itunes.apple.com", "2.2.2.2");
    hC.AddDnsQueryIp("192.168.1.241", "iosapps.itunes.apple.com", "2.2.2.3");
    hC.AddDnsQueryIp("192.168.1.241", "sync.itunes.apple.com", "2.2.2.4");
    hC.AddDnsQueryIp("192.168.1.241", "time-ios.apple.com", "2.2.2.5");
    ASSERT_TRUE(hC.MatchByIpAddress("192.168.1.241"));

    hC.AddDhcpRequest("192.168.1.251", MacAddress("00:00:00:00:00:20"), "kindle-a40752280", "");
    hC.AddDnsQueryIp("192.168.1.251", "api.amazon.com", "1.1.1.5");
    ASSERT_TRUE(hC.MatchByIpAddress("192.168.1.251"));

    auto h = Host(MacAddress("01:01:01:01:01:01"), true);
    ASSERT_FALSE(h.inPrivateAddressRange("11.0.0.0"));
    ASSERT_FALSE(h.inPrivateAddressRange("9.255.255.255"));
    ASSERT_FALSE(h.inPrivateAddressRange("172.15.255.255"));
    ASSERT_FALSE(h.inPrivateAddressRange("172.24.0.0"));
    ASSERT_FALSE(h.inPrivateAddressRange("192.167.255.255"));
    ASSERT_FALSE(h.inPrivateAddressRange("192.169.0.0"));
    ASSERT_TRUE(h.inPrivateAddressRange("192.168.1.1"));
    ASSERT_TRUE(h.inPrivateAddressRange("172.20.1.1"));
    ASSERT_TRUE(h.inPrivateAddressRange("10.255.1.1"));
}

TEST(IpsetTest, blah) {
    auto u = getuid();
    // EXPECT_EQ(u, 0);

    if (u == 0) {
        Ipset i(true);
        i.Open("noddostestv4", "hash:ip", true, true);

        Tins::IPv4Address ipfirst("192.168.1.1");

        ASSERT_TRUE(i.Add(ipfirst, 604800));
        ASSERT_TRUE(i.In(ipfirst));
        ASSERT_TRUE(i.Remove(ipfirst));

        Tins::IPv4Address ipthird("192.168.1.3");
        struct in_addr sin3;
        ASSERT_TRUE(i.Add(ipthird, 604800));
        ASSERT_TRUE(i.In(ipthird));
        ASSERT_TRUE(i.Remove(ipthird));

        Ipset s(true);
        i.Open("noddostestv6", "hash:ip", false, true);

        Tins::IPv6Address ipsix("fdbb:2ad1:cea0:0:1e1b:dff:fe7d:f5ec");
        ASSERT_TRUE(i.Add(ipsix, 604800));
        ASSERT_TRUE(i.In(ipsix));
        ASSERT_TRUE(i.Remove(ipsix));

        Ipset j("noddostest2", "hash:ip", NFPROTO_IPV4, true);
        Tins::IPv4Address ipfourth("192.168.1.1");

        ASSERT_TRUE(j.Add(ipfourth, 604800));
        ASSERT_TRUE(j.In(ipfourth));
        ASSERT_TRUE(j.Remove(ipfourth));
        ASSERT_TRUE(j.Destroy());

        // disable hash:mac test as it requires an existing ipset hash:map to exist
        Ipset m("noddosmac", "hash:mac", NFPROTO_UNSPEC);
        std::string MacString = "AA:22:CC:44:EE:66";

        MacAddress Mac(MacString);

        std::string mstr = Mac.str();

        ASSERT_TRUE(m.Add(Mac, 604800));
        ASSERT_TRUE(m.In(Mac));
        ASSERT_TRUE(m.Remove(Mac));
    }
}

uint32_t RestApiCall (const std::string api, const json &j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile) {
    std::string url = "https://api.noddos.io/" + api;

    std::string body = j.dump();
    char buf[strlen(body.c_str())+1];
    strcpy(buf, body.c_str());
    if (Debug) {
        syslog (LOG_DEBUG, "Uploading %zu bytes of data to %s", strlen(buf), url.c_str());
    }

    struct curl_slist *hlist = NULL;
    hlist = curl_slist_append(hlist, "Content-Type: application/json");
    if (hlist == NULL) {
        syslog(LOG_ERR, "Couldn't create curl header for API call to %s", api.c_str());
    }

    std::string response_string;
    std::string header_string;
    long response_code;
    double elapsed;
    auto curl = curl_easy_init();
    if (curl) {
        CURLcode ret;
        ret = curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_URL returned %d",ret);
        }
        // curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
        ret = curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_USE_SSL returned %u", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_SSLCERT, ClientApiCertFile.c_str());
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_SSLCERT returned %u", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_SSLKEY, ClientApiKeyFile.c_str());
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_SSLKEY returned %u", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "ECDHE-RSA-AES256-GCM-SHA384");
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_SSL_CIPHER_LIST returned %d", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_POSTFIELDS returned %d", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) strlen(buf));
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_POSTFIELDSIZE_LARGE returned %d", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_NOPROGRESS returned %d", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_USERAGENT, "noddos/1.0.0");
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_USERAGENT returned %u", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hlist);
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_HTTPHEADER returned %d", ret);
        }
        // Curllib version on lede doesn't support HTTP 2.0
        // ret = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
        // if(ret) {
        //  syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
        // }
        ret = curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_MAXREDIRS returned %d", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 0L);
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_TCP_KEEPALIVE returned %d", ret);
        }
        // ret = curl_easy_setopt(curl, CURLOPT_TCP_FASTOPEN, 1L);
        // if(ret) {
        //  syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
        // }
        ret = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long) 5000);
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_TIMEOUT_MS returned %d", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlwriteFunction);
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEDATA returned %d", ret);
        }
        ret = curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
        if(ret) {
            syslog (LOG_ERR, "Curl setopt CURLOPT_HEADERDATA returned %d", ret);
        }
        if (false && Debug) {
            // TODO test on whether STDOUT is open for writing
            // 'always' disabled as this logs to STDOUT, which is normally closed
            ret = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }


        ret = curl_easy_perform(curl);
        if(ret) {
            syslog (LOG_ERR, "Curl easy_perform returned %d", ret);
        }
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
        curl_slist_free_all(hlist);
        curl_easy_cleanup(curl);
        curl = NULL;
        if (Debug) {
                syslog (LOG_DEBUG, "Upload resulted in %lu status, data %s", response_code, response_string.c_str());
            }
    }

    if (Debug) {
        std::string file = api;
        std::replace( file.begin(), file.end(), '/', '-');
        std::time_t t = std::time(nullptr);
        std::tm tm = *std::localtime(&t);
        char buf[20];
        strftime(buf,18,"%Y%m%d-%H%M%S",&tm);
        std::string filename = "/tmp/" + file + "-" + buf;
        std::ofstream ofs(filename);
        if (not ofs.is_open()) {
            syslog(LOG_WARNING, "Couldn't open %s", filename.c_str());
        }
        ofs << std::setw(4) << j << std::endl;
        ofs.close();
    }
    return (uint32_t) response_code;
}

/*
size_t curlwriteFunction(void *ptr, size_t size, size_t nmemb, std::string* data) {
    data->append((char*) ptr, size * nmemb);
    return size * nmemb;
}
*/

TEST(CurlTest, uploadStats) {
    std::string filename = "tests/v1-uploadstats-20170515-021413";
    std::ifstream ifs(filename);
    json j;
    ifs >> j;
    ifs.close();
    auto r = RestApiCall ("v1/uploadstats", j, "tests/noddosapiclient.pem", "tests/noddosapiclient.key");
    ASSERT_EQ(r,201);
}

TEST(CurlTest, uploadDevices) {
    std::string filename = "tests/v1-uploaddevices-20170514-222118";
    std::ifstream ifs(filename);
    json j;
    ifs >> j;
    ifs.close();
    auto r = RestApiCall ("v1/uploaddevices", j, "tests/noddosapiclient.pem", "tests/noddosapiclient.key");
    ASSERT_EQ(r,201);
}
