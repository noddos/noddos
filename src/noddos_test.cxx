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

#include <sys/signalfd.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <getopt.h>

#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

#include <gtest/gtest.h>

#include "noddos.h"
#include "WsDiscovery.h"
#include "DnsCache.h"

#define MAXEPOLLEVENTS 64

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
