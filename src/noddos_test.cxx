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

#include <sys/signalfd.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <stdlib.h>

#include <string>

#include <memory>

#include <gtest/gtest.h>

#include "noddos.h"
#include "WsDiscovery.h"
#include "DnsCache.h"

#define MAXEPOLLEVENTS 64

int main(int argc, char **argv) {
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

TEST(MdnsHostTest, Comparison) {
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

TEST(DnsCnameCacheTest, addCname) {
    DnsCnameCache c(true);
    c.addorupdateCname ("originalfqdn", "cnamefqdn", 3600);

    ASSERT_EQ(c.getFqdn("cnamefqdn"), "originalfqdn");
    ASSERT_EQ(c.getCname("originalfqdn"), "cnamefqdn");
}

TEST(DnsCnameCacheTest, updateCname) {
    DnsCnameCache c(true);
    c.addorupdateCname ("originalfqdn", "cnamefqdn", 3600);
    c.addorupdateCname ("originalfqdn", "newcnamefqdn", 3600);

    ASSERT_EQ(c.getFqdn("newcnamefqdn"), "originalfqdn");
    ASSERT_EQ(c.getFqdn("cnamefqdn"), "originalfqdn");
    ASSERT_EQ(c.getCname("originalfqdn"), "newcnamefqdn");
    ASSERT_EQ(c.getCname("originalfqdn"), "cnamefqdn");
}
