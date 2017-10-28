___Noddos v0.5.5___ - 10/28/2017

New features:
* Use yaml for noddos.conf
* Add support for SsdpDeviceType and MdnsHostname
* (OpenWRT/LEDE) Automatic interface detection
* Further reduce logging by making debug logging for main event loop optional (disabled by default)
* Device Profile database is now at 43 devices that can be identified thanks to information learned from home-assistant SSDP/MDNS discovery information

Bug fixes:
* [#39](https://github.com/noddos/noddos/issues/39) DnsQueryCache expired too soon
* [#34](https://github.com/noddos/noddos/issues/34) DnsCache.json expiration incorrect

Instructions:
* Users of previous versions have to manually copy configuration settings made to noddos.conf to noddos.yml
* OpenWRT/LEDE Users: if you install noddos manually, you now also have to download and install the libyaml-cpp package.

___Noddos v0.5.4___ - 10/17/2017

Bug fixes:
* #33 SendUdpPackets had transmission failures

___Noddos v0.5.3___ - 10/15/2017

Bug fix:
* [#32](https://github.com/noddos/noddos/issues/32) Noddos runs out of file descriptors

___Noddos v0.5.2___ - 10/6/2017

Bug fixes:
* [#29](https://github.com/noddos/noddos/issues/29) endless loop in parsing specific mDNS TXT record
* [#31](https://github.com/noddos/noddos/issues/31) add br-lan to default list of LAN interfaces for LEDE routers
* [#30](https://github.com/noddos/noddos/issues/30) reduce logging when running without debugging enabled

___Noddos v0.5.1  - 10/2/2017___

New features:
* Improved mDNS TXT handling to support 'mfg' and 'mdl' fields
* Write IPv6 and DhcpHostname to DeviceDump.json file

Bug fixes:
* Memory leak in Ipset class fixed
* No retries for MAC address lookups as we now send out ARP requests
* Hide IP addresses in device reports for the SSDP Location and the mDNS DeviceURL fields
* All but stop hosts showing up in DeviceDump.json with as IP address '0.0.0.0'
* Fix test case for Android clients for DeviceProfile matching

___Noddos v0.5.0  - 9/17/2017___

New features:
* Support for mDNS is in: Noddos can now find my Epson TX-410 printer
* Support for WS-Discovery
* Debug logging can now be configured more granularly

___Noddos v0.4.1  - 9/1/2017___

New features:
* Improve Lede installation script

___Noddos v0.4.0  - 8/26/2017___

New features:
* Dynamic firewall rules are in.

___Noddos v0.3.3  - 8/21/2017___

Bug fixes:
* Don't call freeifaddrs while still in the loop reading result of getifaddrs

___Noddos v0.3.2  - 8/12/2017___

New features:
* Improved logging and error handling to facilitate remote troubleshooting

___Noddos v0.3.1  - 8/4/2017___

New features:
* Persist DnsCache so that at startup, Noddos already has data to populate firewall rules

Bug fixes:
* pruneTcpSnoopInstances was calling a method of TcpSnoop for a nullptr instance, causing segfaults

___Noddos v0.3.0  - 7/17/2017___

New features:
* Use AF_PACKET_MMAP for DNS and DHCP snooping to avoid dependency on dnsmasq
* Use /proc/net/nf_conntract is available and noddos configuration doesn't disable it
* Disable travis CI as there are issues with IPv6 in the libc included in Ubuntu 14.04 as made available by travis

___Noddos v0.2.3 - 6/14/2017___

Minor bug fix to run the Device Match algorithm periodically instead of constantly.

___Noddos v0.2.2 - 5/31/2017___

Unfortunately, the move on Lede firmware to not configure a custom log file for dnsmasq but configure logd to write to a system log file did not work out so reverting this until we can get a more permanent solution

___Noddos v0.2.1 - 5/27/2017___

Bug fixes:
* Allows Device Report uploads to be disabled.
* Improves efficiency by storing mac addresses and IP addresses as integers (mac- and ipv4 addresses) or byte arrays (ipv6 addresses) instead of std::strings.
* Fixes the LEDE installation instructions as an incorrect file was being referenced.

___Noddos v0.2.0 - 5/21/2017___

This release of Noddos adds integration with the Luci web-interface and its configuration management interface.

Bug fixes to:
* Lede init.d/procd scripts
* Cert handling
* Pruning as cached objects
* Loading of DeviceMatches, import IP addresses
* Logging in Host class

___Noddos v0.1.0 - 4/16/2017___

Initial release of Noddos C++ client for Linux desktop/server distributions. Features:
* Parsing of dnsmasq log data for DHCP and DNS information
* Listening to SSDP messages and getting location data from UPnP hosts
* Receiving connection information from Linux firewall
* Securely downloading [Device Profiles](https://github.com/noddos/noddosprofiles)
* Recognizing devices based on device profiles
* Optionally uploading device stats to the cloud for unrecognized devices
* Optionally uploading traffic stats to the cloud for recognized devices
* Dumping device database to local file when SIGUSR[1|2] signal is received

