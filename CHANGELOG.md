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

