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

