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
