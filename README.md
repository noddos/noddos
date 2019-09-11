[![Noddos Intro](https://www.noddos.io/assets/images/noddos-slide.gif)](https://www.noddos.io)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/879/badge)](https://bestpractices.coreinfrastructure.org/projects/879)
[![SSL Rating](https://sslbadge.org/?domain=www.noddos.io)](https://www.ssllabs.com/ssltest/analyze.html?d=www.noddos.io)

# Noddos - A device-aware firewall

The Noddos client monitors network traffic in the home- or enterprise network, identifies IOT and other devices and dynamically applies device-specific ACLs to the traffic of the identified devices. Its goal is to identify and stop rogue traffic from devices that have been breached, for example when a device is being used in a DDOS attack. The ACLs are downloaded from the cloud and are generated based on traffic stats uploaded anonymously by the Noddos client. You can install the Noddos client on Linux-based (DIY) routers and firewalls and on Home Gateways running firmware from the Lede project.

## Client Overview

Noddos runs as a daemon to listen to DHCP, DNS, mDNS/DNS-SD, UPnP/SSDP and WS-Discovery traffic and to monitor traffic flows on the home or enterprise network. It reads DHCP and DNS data by sniffing those packets using AF_PACKET_RING. If incoming SSDP data has a 'Location' header then Noddos will call the URL contained in the header to collect additional device information. Using the Linux Netfilter functionality, Noddos tracks network flows in real time using either /proc/net/nf_conntrack if available or otherwise using the Linux NFCT API.
Noddos reads a file with Device Profiles that specifies the matching conditions and traffic filtering rules. Periodically, Noddos matches discovered devices with the [device profile database](https://github.com/noddos/noddosprofiles/) to identify known devices. Noddos can be configured to upload traffic statistics for identified devices and device attributes for devices it has not yet been able to identify. The Noddos configuration file specifies a.o. whether traffic and device statistics should be uploaded [anonymously](https://github.com/noddos/noddos/wiki/Privacy).

The Noddos process should be started at boot time. The Noddos package for routers running firmware of the [Lede project](https://lede-project.org/) includes an init.d/procd script that launches Noddos. The process runs as a daemon and needs to run as root so it can update firewall rules. Depending on traffic patterns and the processor architecture, typically the client consumes about 10MB of DRAM. The CPU usage for the process is all but negligible at 1-2%. 

The 'getnoddosdeviceprofiles' script is used to securely download the list of Device Profiles over HTTPS from the Noddos web site, check the digital signature of the file using a Noddos certificate and makes the downloaded file available to the Noddos client. It needs access to the public cert for the key that was used to sign the file. That public key is included in the software distribution of Noddos. Th getnoddosdeviceprofiles script should be called at least once per day from cron. 

## Installation 
* [Install instructions](https://github.com/noddos/noddos/wiki/Installing-Noddos-on-a-router-running-firmware-from-Project-LEDE) for routers running firmware from Project Lede.
* Sorry, there are no packages yet for Ubuntu / Fedora / CentOS / Gentoo. For now, just compile it from source using the instructions provided below.

## Compilation
Compilation instructions are available for Home Gateways and regular Linux systems.
* [Compile with Project LEDE SDK](https://github.com/noddos/noddos/wiki/Compiling-Noddos-for-project-LEDE-routers)
* [Compile and install for Linux systems](https://github.com/noddos/noddos/wiki/Compile-&-Install-Noddos-for-generic-Linux-routers-or-firewalls)

## Configuration file
* [Configuring](https://github.com/noddos/noddos/wiki/Configuring-the-Noddos-firewall) Noddos through the noddos.yml file

## Command line options
The following command line options are supported by the Noddos client:
* __-n, --no-daemon__: Don't run as daemon and send log messages to STDERR in addition to syslog
* __-c, --config-file__: Location of configuration file, default /etc/noddos/noddos.conf
* __-d, --debug__: Enable extensive logging, save uploaded data to /tmp
* __-h, --help__: Print command line options

## Signals
Noddos handles the following signals

* __SIGTERM__: Writes DeviceMatches.json file and exits.
* __SIGHUP__: Reloads noddos.conf and DeviceProfiles.json.
* __SIGUSR1__: Runs matching alogrithm and writes DeviceDump.json file.
* __SIGUSR2__: Runs matching algorithm and uploads (if not disabled) device info and traffic stats to the cloud.

