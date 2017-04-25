[![Build Status](https://travis-ci.org/noddos/noddos.svg?branch=master)](https://travis-ci.org/noddos/noddos)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/97e9282c128543edab63fcb92f576fd7)](https://www.codacy.com/app/noddos/noddos?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=noddos/noddos&amp;utm_campaign=Badge_Grade)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/879/badge)](https://bestpractices.coreinfrastructure.org/projects/879)
[![SSL Rating](https://sslbadge.org/?domain=www.noddos.io)](https://www.ssllabs.com/ssltest/analyze.html?d=www.noddos.io)

# Noddos - A device-aware firewall

The Noddos client monitors network traffic in the home- or enterprise network, identifies with IOT devices are present and dynamically applies device-specific ACLs to the traffic of the IOT devices to stop a device from sending rogue traffic, for example when being used in a DDOS attack. The ACLs are downloaded from the cloud and are generated based on traffic stats uploaded anonymously by the Noddos client. You can install the Noddos client on Linux-based (DIY) routers and firewalls and real soon now on Home Gateways running OpenWRT. For more information see the [NoDDos website](https://www.noddos.io/). 

The current focus of Noddos is on building the database of device profiles by getting the client distributed. The implementation of the firewall functionality will start once the collection functionality is up and running and available in the C++ client on OpenWRT routers.

## Client Overview

Noddos runs as a daemon to listen to DHCP, DNS and SSDP traffic on the home network. It reads DHCP and DNS data from the dnsmasq daemon that should be configured to log extended DNS and DHCP data. If incoming SSDP data has a 'Location' header than nodlisten will call the URL contained in the header to collect additional device information. Using the Linux Netfilter functionality, it tracks network flows in real time. Noddos reads the DeviceProfiles file that specifies the matching conditions and traffic filtering rules. Every hour, Noddos matches discovered devices with the device profile database to identify known devices. Noddos can be configured upload traffic statistics for identified devices and device attributes for devices it not yet has been able to match to a device profile. There is a configuration file that can be used to specify a.o. whether traffic and device statistics should be uploaded and whether or not they should be uploaded anonymously. The Noddos process should be started at boot time.

The 'getdeviceprofiles.sh' script is used to securely download the list of Device Profiles over HTTPS from the Noddos web site, check the digital signature of the file using a Noddos certificate and makes the file available to the Noddos client. It needs access to the public cert that was used to sign the file. This script should be called at least once per day from cron. 

## Installation

Prerequisites
- Linux v2.6.13 or later (as inotify support is needed)
- dnsmasq
- openssl
- libopenssl
- libcurl 
- libnetfilter_conntrack
- wget (preferred because of conditional GET support) or curl
- ca-certificates 
- gzip or bzip2 or brotli (latter is preferred due to superior compression rate)

Noddos leverages dnsmasq logs. The following changes are required to make dnsmasq log the right data to the right place: 

    cat >>/etc/dnsmasq.conf <<EOF
    log-queries=extra
    log-dhcp
    EOF

    sed -i 's|procd_set_param command $PROG -C $CONFIGFILE -k -x /var/run/dnsmasq/dnsmasq.pid|procd_set_param command $PROG -C $CONFIGFILE --log-facility /var/log/dnsmasq.log -k -x /var/run/dnsmasq/dnsmasq.pid|' /etc/init.d/dnsmasq

    cat >/etc/logrotate.d/dnsmasq <<EOF
    /var/log/dnsmasq.log
    {
        rotate 7
        daily
        su root syslog
        size 10M
        missingok
        notifempty
        #nodelaycompress
        compress
        postrotate
        /usr/bin/killall -SIGUSR2 dnsmasq
        endscript
    }
    EOF

Set up Noddos 

### Compile noddos yourself
    # install development packages for libcurl, libopenssl and libnetfilter_conntrack
    git clone https://github.com/noddos/noddos
    cd noddos/src

    # Install 3rd party development libraries
    sudo apt install libssl-dev
    sudo apt install libnetfilter-conntrack-dev
    sudo apt install libcurl4-openssl-dev

    # Download Requests library for C++
    git submodule add https://github.com/whoshuu/cpr.git
    git submodule update --init --recursive
    export BUILD_CPR_TESTS=OFF
    export USE_SYSTEM_GTEST=ON
    export USE_SYSTEM_CURL=ON
    cmake .
    make

    # Install openssl 
    sudo apt install openssl

    sudo adduser --system --home /var/lib/noddos --shell /bin/false \
         --disabled-login --disabled-password\
         --quiet  --group noddos
    sudo mkdir /etc/noddos
    sudo cp noddos.conf-sample /etc/noddos.conf
    sudo cp noddosconfig.pem /etc/noddos

    openssl req -x509 -nodes -subj '/CN=noddosapiclient' -newkey rsa:2048 -days 3650 \
         -keyout /etc/noddos/noddosapiclient.key -out /etc/noddos/noddosapiclient.pem

    ### edit /etc/noddos.conf, for one to whitelist the IP addresses of the interfaces of your router
    sudo chown -R root:root /etc/noddos
    chgrp noddos /etc/noddos/noddosapiclient.key
    chmod 640 /etc/noddos/noddosapiclient.key

    # getdeviceprofiles.sh needs the certificates of well-known CAs installed to be able to connect to
    # https://www.noddos.io/

    # Directory where DeviceProfiles.json will be downloaded to
    mkdir /var/lib/noddos
    chown noddos:noddos /var/lib/noddos

    sudo apt install ca-certificates
    install noddos -o 0 -g 0 -s noddos /usr/sbin 
    install noddos -o 0 -g 0 ../tools/getdeviceprofiles.sh /usr/sbin 
    # Install a cronjob to do this frequently (please pick a randon time of day instead of 3:23am), ie
    23 */3 * * * /usr/sbin/getdeviceprofiles.sh

    # Noddos needs to be started as root as it will need to get Linux
    # firewall connection state changes. It will drop to an unprivileged
    # user/group after that has been set up.
    sudo noddos 

## Command line options
The following command line options are supported by the Noddos client:
__-n, --no-daemon__: Don't run as daemon and send log messages to STDERR in addition to syslog
__-c, --config-file__: Location of configuration default, default /etc/noddos/noddos.conf
__-p, --no_prune__: Disable pruning of Hosts, DnsQueries, DHCP transactions and flows
__-f, --no_flowtrack__: Disable tracking IP flows
__-d, --debug__: Enable extensive logging, save uploaded data to /tmp
__-h, --help__: Print command line options

## Configuration file
The noddos client configuration file (Default: /etc/noddos/noddos.conf) is a JSON file with the configuration settings.

__DeviceProfilesFile__: The list of deviceprofiles for matching hosts against. This file is saved to this location by the shell script that downloads the file from the cloud and checks its signature. Default: /var/lib/noddos/DeviceProfiles.json

__DnsmasqLogFile__: The dnsmasq daemon is configured per the installation instructions to write his extended DNS and DHCP logging to this file. Nodddos tails this file, parses the log lines and populates its DNS and DHCP tables with the information. Default: /var/log/dnsmasq.log

__MatchFile__: Noddos will write all current matched devices to this file after receiving a SIGUSR1 or SIGTERM signal. At startup, Noddos will read this file to have an initial list of matched devices. Default: /var/lib/noddos/DeviceMatches.json

__DumpFile__: Noddos will write all informaiton it has on devices to this file after received a SIGUSR2 signal. Default /var/lib/nodds/DeviceDump.json

__ClientApiCertFile__: certificate for key used to authenticate against Noddos API. Default: /etc/noddos/noddosapiclient.pem

__ClientApiKeyFile__: Key used to authenticate against Noddos API. Default: /etc/noddos/noddosapiclient.key

__SignatureCertFile__: certificate used to validate the digital signature for the DeviceProfiles.json file. This setting is not used by Noddos itself but by the shell script that downloads the DeviceProfiles.json file from the cloud. Default: /etc/noddos/noddossignaturecert.pem

__PidFile__: Location for pidfile of nodlisten daemon.  Default: /var/lib/noddos/noddos.pid

__UploadMode__: If and how Noddos show upload data: Possible values: None, Anonymous, Account

__WhitelistedMacAddresses__: list of ethernet MAC addresses that that should not have any data uploaded to the cloud. Default: empty list of strings

__WhitelistedIpv4Addresses__: list of IPv4 addresses that that should not have any data uploaded to the cloud. This should contain the loopback address and typically the LAN IP address of the router/home-gateway. Default: empty list of strings

__WhitelistedIpv6Addresses__: list of IPv6 addresses that that should not have any data uploaded to the cloud. This should contain the loopback address and typically the LAN IP address of the router/home-gateway. Default: empty list of strings

__ReportTrafficToRfc1918__: should traffic to RFC1918 IP addresses be uploaded to the traffic stats API or not. There is currently no equivalent for IPv6 addresses. Default: false

__ListenInterfaces__: (not currently implemented) Interfaces on which noddos should listen for SSDP traffic. Mutually exclusive with 'ipaddress'. Default: empty list, causes Noddos to listen on all interfaces and their IP addresses.

__ListenIpaddresses__: (not currently implemented) IP address of the NICs connected to the network for noddos to listen for SSDP traffic on. Default: empty list, causes Noddos to listen on all interfaces and their IP addresses.

__TrafficReportInterval__: Interval between uploads of traffic stats for matched devices. To disable upload of traffic uploads, set this value to 0. Default: 3600 seconds

__DeviceReportInterval__: Interval between uploads of data on unmatched devices. To disable upload of device reports, set this value to 0. Default: 14400 seconds

__ExpireDnsQuery__: Cached DNS records will be pruned after this interval. This should be larger of typical largest TTL seen on DNS records. Default: 86400 seconds
Default: 7 days
Command line option: -d, --dnsexpire (janitor.py)

__ExpireHost__: Cached Host records will be deleted if no traffic is seen from them based on this setting. Default: 604800 seconds
Default: 7 days

## Signals
Noddos handles the following signals

__SIGTERM__: Writes DeviceMatches.json file and exits.

__SIGHUP__: Reloads noddos.conf and DeviceProfiles.json.

__SIGTERM1__: Writes DeviceMatches.json file.

__SIGTERM2__: Runs matching alogirithm, writes Devicedump.json and uploads (if not disabled) device info and traffic stats to the cloud.

## Installation on OpenWRT
(TODO: to be updated for C++ client)
The Noddos client can be installed on OpenWRT but keep in mind that:
- You also need to install the Dnsmasq DHCP/DNS server
- You will need SSH access to your Home Gateway as there is no OpenWRT package for the NoDDos client

