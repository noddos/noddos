[![Build Status](https://travis-ci.org/noddos/noddos.svg?branch=master)](https://travis-ci.org/noddos/noddos)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/97e9282c128543edab63fcb92f576fd7)](https://www.codacy.com/app/noddos/noddos?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=noddos/noddos&amp;utm_campaign=Badge_Grade)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/879/badge)](https://bestpractices.coreinfrastructure.org/projects/879)
[![SSL Rating](https://sslbadge.org/?domain=www.noddos.io)](https://www.ssllabs.com/ssltest/analyze.html?d=www.noddos.io)

# Noddos - A device-aware firewall

The Noddos client monitors network traffic in the home- or enterprise network, identifies IOT and other devices and dynamically applies device-specific ACLs to the traffic of the identified devices. It's goal is to identify and stop rogue traffic from devices that have been hacked, for example when a device is being used in a DDOS attack. The ACLs are downloaded from the cloud and are generated based on traffic stats uploaded anonymously by the Noddos client. You can install the Noddos client on Linux-based (DIY) routers and firewalls and on Home Gateways running firmware from the Lede project. For more information see the [Noddos website](https://www.noddos.io/). 

The current focus of Noddos is on building the database of device profiles by getting the client installed on many devices. The short-term goal is to make the client available for as many platforms as possible and entice people to install the software by giving them views on the collected data for the devices in their home. With many clients reporting data, we can enhance the database of device profiles. When that is well underway the focus will shift to adding the actual firewall capability.

## Client Overview

Noddos runs as a daemon to listen to DHCP, DNS and SSDP traffic on the home network. It reads DHCP and DNS data from the dnsmasq daemon that should be configured to log extended DNS and DHCP data. If incoming SSDP data has a 'Location' header then Noddos will call the URL contained in the header to collect additional device information. Using the Linux Netfilter functionality, it tracks network flows in real time.
Noddos reads the DeviceProfiles file that specifies the matching conditions and traffic filtering rules. Periodically, Noddos matches discovered devices with the device profile database to identify known devices. Noddos can be configured upload traffic statistics for identified devices and device attributes for devices it not yet has been able to match to a device profile. There is a configuration file that can be used to specify a.o. whether traffic and device statistics should be uploaded and whether or not they should be uploaded anonymously.

The Noddos process should be started at boot time. A systemctl file is included in the source for Ubuntu systems and an init.d/procd script is automatically installed by the package for [Lede project](https://lede-project.org/) firmware. The process runs as a daemon and can drop privileges after initial startup. Due to issues with polling the file handle for a netfilter conntrack connection, it is recommended to not drop privileges so it is possible to re-establish the filehandle after poll errors occur.

The 'getnoddosdeviceprofiles' script is used to securely download the list of Device Profiles over HTTPS from the Noddos web site, check the digital signature of the file using a Noddos certificate and makes the file available to the Noddos client. It needs access to the public cert that was used to sign the file. This script should be called at least once per day from cron. 

## Installation 

### Installation on Home Gateways running Lede firmware
Here are instructions for installing Noddos on Home Gateways running Lede firmware. At this time, the following packages are available:
- Linksys WRT AC series running using the [ARM Cortex A9 vfpv3 package architecture](https://lede-project.org/docs/instructionset/arm_cortex-a9_vfpv3) : [opkg link](placeholder)
- Various routers from Asus RT-AC56/68/87U, Buffalo, D-Link DIR-885L, Linksys EA6xxx, Netgear R6250/6300/7000/8000/9000 and TPlink Archer C5, C8, C9 using the [arm_cortex_A9 package architecture](https://lede-project.org/docs/instructionset/arm_cortex-a9): [opkg link](placeholder)

If you have a different router, you can either send me a request to build a package for that router or you can follow the instructions to create your own package. If someone wants a package for a router running OpenWRT then please ping me and I'll attempt to build a package for that firmware.
    
    ssh root@<HGW-IP>
    vi /etc/init.d/dnsmasq

We need to edit the dnsmasq start-up script to make sure it starts with the parameters that noddos needs
- (line numbers are based on the file with these modifications being applied)
- insert after line 602: append_parm "$cfg" "logdhcp" "--log-dhcp"
- insert after line 670:

	config_get dnsmasqlogfile "$cfg" logfile ""
	[ -n dnsmasqlogfile ] && {
		xappend "log-facility=$dnsmasqlogfile"
	}

- insert after line 772: procd_add_jail_mount_rw $dnsmasqlogfile

	 
After restart, there should be a /tmp/dnsmasq.log file
	service dnsmasq restart

Download the package and install it
	wget <package-url>
	opkg install <package>

Edit /etc/noddos/noddos.conf to add whitelisted hosts. Make sure to include the WAN and LAN IP- or MAC-addresses of your router. You may also want to include addresses of your PCs that you use daily as collecting traffic statistics for them is of no much use with the traffic they generate to so many destinations. You may also want to add the MAC addresses of phones or tablets. For more information, see the section below on the Noddos configuration file.

	/etc/init.d/noddos start

Optional: remove odhcp so dnsmasq becomes the DHCP server. That enables noddos to read the logs for DHCP transactions. If you use IPv6 from your ISP and have multiple routers that automatically get assigned a prefix from the prefix you get from your ISP then don't perform this step as dnsmasq doesn't support this functionality. If you don't uninstall odhcp then Noddos won't be able to recognize some devices as it won't have access to all the DHCP transaction details

	opkg remove odhcp
	/etc/init.d/dnsmasq restart

Install a cronjob to do this frequently (please pick a randon time of day instead of 3:23am), ie
	crontab -e -u noddos
    	23 */3 * * * /usr/bin/getnoddosdeviceprofiles

### Installation for Linux DIY routers
Sorry, there are no packages yet for Ubuntu / Fedora / CentOS / Gentoo. For now, just compile it from source.

## Compilation
Compilation instructions are available for Home Gateways and regular Linux systems.

### Compilation for a Home Gateway running firmware of the [Lede project](https://lede-project.org/)
Noddos is now up and running on Lede firmware installed on a a Linksys WRT 1200AC. There is also the package for Asus/Netgear/D-Link/Buffalo routers. If you have a HGW using a differnet platform then you can use these instructions to generate your own package. These instructions are based on the Lede 17.01.1 release.

	mkdir -p noddosbuild/package
	cd noddosbuild/package
	git clone https://github.com/noddos/noddos.git
	mv noddos/Makefile-LEDE noddos/Makefile
	cd ..
	ROOTDIR=$PWD

Download the Lede project SDK v17.01.1 for your platform from [Lede Table of Hardware](https://lede-project.org/toh/start)
	tar xf <SDK-for-your-platform-tarbar>
	cd <SDK-directory-for-your-platform>
    echo "src-link custom $ROOTDIR/package" >>feeds.conf.default

    make menuconfig

In the firmware build menu:
- Select Global Build Settings and press enter, in the submenu deselect/exclude the following options:
- "Select all target specific packages by default"
- "Select all kernel module packages by default"
- "Select all userspace packages by default"
- "Cryptographically sign package lists" 
- Select the Save menu option, save to '.config' and then select 'Exit' and again 'Exit'

Then execute the following commands:

    ./scripts/feeds update -a
    ./scripts/feeds install noddos
    make menuconfig

In the firmware build menu:
- Enable building of the noddos package, go to "Network" menu, have noddos build as module ('M')
- Select the Save menu option, save to '.config' and then select 'Exit' and again 'Exit'

Now we just have to build to package:

    make -j5 V=s

Change the architecture directory and architecture ipkg to match your HGW platform

    scp bin/packages/arm_cortex-a9_vfpv3/custom/noddos_1_arm_cortex-a9_vfpv3.ipk root@<HGW-IP>:

Follow the installation instructions from this point onwards.


### Compilation for a Linux DIY router
Your Linux DIY router should be running a Linux kernel 2.6.13 or newer. These instructions assume you have the development tools such as C++, ld, make, cmake installed.

### Compile noddos yourself
    # install development packages for libcurl, libopenssl and libnetfilter_conntrack
    sudo apt install libssl-dev
    sudo apt install libnetfilter-conntrack-dev
    sudo apt install libcurl4-openssl-dev

    git clone https://github.com/noddos/noddos
    cd noddos/src
    cmake .
    make
    make test

### Install noddos
Install needed apps
    sudo apt install openssl ssl libcurl3 brotli wget libnetfilter-conntrack3 ca-certificates

    sudo adduser --system --home /var/lib/noddos --shell /bin/false \
         --disabled-login --disabled-password\
         --quiet  --group noddos
    sudo mkdir /etc/noddos
    sudo cp noddos.conf-sample /etc/noddos.conf
    sudo cp files/noddosconfig.pem /etc/noddos

Edit /etc/noddos.conf, for one to whitelist the IP addresses of the interfaces of your router
    sudo chown -R root:root /etc/noddos
    sudo chgrp noddos /etc/noddos/noddosapiclient.key
    sudo chmod 640 /etc/noddos/noddosapiclient.key

Directory where DeviceProfiles.json will be downloaded to
    sudo mkdir /var/lib/noddos
    sudo chown noddos:noddos /var/lib/noddos

    sudo install noddos -o 0 -g 0 -s noddos /usr/sbin 
    sudo install noddos -o 0 -g 0 ../tools/getnoddosdeviceprofiles /usr/bin 
    sudo install noddos -o 0 -g 0 ../tools/makenoddoscert.sh /usr/bin 
 
	sudo -u noddos /usr/bingetnoddosdeviceprofiles

	cd /etc/noddos
	/usr/bin/makenoddoscert.sh
	
Install a cronjob for user noddos to do this frequently (please pick a randon time of day instead of 3:23am), ie
    23 */3 * * * /usr/bin/getnoddosdeviceprofiles

If you want maximum privacy, create a new client cert every 6 hours or so. That does mean that going forward you may not be able to use some newly developed Noddos portal functions. Create a cronjob for root:
    23 */6 * * * cd /etc/noddos; /usr/bin/makenoddoscert.sh

Noddos needs to be started as root as it will need to get Linux firewall connection state changes. It will drop to an unprivileged user/group after that has been set up if a user and group has been defined in /etc/noddos/noddos.conf. As there is an issue with errors occassionally occurring when polling a netfilter_conntrack filehandle, it is recommended to not define a user and group so noddos keeps running as root and is able to re-open the netfilter_conntrack connection.
    sudo noddos 

Noddos leverages dnsmasq logs. Look at what is installed on your router to make sure installing dnsmasq doesn't interfere with any other installed DNS or DHCP servers. The following changes are required to install dnsmasq and make dnsmasq log the right data to the right place: 

    sudo apt install dnsmasq
    
    cat >>/etc/dnsmasq.conf <<EOF
    log-queries=extra
    log-facility=/var/log/dnsmasq.log
    log-dhcp
    EOF

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


## Command line options
The following command line options are supported by the Noddos client:
* __-n, --no-daemon__: Don't run as daemon and send log messages to STDERR in addition to syslog
* __-c, --config-file__: Location of configuration default, default /etc/noddos/noddos.conf
* __-p, --no_prune__: Disable pruning of Hosts, DnsQueries, DHCP transactions and flows
* __-f, --no_flowtrack__: Disable tracking IP flows
* __-d, --debug__: Enable extensive logging, save uploaded data to /tmp
* __-h, --help__: Print command line options

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

