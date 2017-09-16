[![Noddos Intro](https://www.noddos.io/assets/images/noddos-slide.gif)](https://www.noddos.io)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/879/badge)](https://bestpractices.coreinfrastructure.org/projects/879)
[![SSL Rating](https://sslbadge.org/?domain=www.noddos.io)](https://www.ssllabs.com/ssltest/analyze.html?d=www.noddos.io)

# Noddos - A device-aware firewall

The Noddos client monitors network traffic in the home- or enterprise network, identifies IOT and other devices and dynamically applies device-specific ACLs to the traffic of the identified devices. Its goal is to identify and stop rogue traffic from devices that have been breached, for example when a device is being used in a DDOS attack. The ACLs are downloaded from the cloud and are generated based on traffic stats uploaded anonymously by the Noddos client. You can install the Noddos client on Linux-based (DIY) routers and firewalls and on Home Gateways running firmware from the Lede project. For more information see the [Noddos website](https://www.noddos.io/). 

## Client Overview

Noddos runs as a daemon to listen to DHCP, DNS and UPnP/SSDP traffic and monitor traffic flows on the home or enterprise network. It reads DHCP and DNS data by sniffing those packets using AF_PACKET_RING. If incoming SSDP data has a 'Location' header then Noddos will call the URL contained in the header to collect additional device information. Using the Linux Netfilter functionality, Noddos tracks network flows in real time using either /proc/net/nf_conntrack if available or otherwise using the Linux NFCT API.
Noddos reads a file with Device Profiles that specifies the matching conditions and traffic filtering rules. Periodically, Noddos matches discovered devices with the [device profile database](https://github.com/noddos/noddosprofiles/) to identify known devices. Noddos can be configured to upload traffic statistics for identified devices and device attributes for devices it has not yet been able to identify. The Noddos configuration file specifies a.o. whether traffic and device statistics should be uploaded.

The Noddos process should be started at boot time. The Noddos package for routers running firmware of the [Lede project](https://lede-project.org/) includes an init.d/procd script that launches Noddos. The process runs as a daemon and needs to run as root so it can update firewall rules. Depending on traffic patterns and the processor architecture, typically the client consumes about 10MB of DRAM. The CPU usage for the process is all but negligible at 1-2%. 

The 'getnoddosdeviceprofiles' script is used to securely download the list of Device Profiles over HTTPS from the Noddos web site, check the digital signature of the file using a Noddos certificate and makes the downloaded file available to the Noddos client. It needs access to the public cert for the key that was used to sign the file. That public key is included in the software distribution of Noddos. Th getnoddosdeviceprofiles script should be called at least once per day from cron. 

## Installation 

### Installation on Home Gateways running Lede firmware
Here are instructions for installing Noddos on Home Gateways running Lede firmware. Pre-built packages for all LEDE releases and most of the supported platforms are available from the [Noddos package feed](https://noddos.io/dist/lede/releases/<lede-release>/arch/<router-architecture>/packages/).

In the near future, a package will be made available for the Noddos Luci interface. Until that time, you can either manage the configuration of Noddos using UCI under /etc/config/noddos or you can clone the Noddos repository from Github and copy the following files for the LUCI user interface:

* files/clientdetails -> /www/cgi-bin
* files/clients.htm -> /usr/lib/lua/luci/view/admin_status
* files/dkjson.lua -> /usr/lib/lua
* files/noddos.lua -> /usr/lib/lua/luci/model/cbi/admin_network

We need to modify the menu structure of the Luci web interface to point to the Noddos Client and Configuration pages. First edit the file /usr/lib/lua/luci/controller/admin/status.lua. Insert on line 15:

    if nixio.fs.access("/usr/lib/lua/luci/view/admin_status/clients.htm") then
        entry({"admin", "status", "clients"}, template("admin_status/clients"), _("Clients"), 3)
    end

Then edit /usr/lib/lua/luci/controller/admin/network.lua, insert on line 116:

    if nixio.fs.access("/usr/lib/lua/luci/model/cbi/admin_network/noddos.lua") then
        page = entry({"admin", "network", "noddos"}, cbi("admin_network/noddos"), nil)
        page.target = cbi("admin_network/noddos")
        page.title = _("Client Tracking")
        page.order = 55
        page.leaf = true
    end

To make sure Luci picks up the menu and module changes, execute:

    rm /tmp/luci-modulecache 
    rm /tmp/luci-indexcache

Now we can install the actual Noddos package (and the libtins package that is also needed) that you can download from Noddos website. You'll need to know the version of Lede you are running and the architecture of your platform to be able to select the right build for your router.

    wget https://noddos.io/dist/lede/releases/<lede-release>/arch/<arch>/packages/devel/noddos_v0.4.0-1_<soc>.ipk
    wget https://noddos.io/dist/lede/releases/<lede-release>/arch/<arch>/packages/devel/libtins_v3.5-1_<soc>.ipk
    opkg update
    opkg install libtins_v3.5-1_<soc>.ipk
    opkg install noddos_0.4.0-1_<soc>.ipk

If you installed the Luci Noddos UI, go to the Luci -> Network -> Client Firewall page to configure Noddos. Make sure to include the Loopback, WAN and LAN IP- or MAC-addresses of your router in the whitelists. Populate the lists of LanInterfaces and WanInterfaces with your interface names as DNS and DHCP snooping use that to select the interfaces they accept traffic from. You may also want to whitelist addresses of your PCs that you use daily as collecting traffic statistics for them is of not much use with the traffic they generate to so many destinations. You may also want to add the MAC addresses of phones or tablets. If you didn't install the Noddos Luci UI then you can make your changes directly in /etc/config/noddos. Don't forget to execute 'uci commit' after you're done edting the file.

    service noddos restart

Install a cronjob to download the Device Profiles database frequently (please pick a randon minute instead of 23 minutes after the hour, ie:

    crontab -e 
        23 */3 * * * /usr/bin/getnoddosdeviceprofiles; if [ $? -gt 0 ]; then service noddos reload; fi

If you want maximum privacy for uploads, create a new client cert every 12 hours or so. That does mean that going forward you may not be able to use some newly developed Noddos portal functions. Create a cronjob for root:

    crontab -e 
        41 */12 * * * cd /etc/noddos; /usr/bin/makenoddoscert.sh

The installation script for Noddos automatically creates a 'NODDOS' chain in the filter table of ip(6)tables and adds as first entry in the FORWARD chain of the filter table a rule to process all traffic with the NODDOS chain. Depending on your requirements, you may customize this rule or put it different location of the FORWARD chain.

### Installation for Linux DIY routers
Sorry, there are no packages yet for Ubuntu / Fedora / CentOS / Gentoo. For now, just compile it from source using the instructions provided below.

## Compilation
Compilation instructions are available for Home Gateways and regular Linux systems.

### Compilation for a Home Gateway running firmware of the [Lede project](https://lede-project.org/) for Noddos
Noddos can be compiled and installed on most if not all of the platforms supported by Lede 17.01.x releases. Use these instructions to generate your own package. These instructions are based on the Lede 17.01.2 release.

    mkdir -p noddosbuild/package/{noddos,libtins}
    cd noddosbuild
    wget https://raw.githubusercontent.com/noddos/noddos/master/lede/packages/noddos/Makefile -O package/noddos/Makefile
    ROOTDIR=$PWD

Download the Lede project SDK v17.01.2 for your platform from [Lede Table of Hardware](https://lede-project.org/toh/start)

    tar xf <SDK-for-your-platform-tarbar>
    cd <SDK-directory-for-your-platform>
    echo "src-link custom $ROOTDIR/package" >>feeds.conf.default

    make menuconfig

In the firmware build menu:
- Select "Global Build Settings" and press enter, in the submenu deselect/exclude the following options:
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
- Enable building of the Noddos package, go to "Network" menu, have Noddos build as module ('M')
- Select the Save menu option, save to '.config' and then select 'Exit' and again 'Exit'

Now we just have to build the packages:

    make -j4

Change the architecture directory and architecture ipkg to match your HGW platform

    scp bin/packages/arm_cortex-a9_vfpv3/custom/libtins-v.3.5-1_arm_cortex-a9_vfpv3.ipk root@<HGW-IP>:
    scp bin/packages/arm_cortex-a9_vfpv3/custom/noddos-v0.4.0-1_arm_cortex-a9_vfpv3.ipk root@<HGW-IP>:

Follow the installation instructions from this point onwards.


### Compilation for a Linux DIY router
Your Linux DIY router should be running a Linux kernel 2.6.13 or newer. These instructions assume you have the development tools such as C++, ld, make, cmake installed.

### Compile Noddos yourself
Install development packages for libcurl, libopenssl and libnetfilter_conntrack

    sudo apt install libssl-dev libnetfilter-conntrack-dev libcurl4-openssl-dev libtins-dev libipset-dev

    git clone https://github.com/noddos/noddos
    cd noddos
    cmake .
    make
    sudo apt install openssl libcurl3 libtins3.4 brotli wget libnetfilter-conntrack3 ca-certificates ipset iptables-persistent
    make test

### Install Noddos
Install needed apps

    sudo adduser --system --home /var/lib/noddos --shell /bin/false \
         --disabled-login --disabled-password \
         --quiet  --group noddos
    sudo mkdir /etc/noddos
    sudo cp noddos.conf-sample /etc/noddos/noddos.conf
    sudo cp files/noddosconfig.pem /etc/noddos

Edit /etc/noddos.conf, to at least set the LanInterfaces and WanInterfaces and to whitelist the IP addresses of the interfaces of your router

    sudo chown -R root:root /etc/noddos

Directory where DeviceProfiles.json will be downloaded to

    sudo mkdir /var/lib/noddos
    sudo chown noddos:noddos /var/lib/noddos

    sudo install -o 0 -g 0 -s src/noddos /usr/sbin 
    sudo install -o 0 -g 0 tools/getnoddosdeviceprofiles /usr/bin 
    sudo install -o 0 -g 0 tools/makenoddoscert.sh /usr/bin 
 
    sudo -u noddos bash /usr/bin/getnoddosdeviceprofiles

    cd /etc/noddos
    /usr/bin/makenoddoscert.sh
    sudo chgrp noddos /etc/noddos/noddosapiclient.key
    sudo chmod 640 /etc/noddos/noddosapiclient.key
    
Install firewall rules. This example puts the NODDOS user-defined chain at the start of the FORWARD chain of the ilter table. You may want to put it in a different location and you may want to specify the interfaces for which you want traffic to be processed by the NODDOS chain

    iptables -N NODDOS
    iptables -t filter -I FORWARD -j NODDOS
    ip6tables -N NODDOS
    ip6tables -t filter -I FORWARD -j NODDOS

Install a cronjob for user noddos to do this frequently (please pick a randon time of day instead of 3:23am), ie:

    23 */3 * * * bash /usr/bin/getnoddosdeviceprofiles; if [ $? -gt 0 ]; then kill -SIGHUP $(cat /var/lib/noddos/noddos.pid); fi

If you want maximum privacy, create a new client cert every 6 hours or so. That does mean that going forward you may not be able to use some newly developed Noddos portal functions. Create a cronjob for root:

    23 */6 * * * cd /etc/noddos; /usr/bin/makenoddoscert.sh

Noddos needs to be run as root as it will need to make Linux firewall changes. 

    sudo noddos 

## Command line options
The following command line options are supported by the Noddos client:
* __-n, --no-daemon__: Don't run as daemon and send log messages to STDERR in addition to syslog
* __-c, --config-file__: Location of configuration default, default /etc/noddos/noddos.conf
* __-d, --debug__: Enable extensive logging, save uploaded data to /tmp
* __-h, --help__: Print command line options

## Configuration file
The Noddos client configuration file (Default: /etc/noddos/noddos.conf) is a JSON file with the configuration settings.

__DeviceProfilesFile__: The file with the list of device profiles for matching hosts against. This file is saved to this location by the shell script that downloads the file from the cloud and checks its signature. Default: /var/lib/noddos/DeviceProfiles.json

__MatchFile__: Noddos will write all current matched devices to this file after receiving a SIGTERM signal. At startup, Noddos will read this file to have an initial list of matched devices. Default: /var/lib/noddos/DeviceMatches.json on Linux systems and /etc/noddos/DeviceMatches.json on routers with Lede firmware

__DumpFile__: Noddos will write all informaiton it has on devices to this file after received a SIGUSR1 signal. Default /var/lib/noddos/DeviceDump.json on Linux systems and /tmp/Devicedump.json on routers with Lede firmware

__DnsCacheFile__: Noddos will write all cached DNS data to this file after received a SIGUSR1 signal or at program exit. Default /var/lib/noddos/DnsCache.json.

__ClientApiCertFile__: certificate for key used to authenticate against Noddos API. Default: /etc/noddos/noddosapiclient.pem

__ClientApiKeyFile__: Key used to authenticate against Noddos API. Default: /etc/noddos/noddosapiclient.key

__SignatureCertFile__: certificate used to validate the digital signature for the DeviceProfiles.json file. This setting is not used by Noddos itself but by the shell script that downloads the DeviceProfiles.json file from the cloud. Default: /etc/noddos/noddossignaturecert.pem

__FirewallRulesFile__: location of file where Noddos will save the firewall rules for the NODDOS chain. Noddos will then execute the iptables-restore command to update the NODDOS chain in the filter table of iptables. Default: /var/lib/noddos/iptables.rules

__FirewallBlockTraffic__: Boolean that specifies whether firewall rules should block (true) certain traffic or whether it should just log (false) violations. As Noddos is still pre-release software, blocking traffic may impact the functioning of your devices and is thus not adviced. Default: false

__PidFile__: Location for file with the pid of the noddos client.  Default: /var/lib/noddos/noddos.pid

__UploadMode__: If and how Noddos show upload data: Possible values: None or Anonymous.

__WhitelistedMacAddresses__: list of ethernet MAC addresses that that should not have any data uploaded to the cloud. Default: empty list of strings

__WhitelistedIpv4Addresses__: list of IPv4 addresses that that should not have any data uploaded to the cloud. This should contain the loopback address and typically the LAN IP address of the router/home-gateway. Default: empty list of strings

__WhitelistedIpv6Addresses__: list of IPv6 addresses that that should not have any data uploaded to the cloud. This should contain the loopback address and typically the LAN IP address of the router/home-gateway. Default: empty list of strings

__ReportTrafficToRfc1918__: should traffic to RFC1918 IP addresses be uploaded to the traffic stats API or not. There is currently no equivalent for IPv6 addresses. Default: false

__WanInterfaces__: Interfaces on which Noddos should accept DNS answers. Default: empty list causes Noddos to discard all DNS answers, so one or more values should be provided for DNS snooping to work.

__LanInterfaces__: Interfaces on which Noddos should listen for DNS messages without answers. Currently unimplemented but planned: Noddos will only listen to SSDP multicast on these interfaces and Noddos will only perform ARP lookups on these interfaces. Default: empty list, which means Noddos will discard DNS queries so one or more values should be provided for DNS snooping to work.

__WsDiscoveryProbeInterval__: Interval between sending of WS-Discovery probes. Default: 3600 seconds

__TrafficReportInterval__: Interval between uploads of traffic stats for matched devices. To disable upload of traffic uploads, set this value to 0. Default: 3600 seconds

__DeviceReportInterval__: Interval between uploads of data on unmatched devices. To disable upload of device reports, set this value to 0. Default: 14400 seconds

__ExpireHost__: Cached Host records will be deleted if no traffic is seen from them based on this setting. Default: 90 days

## Signals
Noddos handles the following signals

__SIGTERM__: Writes DeviceMatches.json file and exits.

__SIGHUP__: Reloads noddos.conf and DeviceProfiles.json.

__SIGUSR1__: Runs matching alogrithm and writes DeviceDump.json file.

__SIGUSR2__: Runs matching algorithm and uploads (if not disabled) device info and traffic stats to the cloud.

