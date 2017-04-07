# Noddos - A device-aware firewall

The Noddos client monitors network traffic in the home- or enterprise network and dynamically applies device-specific ACLs to that traffic to stop a device from sending rogue traffic, for example when being used in a DDOS attack. The ACLs are downloaded from the cloud and are generated based on traffic data uploaded anonymously by the NoDDos client. You can install the NoDDos client on Linux-based (DIY) routers and firewalls and on Home Gateways running OpenWRT. For more information see the [NoDDos website](https://www.noddos.io/). The Python client has been removed as it will soon be replaced by a C++ client that is faster, uses less memory, doesn't rely on Ulogd and that is easier to run on OpenWRT routers.

The current focus of Noddos is on building the database of device profiles by getting the client distributed. The implementation of the firewall functionality will start once the collection functionality is up and running and available in the C++ client on OpenWRT routers.

## Client Overview

##### noddos
Noddos runs as a daemon to listen to DHCP, DNS and SSDP traffic on the home network. It reads DHCP and DNS data from the dnsmasq daemon that should be configured to log extended DNS and DHCP data. If incoming SSDP data has a 'Location' header than nodlisten will call the URL contained in the header to collect additional device information. Using the Linux Netfilter functionality it tracks network flows in real time. Noddos reads the DeviceProfiles file that specifies the matching conditions and traffic filtering rules. Every hour, Noddos matches discovered devices with the device profile database to identify known devices. Noddos can be configured upload traffic statistics for identified devices and device attributes for devices it not yet has been able to match to a device profile. There is a configuration file that can be used to specify a.o. whether traffic and device statistics should be uploaded and whether or not they should be uploaded anonymously. The process should be started at boot time.

##### getdeviceprofiles.sh
The 'getdeviceprofiles.sh' script is used to securely download the list of Device Profiles over HTTPS from the Noddos web site, check the digital signature of the file using a Noddos certificate and makes the file available to the Noddos client. It needs access to the public cert that was used to sign the file. This script should be called at least once per day from cron. 

## Installation

Prerequisites
- Linux v2.6.13 or later (as inotify support is needed)
- dnsmasq
- openssl
- libcurl 
- libnetfilter_conntrack
- wget (preferred because of conditional GET support) or curl
- gzip or bzip2 or brotli (latter is preferred due to superior compression rate)

NoDDos leverages dnsmasq logs. 

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

Set up NoDDos 

### Compile noddos yourself
    # install development packages for libcurl and libnetfilter_conntrack
    git clone https://github.com/noddos/noddos
    cd noddos

    sudo mkdir /var/log/noddos /etc/noddos/ /var/lib/noddos
    MYUSERNAME=`whoami`
    sudo chown $MYUSERNAME /var/log/noddos /etc/noddos /var/lib/noddos

    cp noddosconfig.crt /etc/noddos
    tools//getdeviceprofiles.sh 
    # Install a cronjob to do this frequently (please pick a randon time of day instead of 3:23am), ie
    # 23 */3 * * * /path/to/noddos/tools/getdeviceprofiles.sh

    cp noddosconfig-sample.json /etc/noddosconfig.json

    tools/makecert.sh
    mv noddosapiclient.pem /etc/noddos

    # Nodlisten is still at alpha quality so best to run it from `screen' without spanning a daemon.
    noddos -n

## Configuration (to be updated with release of C++ client)
The noddos client configuration file (Default: /etc/noddos/noddosconfig.json, -c / --configurationfile command line parameter) is a JSON file with a JSON object under the 'client' key. Some of its settings can be overrriden by command line options. The keys for the configuration items in the JSON file are:

__whitelistmac__: list of ethernet MAC addresses that that should not have any data  uploaded to the cloud.
Default: empty list of strings
Command line option: none

__whitelistipv4__: list of IPv4 addresses that that should not have any data uploaded to the cloud.
Default: empty list of strings
Command line option: none

__whitelistipv6__: list of IPv6 addresses that that should not have any data uploaded to the cloud.
Default: empty list of strings
Command line option: none

__signaturecert__: certificate used to validate the digital signature for the DeviceProfiles.json file.
Default: /etc/noddos/noddosconfig.crt
Command line option: -c, --certificate (getdeviceprofiles.sh)

__clientcert__: authentication certificate for the client when calling NoDDos cloud APIs.
Default: /etc/noddos/noddosconfig.crt
Command line option: -e, --clientcertificate (nodreport.py)

__lastrunfile__: Keeps track of when nodreport was last executed. Hosts that are mapped to a device profile will only be re-evaluated by nodreport if t
he value of the LastUpdate field in the device profile is greater than the last time that nodreport ran.
Default: /var/log/noddos/reporter-lastrun.out
Command line option: none

__dbfile__: SQLite3 database that locally stores all information collected by nodlisten and the mappings from hosts to device profiles found by no
dreporter.
Default: /var/log/noddos/noddos.db
Command line option: -s, --dbfile (nodreport.py, nodlisten.py, janitor,py)

__ulogdbfile__: SQLite3 database that locally stores all information collected by ulogd.
Default: /var/log/ulog/ulog.sqlite3db
Command line option: -u, --ulogdbfile (nodreport.py, janitor,py)

__dnsmasqlog__: The dnsmasq daemon is configured per the installation instructions to write his extended DNS and DHCP logging to this file. Nodlisten
tails this file, parses the log lines and puts the data in noddos.db.
Default: /var/log/dnsmasq.log
Command line option: none
BUG: hardcoded in nodlisten because of some issues with calling inotify.

__deviceprofilesfile__: The list of deviceprofiles for matching hosts against.
Default: /var/lib/noddos/DeviceProfiles.json
Command line option: -p, --deviceprofiles (nodreport.py)

__apiserver__: The FQDN of the Noddos API server in the cloud.
Default: api.noddos.io
Command line option: -a, --apiserver (nodreport.py)

__logfilenodlisten__: File to which nodlisten sends logging info.
Default: (no logging)
Command line option: -l, --logfile (nodlisten.py)

__logfilenodreport__: File to which nodreport sends logging info
Default: (no logging).
Command line option: -l, --logfile (nodreport.py)

__loglevelnodlisten__: debug level of nodlisten, can be 'debug', 'info', 'warning', 'error' or 'critical'.
Default: warning
Command line option: -v, --verbose (nodlisten.py, nodreport.py)

__loglevelnodreport__: debug level of nodlisten, can be 'debug', 'info', 'warning', 'error' or 'critical'.
Default: warning
Command line option: -v, --verbose (nodreport.py)

__ipaddress__: IP address of the NIC connected to the home network for nodlisten to listen for SSDP traffic on.
Default: none
Command line option: -a --ip-address (nodlisten.py)

__interface__: BUG: not currently implemented. Interface on which nodlisten should listen for SSDP traffic. Mutually exclusive with 'ipaddress'.
Default: none
Command line option: -i, --interface (nodlisten.py)

__pidfile__: Location for pidfile of nodlisten daemon.
Default: /var/log/noddos/nodlisten.pid
Command line option: -p, --pidfile (nodlisten.py)

__nodaemon__: Nodlisten can remain in the foreground for debugging purposes if this is set to true.
Default: false
Command line option: -n, --nodaemon (nodlisten.py)

__expiredns__: The janitor will delete DNS queries older than the value for this key in seconds from noddos.db.
Default: 7 days
Command line option: -d, --dnsexpire (janitor.py)

__expiretraffic__: The janitor will delete IP flow stats older than the value for this key in seconds from noddos.db.
Default: 12 hours
Command line option: -t, --trafficexpire (janitor.py)

__expirehost__: The janitor will delete hosts not seen on the network for longer than the value for this key in seconds from noddos.db
Default: 7 days
Command line option: -e, --hostexpire (janitor.py)

## Installation on OpenWRT
The NoDDos client can be installed on OpenWRT but keep in mind that:
- You also need to install the Dnsmasq DHCP/DNS server
- You will need SSH access to your Home Gateway as there is no OpenWRT package for the NoDDos client

