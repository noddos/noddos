# Copyright 2017 Steven Hessing
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import re
import ipaddress
import logging

dhcp_vendor_rx = re.compile(r'vendor class: (.*)$', re.I)
dhcp_clientprovidedname_rx = re.compile(r'client provides name: (.*)$', re.I)
dhcp_ack_rx = re.compile(r'DHCPACK\(.*?\) ([\d\.]*?) ([\w\d\:]*?)( (\w*))?$', re.I)

#
# DHCP related regexes. We first filter for dhcp log messages and then look for the
# dhcp log messages of interest to us.
#
dhcp_rx = re.compile(r'dnsmasq-dhcp\[\d+?\]: (\d+?) (.*)$', re.I)

class DhcpQuery:

    def __init__(self):
        self._HostName = ''
        self._Mac = ''
        self._Ipv4Address = ''
        self._Ipv6Address = ''
        self._ClientProvidedName = ''
        self._Vendor = ''

    @property
    def mac(self):
        return self._Mac

    @mac.setter
    def mac(self, mac):
        self._Mac = mac

    @property
    def ipv4address(self):
        return self._Ipv4Address

    @ipv4address.setter
    def ipv4address(self, ipv4address):
        self._Ipv4Address = ipv4address

    @property
    def ipv6address(self):
        return self._Ipv6Address

    @ipv6address.setter
    def ipv6address(self, ipv6address):
        self._Ipv6Address = ipv6address

    @property
    def clientname(self):
        return self._ClientProvidedName

    @clientname.setter
    def clientname(self, clientname):
        self._ClientProvidedName = clientname

    @property
    def hostname(self):
        return self._HostName

    @hostname.setter
    def hostname(self, hostname):
        self._HostName = hostname

    @property
    def vendor(self):
        return self._Vendor

    @vendor.setter
    def vendor(self, vendor):
        self._Vendor = vendor

    def addlogline(self, line):
        logging.debug("DHCP log: %s", line)
        m = dhcp_ack_rx.search(line)
        if m:
            self.ipv4address = m.group(1)
            self.mac = m.group(2)
            self.hostname = m.group(4)
            logging.debug("DHCPACK seen for %s %s %s", self.hostname, \
                self.ipv4address, self.mac)
            return True
        else:
            m = dhcp_vendor_rx.search(line)
            if m:
                self.vendor = m.group(1)
                logging.debug("DHCP vendor: %s", self.vendor)
                return True
            else:
                m = dhcp_clientprovidedname_rx.search(line)

                if m:
                    self.clientname = m.group(1)
                    logging.debug("DHCP client provided name: %s", self.clientname)
                    return True

        return False

