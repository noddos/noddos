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

from datetime import datetime, timezone
import ipaddress
import re
import logging

#
# For DNS log messages, we're only interested at the initial lookup and at responses
# we ignore reverse lookups for now (so queries for records starting with digit are ignored)
#
dns_rx = re.compile(r'dnsmasq\[\d+?\]: (\d+?) (\d+?\.\d+?\.\d+?\.\d+?)\/\d+? (\D\S*?) (\D\S*?) (is|from) (\S+?)$', re.I)

class DnsQuery:
    def __init__(self, fqdn):
        self._Fqdn = fqdn
        self._Ips = set()
        self.lastseen_now()
        self.firstseen_now()
        self.lastmodified_now()

    @property
    def lastmodified(self):
        return self._LastModified

    @lastmodified.setter
    def lastmodified(self,lastmodified=None):
        if lastmodified is None:
            self._LastModified = datetime.now(timezone.utc)
        else:
            self._LastModified = lastmodified

    @property
    def lastseen(self):
        return self._LastSeen

    def lastseen_now(self):
        self._LastSeen = datetime.now(timezone.utc)

    @lastseen.setter
    def lastseen(self,lastseen=None):
        if lastseen is None:
            self._LastSeen = datetime.now(timezone.utc)
        else:
            self._LastSeen = lastseen

    @property
    def firstseen(self):
        return self._FirstSeen

    @firstseen.setter
    def firstseen(self,firstseen=None):
        if firstseen is None:
            self._FirstSeen = datetime.now(timezone.utc)
        else:
            self._FirstSeen = firstseen

    def firstseen_now(self):
        self._FirstSeen = datetime.now(timezone.utc)

    @property
    def lastmodified(self):
        return self._LastModified

    @lastmodified.setter
    def lastmodified(self,lastmodified=None):
        if lastmodified is None:
            self._LastModified = datetime.now(timezone.utc)
        else:
            self._LastModified = lastmodified

    def lastmodified_now(self):
        self._LastModified = datetime.now(timezone.utc)

    @property
    def fqdn(self):
        return self._Fqdn

    @fqdn.setter
    def fqdn(self, value):
        self._LastSeen = self.LastModified = datetime.now(timezone.utc)
        self._Fqdn = value

    @property
    def ips(self):
        return self._Ips

    @ips.setter
    def ips(self, value):
        self._LastSeen = self.LastModified = datetime.now(timezone.utc)
        self._Ips = value

    @ips.deleter
    def ips(self):
        del self._Ips

    def add_ip(self, ip):
        change = 0
        logging.debug("Is %s in set %s?", ip, str(self._Ips))
        if '.' in ip:
            #ipv4 = ipaddress.IPv4Address(ip)
            if ip in self._Ips:
                logging.debug("%s already has IPv4 address %s", self._Fqdn, ip)
            else:
                logging.debug("%s adding IPv4 address %s", self._Fqdn, ip)
                self._Ips.add(ip)
                change = 1
        elif ':' in ip:
            #ipv6 = ipaddress.IPv6Address(ip)
            if ip in self._Ips:
                logging.debug("%s already has IPv4 address %s", self._Fqdn, ip)
            else:
                logging.debug("%s adding IPv6 address %s", self._Fqdn, ip)
                self._Ips.add(ip)
                change = 1

        return change


    def update(self, fqdn, data):
       return self.add_ip(data)

