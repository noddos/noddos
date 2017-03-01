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
import sqlite3
import ipaddress
from dnsquery import DnsQuery
from datetime import datetime, timezone
import http.client
import logging

ssdp_rx = re.compile(r'(SERVER|LOCATION|NT|USN|USER-AGENT): (.*)', re.IGNORECASE)

#
# Regex's for SSDP host info coming from XML data in response to HTTP request
#
friendlyname_rx = re.compile(r'\<friendlyname\>(.*?)\<\/friendlyname\>', re.IGNORECASE | re.M | re.UNICODE )
manufacturer_rx = re.compile(r'\<manufacturer\>(.*?)\<\/manufacturer\>', re.IGNORECASE)
modelname_rx = re.compile(r'\<modelname\>(.*?)\<\/modelname>', re.I | re.M)
udn_rx = re.compile(r'\<udn\>(.*?)\<\/udn\>', re.IGNORECASE | re.M)
serialnumber_rx = re.compile(r'\<serialnumber\>(.*?)\<\/serialnumber\>', re.IGNORECASE | re.M)
manufacturerurl_rx = re.compile(r'\<manufacturerurl\>(.*?)\<\/manufacturerurl\>', re.IGNORECASE | re.M)
modelurl_rx = re.compile(r'\<modelurl\>(.*?)\<\/modelurl\>', re.IGNORECASE | re.M)


class Host:
    def __init__(self,sender):
        # Following items have getter/setters
        self._Ipv4Address = sender
        self._Ipv6Address=''
        self._Mac= self.discover_mac()
        self._Hostname=''
        self._DhcpHostname=''
        self._DhcpVendor=''

        # The remaining do not
        self._FirstSeen = self.lastseen_set()
        self.lastmodified_set()
        self._SsdpFriendlyName=''
        self._SsdpManufacturer=''
        self._SsdpModelName=''
        self._SsdpUdn=''
        self._SsdpSerialNumber=''
        self._SsdpManufacturerUrl=''
        self._SsdpModelUrl=''
        self._ssdp = dict()
        self._dns = dict()

    @property
    def ipv4address(self):
        return self._Ipv4Address

    @ipv4address.setter
    def ipv4address(self, value):
        self._Ipv4Address = value

    @property
    def ipv6address(self):
        return self._Ipv6Address

    @ipv6address.setter
    def ipv6address(self, value):
        self._Ipv6Address = value

    @property
    def mac(self):
        return self._Mac

    @mac.setter
    def mac(self, value):
        self._Mac = value

    @property
    def hostname(self):
        return self._Hostname

    @hostname.setter
    def hostname(self, value):
        self._Hostname = value

    @property
    def dhcphostname(self):
        return self._DhcpHostname

    @dhcphostname.setter
    def dhcphostname(self, value):
        self._DhcpHostname = value

    @property
    def dhcpvendor(self):
        return self._DhcpVendor

    @dhcpvendor.setter
    def dhcpvendor(self, value):
        self._DhcpVendor = value

    def lastseen_get(self):
        return self._LastSeen

    def lastseen_set(self, value = None):
        if value:
            self._LastSeen = value
        else:
            self._LastSeen = datetime.now(timezone.utc)
        return self._LastSeen

    def lastmodified_set(self):
        self._LastModified = datetime.now(timezone.utc)
        return self._LastModified

    def lastmodified__get(self):
        return self._LastModified

    def discover_mac(self):
        arptable = open ("/proc/net/arp").read()
        for line in arptable:
            fields = line.split()
            if len(fields) > 0 and fields[0] == self._Ipv4Address:
                return fields[3]
        return None 
        
    def ssdpheader_add(self, header, value):
        if not header in self._ssdp:
            logging.debug('Sender %s creating list for %s', self._Ipv4Address, \
                header)
            self._ssdp[header] = []

        self.lastseen_set()
        found = 0
        for v in self._ssdp[header]:
            if v['Value'] == value:
                found = 1
                logging.debug('Sender %s already has header %s with %s', \
                    self._Ipv4Address, header, value)
                v['LastSeen']=datetime.now(timezone.utc)

        if found == 0:
            v = dict()
            v['Value'] = value
            v['LastSeen'] = v['FirstSeen'] = datetime.now(timezone.utc)
            self._ssdp[header].append(v)
            self.lastmodified_set()
            logging.debug('Sender %s adding header %s with %s', self._Ipv4Address,\
                header, value)
        return found

    def ssdpheader_compare(self, header, value):
        if not header in self._ssdp:
            logging.debug('Sender %s does not yet have header %s', \
                     self._Ipv4Address, header)
            return 1

        logging.debug('Sender %s comparing field %s from %s to %s', \
            self._Ipv4Address, header, self._ssdp[header], value)

        found = 0
        for v in self._ssdp[header]:
            if v['Value'] == value:
                found = 1
                v['LastSeen']=datetime.now(timezone.utc)
                self._LastSeen = v['LastSeen']
                return 0

        return 1


    def dnsquery_add(self, qn, fqdn, action, result):
        logging.debug("Q# %s from %s : %s %s %s", qn, self._Ipv4Address, \
            action, fqdn, result)

        self.lastseen_set()

        change = 0
        if not qn in self._dns:
            if action == 'reply':
                # We missed the original query so we ignore this query
                logging.debug("We missed first dns log with query")
                return change
            logging.debug("Creating DNS log entry for %s", fqdn)
            change = self._dns[qn] = DnsQuery(fqdn)
        else:
            # First log entry for fqdn that is a CNAME lists <CNAME> as data,
            # which we don't care about
            if result != '<CNAME>':
                # note that the fqdn here may be a CNAME and 
                # not the original fqdn queried.
                logging.debug("Adding DNS log data for: %s with %s %s", qn, \
                    fqdn, result)
                change = self._dns[qn].update(fqdn,result)


        return change


    def write_db_record_thing(self, conn):
        cur = conn.cursor()
        thingid = self.getthingid(cur)
        if not self.mac:
            self.mac = self.discover_mac()

        if thingid:
            logging.debug('Updating DB Thing record for %s', self._Ipv4Address)
            cur.execute('''
                UPDATE Things SET Mac = ?, Ipv4Address = ?, Ipv6Address = ?,
                    Hostname = ?, DhcpHostname = ?, DhcpVendor = ?,
                    SsdpFriendlyName = ?, SsdpManufacturer = ?, SsdpModelName = ?,
                    SsdpUdn = ?, SsdpSerialNumber = ?, SsdpManufacturerUrl = ?,
                    SsdpModelUrl = ?, FirstSeen = ?, LastModified = ?,
                    LastSeen = ?, Status = ?  WHERE ThingId = ?
                ''',\
                (self.mac, self.ipv4address, self.ipv6address, \
                self.hostname, self.dhcphostname, self.dhcpvendor, \
                self._SsdpFriendlyName, self._SsdpManufacturer, \
                self._SsdpModelName, self._SsdpUdn,self._SsdpSerialNumber, \
                self._SsdpManufacturerUrl, self._SsdpModelUrl, \
                self._FirstSeen, self._LastModified, self._LastSeen,'Active', \
                thingid))
            conn.commit()
        else:
            thingid = self.create_db_record_thing(conn)

        return self.getthingid(cur)

    def create_db_record_thing(self, conn):
        cur = conn.cursor()
        cur.execute('''INSERT INTO Things (Mac, Ipv4Address, Ipv6Address,
           Hostname, DhcpHostname, DhcpVendor,
            SsdpFriendlyName, SsdpManufacturer, SsdpModelName, SsdpUdn,
            SsdpSerialNumber, SsdpManufacturerUrl, SsdpModelUrl,
            FirstSeen, LastModified, LastSeen, Status, DeviceProfileUuid)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', \
            (self.mac, self.ipv4address, self.ipv6address, \
            self.hostname, self.dhcphostname, self.dhcpvendor, \
            self._SsdpFriendlyName, self._SsdpManufacturer, self._SsdpModelName, \
            self._SsdpUdn, self._SsdpSerialNumber, self._SsdpManufacturerUrl, \
            self._SsdpModelUrl, self._FirstSeen, self._LastModified, \
            self._LastSeen,'Active', ''))

        conn.commit()
        return self.getthingid(cur)

    def getthingid(self, cur, ipv4address = None, ipv6address = None, mac = None):
        if not ipv4address:
            ipv4address = self._Ipv4Address

        cur.execute('''SELECT * FROM Things WHERE Ipv4Address = ? AND
            Status <> "Decommissioned"''', (ipv4address,))
        row = cur.fetchone()
        thingid = None
        if row:
            thingid = row['ThingId']
            logging.debug("DB: IPv4 Address %s ThingId %s", ipv4address, thingid)
        else:
            logging.debug("DB: no thing found for IPv4 address %s", ipv4address)

        return thingid

    def write_db_record_dns (self, conn, qn, ip = ''):
        cur = conn.cursor()

        dq = self._dns[qn]
        if len(dq.ips) == 0:
            logging.debug("No DNS data to write yet for %s", dq.fqdn)
            return 0
        change = 0
        thingid = self.getthingid(cur)
        if not thingid:
            thingid = self.create_db_record_thing(conn)
            change = 1
            logging.debug('Creating DB Thing  record for %s', self._Ipv4Address)
        else:
            logging.debug('Updating DB Thing record for %s', self._Ipv4Address)
            change = self.write_db_record_thing(conn)

        cur.execute('''SELECT * FROM DnsQueries WHERE ThingId = ? AND Fqdn = ?''',\
             (thingid, dq.fqdn))
        s = cur.fetchall()

        # We only really care in the IPs for a FQDN that 
        # the Thing has performed a lookup on
        found = 0
        logging.debug("Checking on %s with %s", dq.fqdn, ip)
        for row in s:
            logging.debug("Comparing with %s", row['Data'])
            if str(ip) == str(row['Data']):
                logging.debug("Found matching row %s %s with %s", thingid, \
                dq.fqdn, row['Data'])
                found = 1
                if row['LastSeen'] != dq.lastseen:
                    logging.debug("Updating lastseen")
                    change = 1
                    cur.execute('''UPDATE DnsQueries SET FirstSeen = ?,
                        LastSeen = ?, LastModified = ? WHERE ThingId = ?
                        AND Fqdn = ? AND data = ?''', \
                        (dq.firstseen, dq.lastseen, dq.lastmodified, \
                        thingid, dq.fqdn, str(ip)))
                    conn.commit()
                break

        if not found:
            change = 1
            logging.info("Adding DNS entry to ThingID: %s %s %s %s %s %s", \
                thingid, dq.fqdn, ip, dq.firstseen, dq.lastseen, \
                dq.lastmodified)
            cur.execute('''INSERT INTO DnsQueries (ThingId, Fqdn, Data, 
                FirstSeen, LastSeen, LastModified) 
                VALUES (?, ?, ?, ?, ?, ?)''', \
                (thingid, dq.fqdn, str(ip), dq.firstseen, dq.lastseen, \
                dq.lastmodified))
            conn.commit()

        return change



    def write_db_record_ssdp (self, conn):
        cur = conn.cursor()
        thingid = self.getthingid(cur)
        if not thingid:
            thingid = self.create_db_record_thing(conn)

        cur.execute('''SELECT * FROM SsdpHeaders WHERE ThingId = ?''', (thingid,))
        s = cur.fetchall()
        for header in self._ssdp:
            for value in self._ssdp[header]:
                found = 0
                for row in s:
                    if header == row['Header'] and value['Value'] == row['Value']:
                        logging.debug('Header with value already exists for %s %s', header, value['Value'])
                        found = 1
                        # SQLite3 includes a : between hours and minutes
                        # in the timezone
                        LastSeen = row['LastSeen'][:29] + row['LastSeen'][30:]
                        RowLastSeen = datetime.strptime(LastSeen, \
                            '%Y-%m-%d %H:%M:%S.%f%z')
                        if value['LastSeen'] > RowLastSeen:
                            logging.debug('Updating LastSeen for SsdpHeaderId %s',\
                                row['SsdpHeaderId'])
                            cur.execute('''UPDATE SsdpHeaders SET LastSeen = ?
                                WHERE SsdpHeaderId = ?''',\
                                (value['LastSeen'], row['SsdpHeaderId']))

                if not found:
                    logging.debug ("Inserting header / value in DB %s %s", \
                        header, value['Value'])
                    cur.execute('''INSERT INTO SsdpHeaders 
                        (ThingId, Header, Value, FirstSeen, LastSeen)
                        VALUES (?,?,?,?,?)''', \
                        (thingid, header, value['Value'], value['FirstSeen'], \
                        value['LastSeen']))

    def request_ssdphostinfo(self, url):
        lines = []
        try:
            logging.debug("HTTP GET of: %s", url)

            # TODO this is blocking
            url_rx = re.compile(r'^http:\/\/(.*?)(\/.*)$', re.IGNORECASE)
            urlmatch = url_rx.match(url)
            if not urlmatch:
                raise
            host = urlmatch.group(1)
            path = urlmatch.group(2)
            hconn = http.client.HTTPConnection(host)
            hconn.request('GET', path)
            hresp = hconn.getresponse()
            lines = hresp.read().decode().splitlines()

        except:
            logging.debug("Failed to get SSDP host info from %s", url)
            return

        for line in lines:
            mfn = friendlyname_rx.search(line)
            if mfn:
                self._SsdpFriendlyName = mfn.group(1)
                logging.debug("Matched SSDP FriendlyName: %s", \
                    self._SsdpFriendlyName)

            mm = manufacturer_rx.search(line)
            if mm:
                self._SsdpManufacturer = mm.group(1)
                logging.debug("Matched SSDP Manufacturer: %s", \
                    self._SsdpFriendlyName)

            mmn = modelname_rx.search(line)
            if mmn:
                self._SsdpModelName = mmn.group(1)
                logging.debug("Matched SSDP ModelName: %s", self._SsdpFriendlyName)

            mu = udn_rx.search(line)
            if mu:
                self._SsdpUdn = mu.group(1)
                logging.debug("Matched SSDP Udn: %s", self._SsdpUdn)

            msn = serialnumber_rx.search(line)
            if msn:
                self._SsdpSerialNumber = msn.group(1)
                logging.debug("Matched SSDP SerialNumber: %s", \
                    self._SsdpSerialNumber)

            mmu = manufacturerurl_rx.search(line)
            if mmu:
                self._SsdpManufacturerUrl = mmu.group(1)
                logging.debug("Matched SSDP ManufacturerUrl: %s", \
                    self._SsdpManufacturerUrl)

            mmo = modelurl_rx.search(line)
            if mmo:
                self._SsdpModelUrl = mmo.group(1)
                logging.debug("Matched SSDP ModelUrl: %s", self._SsdpModelUrl)

