#!/usr/bin/env python3

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

import sys
import sqlite3
import json
from datetime import datetime, timezone
import time
from ipaddress import ip_address, IPv4Address
import socket
import ssl
import http.client
import argparse
import logging

class DeviceProfile:
    def __init__(self, obj):
        self._deviceprofile = obj
        self._uuid = obj['DeviceProfileUuid'] 
        self._manufacturer = obj['Manufacturer']
        self._model = obj['Model']
        self._uploadstats = True
        self._lastupdated = obj['LastUpdated']
        if 'UploadStats' in obj:
            self._uploadstats = obj['UploadStats']

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self,value):
        self._uuid = value

    @property
    def uploadstats(self):
        return self._uploadstats

    @uploadstats.setter
    def uploadstats(self,value):
        self._uploadstats = value

    @property
    def deviceprofile(self):
        return self._deviceprofile

    @deviceprofile.setter
    def deviceprofile(self,value):
        self._deviceprofile = value

    @property
    def manufacturer(self):
        return self._manufacturer

    @property
    def model(self):
        return self._model

    @property
    def lastupdated(self):
        return self._lastupdated

    @lastupdated.setter
    def lastupdated(self,value):
        self._lastupdated = value

    @property
    def uploadstats(self):
        return self._uploadstats

    @uploadstats.setter
    def uploadstats(self,value):
        self._uploadstats = value

    def ismatch(self,thing, trafficstats):
        match = False

        logging.debug("Comparing profile %s %s", self.manufacturer, self.model)
        # If a profile has no identifying criteria, it can never match
        if not 'Identifiers' in self._deviceprofile:
            return False

        identified = False
        for identifier in self._deviceprofile['Identifiers']:
            identified=True
            if 'MustMatch' in identifier:
                matched = self.ismustmatch(identifier['MustMatch'], thing, \
                    trafficstats)
                if not matched:
                    identified = False

            if 'MustContain' in identifier:
                contained = self.ismustcontain(identifier['MustContain'], \
                    thing, trafficstats)
                if not contained:
                    identified = False

            if identified == True:
                match = True
                
        return match

    def ismustmatch(self, mustmatchconditions, thing, trafficstats):
        logging.debug("Match conditions %s", mustmatchconditions)
        for condition in mustmatchconditions:
            matchstring = mustmatchconditions[condition]
            offset = 0
            length = len(matchstring)
            if matchstring[0] == '*':
                matchstring = matchstring[1:]
                offset = -length + 1
                length = thing[condition]
            elif matchstring[-1:] == '*':
                matchstring = matchstring[0:-1]
                length -= 1    
                offset = 0 
            if thing[condition][offset:length] != matchstring:
                logging.debug("No match: %s != %s", thing[condition], \
                        mustmatchconditions[condition])
                return False
            else:
                logging.debug("Match: %s == %s", thing[condition], \
                        mustmatchconditions[condition])

        return True

    def ismustcontain(self, mustcontainconditions, thing, trafficstats):
        for criterium in mustcontainconditions:
            if criterium == 'DnsQueries':
                matched = self.ismustcontaindnsqueries \
                    (mustcontainconditions['DnsQueries'], thing, trafficstats)
                if not matched:
                    return False

        return True

    def ismustcontaindnsqueries(self, matchfqdns, thing, trafficstats):
        if not 'DnsQueries' in trafficstats:
            return False
        for fqdn in matchfqdns:
            if fqdn not in trafficstats['DnsQueries']:
                return False

        return True



RFC1918_192_start = int(IPv4Address('192.168.0.0'))
RFC1918_192_end = int(IPv4Address('192.168.255.255'))
RFC1918_172_start = int(IPv4Address('172.16.0.0'))
RFC1918_172_end = int(IPv4Address('172.31.255.255'))
RFC1918_10_start = int(IPv4Address('10.0.0.0'))
RFC1918_10_end = int(IPv4Address('10.255.255.255'))
MULTICAST_start = int(IPv4Address('224.0.0.0'))
def isfilteredtraffic(ipaddress):
    ip = int(ipaddress)
    if ip >= RFC1918_192_start and ip <= RFC1918_192_end:
        return 1
    if ip >= RFC1918_172_start and ip <= RFC1918_172_end:
        return 1
    if ip >= RFC1918_10_start and ip <= RFC1918_10_end:
        return 1
    if ip >= MULTICAST_start:
        return 1

    return 0

def bestprofilematch(thing, trafficstats, deviceprofiles):
    bestmatch = 0
    uuid = ''
    for dp in deviceprofiles:
        match = deviceprofiles[dp].ismatch(thing, trafficstats)
        if match > bestmatch:
            uuid = deviceprofiles[dp].uuid
            bestmatch = match
        elif match == bestmatch and match > 0:
            logging.debug("Equal match for %s between %s and %s", thing['Mac'], \
            uuid, deviceprofiles[dp].uuid)
    return uuid

def gettrafficstats(thingid, ipv4address, lastrun, conn, conn_ulog):
    DnsQueries = set()
    ResolvedIps = dict()
    cur = conn.cursor()
    oneweekago=datetime.fromtimestamp(time.time()-7*24*60*60,timezone.utc)
    cur.execute('''SELECT * FROM DnsQueries WHERE ThingId = ? AND LastSeen > ? ORDER BY LastSeen''',(thingid,oneweekago))
    dnsqueries = cur.fetchall()
    for query in dnsqueries:
        if 'Fqdn' in query.keys(): 
            LastSeen = query['LastSeen'][:29] + query['LastSeen'][30:]
            if query['Fqdn'] not in DnsQueries and datetime.strptime(LastSeen, \
                    '%Y-%m-%d %H:%M:%S.%f%z')>lastrun:
                DnsQueries.add(query['Fqdn'])
            if 'Data' in query.keys():
                ResolvedIps[query['Data']]= query['Fqdn']
                logging.debug("Setting Resolved IP for %s to %s", query['Fqdn'], \
                    query['Data'])

    FlowStats = dict()
    if ipv4address:
        ipaddress = socket.htonl(int(ip_address(ipv4address)))
        cur_ulog = conn_ulog.cursor()
        cur_ulog.execute( \
            '''SELECT * FROM ulog_ct 
            WHERE orig_ip_saddr  = ? AND flow_end_sec > ? 
            ORDER BY flow_end_sec''', (ipaddress,int(lastrun.timestamp())))
        for flow in cur.fetchall():
            # We don't want to report on RFC1918 traffic or multicast traffic
            daddr = IPv4Address(socket.ntohl(flow['orig_ip_daddr']))
            if not isfilteredtraffic(daddr):
                if str(daddr) not in ResolvedIps:
                    logging.debug("%s is not in list of resolved IPs", daddr)
                    if daddr not in FlowStats.keys():
                        FlowStats[daddr] = dict()
                        FlowStats[daddr]['dest_ip'] = str(daddr)
                        FlowStats[daddr]['flows'] = 1
                        FlowStats[daddr]['bytes_out'] = flow['orig_raw_pktlen']
                        FlowStats[daddr]['bytes_in'] = flow['reply_raw_pktlen']
                        FlowStats[daddr]['packets_out'] = flow['orig_raw_pktcount']
                        FlowStats[daddr]['bytes_in'] = flow['reply_raw_pktcount']
                    else: 
                        FlowStats[daddr]['flows'] += 1
                        FlowStats[daddr]['bytes_out'] += flow['orig_raw_pktlen']
                        FlowStats[daddr]['bytes_in'] += flow['reply_raw_pktlen']
                        FlowStats[daddr]['packets_out'] += flow['orig_raw_pktcount']
                        FlowStats[daddr]['bytes_in'] += flow['reply_raw_pktcount']
                else:
                    logging.debug("%s is in list of resolved IPs", str(daddr))


    trafficstats = dict()
    trafficstats['DnsQueries']= list(DnsQueries)
    trafficstats['FlowStats'] = list(FlowStats.values())
    return trafficstats

def updatethingprofileuuid(conn, thingid, profileuuid):
    logging.debug("Updating DeviceProfileUuid for %s to %s", thingid, profileuuid)
    cur = conn.cursor()
    cur.execute (\
        '''UPDATE Things SET DeviceProfileUuid = ? WHERE ThingId = ?''', \
        (profileuuid, thingid))

    conn.commit()
    if cur.rowcount == 0:
        raise ValueError ('No rows where updated for ThingID', thingid, 'with DeviceProfileId', \
            profileuuid)

def call_uploaddevice_api(conn, thing, trafficstats, clientcert,apiserver, loglevel):
    # Set up HTTPS connection to API endpoint
    sslcontext = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    sslcontext.load_cert_chain(clientcert)
    httpconn = http.client.HTTPSConnection(apiserver, context=sslcontext, timeout = 2)

    DeviceStats = dict.fromkeys(['Mac', 'DhcpHostname', 'DhcpVendor', \
        'SsdpFriendlyName', 'SsdpManufacturer', 'SsdpModelName', 'SsdpUdn', \
        'SsdpManufacturerUrl', 'SsdpModelUrl', 'SsdpHeaders'])
    DeviceStats.update(thing)
    if 'DnsQueries' in trafficstats and trafficstats['DnsQueries']:
        DeviceStats['DnsQueries'] = trafficstats['DnsQueries']
    if 'FlowStats' in trafficstats and trafficstats['FlowStats']:
        DeviceStats['FlowStats'] = trafficstats['FlowStats']

    DeviceStats['SsdpHeaders'] = list()

    cur = conn.cursor()
    cur.execute ('''Select * FROM SsdpHeaders WHERE ThingId = ?''', (thing['ThingId'],))
    ssdpheaders = cur.fetchall()

    for header in ssdpheaders:
        DeviceStats['SsdpHeaders'].append({ header['Header']: header['Value']})

    logging.info("Calling uploaddevice api for %s", thing['Ipv4Address'])
    httpconn.request('POST','/uploaddevice', body = json.dumps(DeviceStats), \
            headers = { 'Content-Type': 'application/json'})
    if loglevel == "debug" and DeviceStats['Mac']:
        f = open ("/tmp/Device-" + DeviceStats['Mac'],'w')
        f.write(json.dumps(DeviceStats))
        f.close()
    logging.debug( \
        "Calling uploaddevice for thing %s mac %s IP %s SsdpModelName %s", \
            thing['ThingId'], thing['Mac'], thing['Ipv4Address'], \
            thing['SsdpModelName'])
    return httpconn.getresponse()

def call_uploadstats_api(deviceprofileuuid, deviceprofiles, trafficstats, certfile, apiserver, loglevel):
    # Set up HTTPS connection to API endpoint
    sslcontext = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    sslcontext.load_cert_chain(certfile)
    httpconn = http.client.HTTPSConnection(apiserver, context=sslcontext, timeout = 2)

    if loglevel == "debug":
        f = open ("/tmp/Stats-" + \
            deviceprofiles[deviceprofileuuid].manufacturer + "-" + \
            deviceprofiles[deviceprofileuuid].model + "-" + \
            datetime.now(timezone.utc).strftime("%y%m%d-%H%M") + '.json', 'w')
        f.write(json.dumps(trafficstats))
        f.close()

    # Only upload stats if there is DNS or IP traffic
    if len(trafficstats['DnsQueries']) > 0 or len(trafficstats['FlowStats']) > 0:
        httpconn.request('POST','/uploadstats/' + deviceprofileuuid, \
            body = json.dumps(trafficstats), \
            headers = { 'Content-Type': 'application/json'})
        logging.info("Calling uploadstats api for %s", \
            deviceprofiles[deviceprofileuuid].model)
        return httpconn.getresponse()

    logging.info('No traffic to call uploadstats API for %s', \
        deviceprofiles[deviceprofileuuid].model)

    return None

def read_command_line_arguments():
    parser = argparse.ArgumentParser(description= \
        "Report devices and their traffic to the cloud")
    parser.add_argument("-c", "--configurationfile", \
        help="Noddos client configuration file", \
        default='/etc/noddos/noddosconfig.json')
    parser.add_argument("-p", "--deviceprofiles", \
        help="Noddos device profiles")
    parser.add_argument("-r", "--lastrunfile", \
        help="Tracks when nodreporter was last run")
    parser.add_argument("-v", "--verbose", help="Log verbosity")
    parser.add_argument("-s", "--dbfile", help="Noddos SQL database file")
    parser.add_argument("-u", "--ulogdbfile", help="Ulog2 SQL database file")
    parser.add_argument("-l", "--logfile", help="Log file to send output to")
    parser.add_argument('-a', "--apiserver", help="FQDN of API server")
    parser.add_argument('-e', "--clientcertificate", \
        help="Certificate to use for TLS client-auth against API server")
    parser.add_argument('-t', "--thingid", \
        help="Select Thing to report for (thingid comes from Things table in noddos.db")
    args = parser.parse_args()

    config=json.loads(open(args.configurationfile).read())
    if args.deviceprofiles:
        config['client']['deviceprofiles'] = args.deviceprofiles
    if 'deviceprofiles' not in config['client']:
        config['client']['deviceprofiles'] = '/var/lib/noddos/DeviceProfiles.json'
    if args.lastrunfile:
        config['client']['lastrunfile'] = args.lastrunfile
    if 'lastrunfile' not in config['client']:
        config['client']['lastrunfile'] = '/var/lib/noddos/reporter-lastrun.json'
    if args.verbose:
        config['client']['loglevelnodreporter'] = args.verbose
    if 'loglevelnodreporter' not in config['client']:
        config['client']['loglevelnodreporter'] = "warning"
    if args.dbfile:
        config['client']['dbfile'] = args.dbfile
    if 'dbfile' not in config['client']:
        config['client']['dbfile'] = '/var/log/noddos/noddos.db'
    if args.ulogdbfile:
        config['client']['ulogdbfile'] = args.ulogdbfile
    if 'ulogdbfile' not in config['client']:
        config['client']['ulogdbfile'] = '/var/log/ulog/ulog.sqlite3db'
    if args.logfile:
        config['client']['logfilenodreporter'] = args.logfile
    if 'logfilenodreporter' not in config['client']:
        config['client']['logfilenodreporter'] = '/var/log/noddos/nodreporter.log'
    if args.apiserver:
        config['client']['apiserver'] = args.apiserver
    if 'apiserver' not in config['client']:
        config['client']['apiserver'] = 'api.noddos.io'

    if args.clientcertificate:
        config['client']['cliencert'] = args.clientcertificate
    if 'clientcert' not in config['client']:
        config['client']['clientcert'] = '/etc/noddos/noddosapiclient.pem'
    if args.thingid:
        config['client']['thingid'] = args.thingid

    return config

def main():
    config = read_command_line_arguments()
    if config['client']['logfilenodreporter']:
        logging.basicConfig(filename=config['client']['logfilenodreporter'],\
        level = getattr(logging, config['client']['loglevelnodreporter'].upper(), \
        None), format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %H:%M:%S')
    else:
        logging.basicConfig( level = \
        getattr(logging, config['client']['loglevelnodreporter'].upper(), \
        None), format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %H:%M:%S')

    json_data=open(config['client']['deviceprofiles']).read()
    deviceprofileslist = json.loads(json_data)
    deviceprofiles = dict()
    for profile in deviceprofileslist:
        deviceprofiles[profile['DeviceProfileUuid']]=DeviceProfile(profile)

    lastrun=datetime.fromtimestamp(time.time()-86400,timezone.utc)
    try:
        string = open(config['client']['lastrunfile']).read()
        lastrun = datetime.strptime(string[:29] + string[30:],'%Y-%m-%d %H:%M:%S.%f%z')
        logging.info("nodreported last run at %s", str(lastrun))
    except:
        logging.info("We execute for the first time! We look at the data from the last day, since %s", \
             str(lastrun))

    # Open connection to SQLite database
    conn = sqlite3.connect(config['client']['dbfile'])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    conn_ulog = sqlite3.connect(config['client']['ulogdbfile'])
    conn_ulog.row_factory = sqlite3.Row

    cur.execute('''SELECT * FROM Things WHERE Status <> "Decommissioned" AND LastSeen > ?''', \
        (lastrun,))
    things = cur.fetchall()

    if not things:
        logging.warning("No things found with LastSeen > %s", str(lastrun))
        sys.exit()

    if 'thingid' in config['client']:
        logging.debug("Filter on thingid %s", config['client']['thingid'])
    
    config['client']['whitelistmacset'] = set()
    config['client']['whitelistipv4set'] = set()
    config['client']['whitelistipv6set'] = set()
    if 'whitelistmac' in config['client']:
        config['client']['whitelistmacset'] = set(config['client']['whitelistmac'])
    if 'whitelistipv4' in config['client']:
        config['client']['whitelistipv4set'] = set(config['client']['whitelistipv4'])
    if 'whitelistipv6' in config['client']:
        config['client']['whitelistipv6set'] = set(config['client']['whitelistipv6'])

    for thing in things:
        if 'thingid' in config['client']:
            if int(config['client']['thingid']) != int(thing['ThingId']):
                continue
        logging.debug("Processing thingid %s", thing['ThingId'])

        trafficstats=gettrafficstats(thing['ThingId'], \
            thing['Ipv4Address'],lastrun,conn, conn_ulog)
        if 'DnsQueries' not in trafficstats:
            logging.debug("No DNS queries")
        else:
            logging.debug('DnsQueries: %s', trafficstats['DnsQueries'])

        profileuuid = None
        profilefresh = True
        logging.debug ("Thing: %s", thing['DeviceProfileUuid'])

        if thing['DeviceProfileUuid']:
            logging.debug ("Thing has existing DeviceProfile associated: %s %s", \
                deviceprofiles[thing['DeviceProfileUuid']].manufacturer,
                deviceprofiles[thing['DeviceProfileUuid']].model)
            # If we previously discovered the matching profile, use it
            profileuuid = thing['DeviceProfileUuid']
            profilefresh = False

            # If the matching profile is newer then the last time we ran noddosreporter
            # then mark the match as stale. 
            if deviceprofiles[thing['DeviceProfileUuid']]:
                lastupdatedstring = deviceprofiles[thing['DeviceProfileUuid']].lastupdated
                if lastupdatedstring:
                    lastupdated = datetime.strptime(lastupdatedstring[:29] + lastupdatedstring[30:],\
                        '%Y-%m-%d %H:%M:%S.%f%z')
                    if lastupdated < lastrun:
                        profilefresh = True

            logging.info("Found device profile uuid in DB %s Fresh: %s", \
                profileuuid, str(profilefresh))
        else:
            logging.debug("Thing does not have existing device profile associated")

        if not profileuuid or not profilefresh:
            # Match the thing to a profile
            newprofileuuid = bestprofilematch(thing, trafficstats, deviceprofiles)
            if newprofileuuid:
                profileuuid = newprofileuuid

            # profileuuid is now set if we had a previous stale or fresh match, or
            # if we matched based on current traffic
            if profileuuid:
                logging.info("Match: %s for Thing %s", \
                    deviceprofiles[profileuuid].model, thing['ThingId'])
                updatethingprofileuuid(conn, thing['ThingId'], profileuuid)
            else:
                logging.info("Couldn't match thing %s", thing['ThingId'])
                
        if thing['Mac'] not in config['client']['whitelistmacset'] and \
                thing['Ipv4Address'] not in config['client']['whitelistipv4set'] and \
                thing['Ipv6Address'] not in config['client']['whitelistipv6set']:
            hresp = None
            if not profileuuid:
                # We don't upload traffic stats for unrecognized devices
                del trafficstats['FlowStats']
                hresp = call_uploaddevice_api(conn, thing, trafficstats, \
                    config['client']['clientcert'], config['client']['apiserver'],
                    config['client']['loglevelnodreporter'])
            else: 
                # Don't upload data if 'UploadStats' : False in device profile
                if deviceprofiles[profileuuid].uploadstats:
                    hresp = call_uploadstats_api(profileuuid, \
                        deviceprofiles, trafficstats, \
                        config['client']['clientcert'], config['client']['apiserver'],
                        config['client']['loglevelnodreporter'])
            # note that uploadstats api is only called if there is traffic to report
            if hresp:
                logging.info("HTTP status: %s %s", hresp.status, hresp.reason)
        else:
            logging.info("Not logging traffic for whitelisted %s - %s - %s", \
                thing['Mac'], thing['Ipv4Address'], thing['Ipv6Address'])

            
    if 'thingid' not in config['client']:
        logging.debug("Writing last run file to %s", config['client']['lastrunfile'])
        open(config['client']['lastrunfile'], 'w').write(str(datetime.now(timezone.utc)))

if __name__ == "__main__":
    main()

