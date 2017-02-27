#!/usr/bin/env python3
#
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
import time
import sqlite3
from ipaddress import ip_address, IPv4Address
import argparse
import json


def read_command_line_arguments():
    parser = argparse.ArgumentParser(description= \
        "Clean up noddos SQL database")
    parser.add_argument("-c", "--configurationfile", \
        help="Noddos client configuration file", \
        default='/etc/noddos/noddosconfig.json')
    parser.add_argument("-s", "--dbfile", help="Noddos SQL database file")
    parser.add_argument("-u", "--ulogdbfile", help="Ulog SQL database file")
    parser.add_argument("-d", "--dnsexpire", help="Delete DNS log entries older than n seconds", \
        type=int)
    parser.add_argument("-t", "--trafficexpire", help="Delete traffic log entries older than n seconds",\
        type=int)
    parser.add_argument("-e", "--hostexpire", \
        help="Delete a host entry if its IP address has been reused and the host was last seen more than n seconds ago",\
        type=int)
    args = parser.parse_args()

    config=json.loads(open(args.configurationfile).read())
    if args.dbfile:
        config['client']['dbfile'] = args.dbfile
    if 'dbfile' not in config['client']:
        config['client']['dbfile'] = '/var/log/noddos/noddos.db'

    if args.ulogdbfile:
        config['client']['ulogdbfile'] = args.ulogdbfile
    if 'ulogdbfile' not in config['client']:
        config['client']['ulogdbfile'] = '/var/log/ulog/ulog.sqlite3db'

    if args.dnsexpire:
        config['client']['expiredns'] = args.dnsexpire
    if 'expiredns' not in config['client']:
        config['client']['expiredns'] = 7 * 24 * 60 * 60

    if args.trafficexpire:
        config['client']['expiretraffic'] = args.trafficexpire
    if 'expiretraffic' not in config['client']:
        config['client']['expiretraffic'] = 12 * 60 * 60

    if args.hostexpire:
        config['client']['expirehost'] = args.hostexpire
    if 'expirethost' not in config['client']:
        config['client']['expirehost'] = 7 * 24 * 60 * 60
    
    return config

def main ():
    config = read_command_line_arguments()

    trafficthreshold =datetime.fromtimestamp(time.time()- \
        float(config['client']['expiretraffic']),timezone.utc)
    conn = sqlite3.connect(config['client']['dbfile'])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    conn_ulog = sqlite3.connect(config['client']['ulogdbfile'])
    conn.row_factory = sqlite3.Row
    cur_ulog = conn_ulog.cursor()

    cur_ulog.execute('''DELETE FROM ulog_ct WHERE flow_end_sec < ?''', \
        (str(trafficthreshold)[:10],))

    RFC1918_192_start = int(IPv4Address('192.168.0.0'))
    RFC1918_192_end = int(IPv4Address('192.168.255.255'))
    RFC1918_172_start = int(IPv4Address('172.16.0.0'))
    RFC1918_172_end = int(IPv4Address('172.31.255.255'))
    RFC1918_10_start = int(IPv4Address('10.0.0.0'))
    RFC1918_10_end = int(IPv4Address('10.255.255.255'))
    MULTICAST_start = int(IPv4Address('224.0.0.0'))

    cur_ulog.execute('''
        DELETE FROM ulog_ct WHERE 
            (
                (orig_ip_saddr >= ? AND orig_ip_saddr <= ?) OR
                (orig_ip_saddr >= ? AND orig_ip_saddr <= ?) OR
                (orig_ip_saddr >= ? AND orig_ip_saddr <= ?)
            ) AND
            (
                (orig_ip_daddr >= ? AND orig_ip_daddr <= ?) OR
                (orig_ip_daddr >= ? AND orig_ip_daddr <= ?) OR
                (orig_ip_daddr >= ? AND orig_ip_daddr <= ?) OR
                orig_ip_daddr >= ?
            )''', (RFC1918_192_start, RFC1918_192_end, RFC1918_172_start, \
            RFC1918_172_end, RFC1918_10_start,  RFC1918_10_end, RFC1918_192_start, \
            RFC1918_192_end, RFC1918_172_start, RFC1918_172_end, RFC1918_10_start, \
            RFC1918_10_end, MULTICAST_start))


    dnsthreshold=datetime.fromtimestamp(time.time()-\
        float(config['client']['expiredns']),timezone.utc)
    cur.execute('''DELETE FROM DnsQueries WHERE LastSeen < ?''', \
        (str(dnsthreshold)[:10],))

    cur.execute('''
        SELECT LT.Mac, LT.Ipv4Address, LT.ThingId, RT.Mac, RT.Ipv4Address
        FROM Things AS LT JOIN Things AS RT
        ON LT.Mac = RT.Mac AND
        LT.ThingId != RT.ThingId AND
        LT.Mac <> '' AND
        LT.Status <> 'Decommissioned' AND
        LT.LastSeen < RT.LastSeen''')
    s = cur.fetchall()
    for thing in s:
        cur.execute(
            '''UPDATE Things SET Status = 'Decommisioned' WHERE ThingID = ?''', \
            (thing['LT.ThingId'],))
    
    # The following automatically causes cascaded deletes of SsdpHeaders and 
    # DnsQueries
    hostthreshold=datetime.fromtimestamp(time.time()-\
        float(config['client']['expirehost']),timezone.utc)
    cur.execute(
        '''DELETE FROM Things WHERE Status = 'Decommisioned' AND LastSeen < ?''', \
        (hostthreshold,))
    
    conn.close()

if __name__ == "__main__":
    main()

