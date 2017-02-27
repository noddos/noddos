#!/usr/bin/python3 

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


from dhcpquery import DhcpQuery, dhcp_rx
from dnsquery import DnsQuery, dns_rx
from host import Host, ssdp_rx

import inotify

import os
import sys
import socket
import select
from signal import SIGTERM, SIGHUP

import argparse
import logging
import struct
import queue
import time
from datetime import datetime, timezone 
import re
import json
import ipaddress
import sqlite3


MCAST_GRP = '239.255.255.250'
MCAST_PORT = 1900

def recv_ssdp_packet(sock, hosts, conn):
    data, address = sock.recvfrom(10240)
    sender = address[0]
    
    logging.debug('received %s bytes of SSDP data from %s', len(data), sender)
    string=data.decode('utf-8')
    lines=string.splitlines()

    change = 0
    for line in lines:
        logging.debug("SSDP: %s",line)
        m = ssdp_rx.match(line)
        if m:
            header = m.group(1)
            value = m.group(2)
            logging.debug('sender: %s %s -> %s', sender, header, value)
            if not sender in hosts:
                hosts[sender]=Host(sender)
                hosts[sender].ssdpheader_add(header, value)
                change = 1
            else: 
                hosts[sender].lastseen_set()
                if hosts[sender].ssdpheader_compare(header, value) != 0:
                    hosts[sender].ssdpheader_add(header, value)
                    change = 1
            if change:
                if header.lower() == 'location':
                    hosts[sender].request_ssdphostinfo(value)
                    

    if change:
        hosts[sender].write_db_record_ssdp(conn)

    return change

def read_file_events(fd, logfd, hosts, dhcpqueries, conn):
    try:
        event_buffer = os.read(fd, inotify.EVENT_BUFFER_SIZE)
    except (Exception, msg):
        raise msg
    
    count = 0
    buffer_i = 0
    q = queue.Queue(128)

    fmt = 'iIII'
    s_size = struct.calcsize(fmt)
    while buffer_i < len(event_buffer):
        wd, mask, cookie, fname_len = \
               struct.unpack(fmt, event_buffer[buffer_i:buffer_i+s_size])
        logging.debug("parsing inotify event")
        if (mask & inotify.IN_MODIFY):
            logging.debug("IN_MODIFY inotify event")
            for line in logfd:
                logging.debug("Log %s", line)
                sender = ""
                change = 0
                #
                # See if this is a DNS log message
                m = dns_rx.search(line)
                if m:
                    qn = m.group(1)
                    sender = m.group(2)
                    action = m.group(3)
                    fqdn = m.group(4)
                    result = m.group(6)
                    if not sender in hosts:
                        hosts[sender]=Host(sender)
                    host = hosts[sender]
                    host.lastseen_set()
                    if host.dnsquery_add(qn, fqdn, action, result):
                        host.write_db_record_dns(conn, qn, result)
                else:
                    logging.debug("Is it a DHCP log entry?")
                    m = dhcp_rx.search(line)
                    if m:
                        qn = m.group(1)
                        dhcpmessage = m.group(2)
                        logging.debug("DHCP match %s", m.group(2))
                        if not qn in dhcpqueries:
                            dhcpqueries[qn]=DhcpQuery()
                        dhcpquery = dhcpqueries[qn]
                        if dhcpquery.addlogline(dhcpmessage):
                            sender = dhcpquery.ipv4address
                            if not sender in hosts:
                                hosts[sender]=Host(sender)
                            host = hosts[sender]
                            host.dhcphostname = dhcpquery.clientname
                            host.dhcpvendor = dhcpquery.vendor
                            host.hostname = dhcpquery.hostname
                            host.mac = dhcpquery.mac
                            host.ipv4address = dhcpquery.ipv4address
                            host.ipv6address = dhcpquery.ipv6address
                            host.write_db_record_thing(conn)
                            host.lastseen = datetime.now(timezone.utc)
                            del dhcpqueries[qn]

        buffer_i += s_size + fname_len
        count += 1

def open_multicast_socket(interface_ip, mcast_ip, mcast_port):
    # Create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if sock == -1:
        raise ConnectionError ("Can't open SSDP socket")
    if sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) == -1:
        raise ConnectionError ("setsockopt SO_REUSEADDR")
    #sock.setblocking(0)

    # Join the multicast group
    # adding/concatenating two inet_aton results looks fishy but works as
    # in python inet_aton returns a string of four characters which somehow
    # fits nicely in the linux 2.2 ip_mreqn structure
    if sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, 
        socket.inet_aton(mcast_ip)+socket.inet_aton(interface_ip)) == -1:
        raise ConnectionError ("setsockopt IP_ADD_MEMBERSHIP")

    # Bind to the server address (binding to mcast_ip looks fishy to me but
    # that's the only way it works for me on a server with multiple NICs)
    if sock.bind((mcast_ip,mcast_port)) == -1:
        raise ConnectionError ("bind")
    
    return sock

def create_tables(cur):
    cur.execute('''CREATE TABLE IF NOT EXISTS Things (
        ThingId integer PRIMARY KEY,
        Mac integer, Ipv4Address text, Ipv6Address text, Hostname text,
        DhcpHostname text, DhcpVendor,
        SsdpFriendlyName, SsdpManufacturer, SsdpModelName, SsdpUdn,
        SsdpSerialNumber, SsdpManufacturerUrl, SsdpModelUrl,
        FirstSeen integer, LastModified integer, LastSeen integer, Status text,
        DeviceProfileUuid text
        )''')

    cur.execute('''CREATE INDEX IF NOT EXISTS ThingIpv4Address
        ON Things (Ipv4Address)''')

    cur.execute('''CREATE TABLE IF NOT EXISTS SsdpHeaders (
        SsdpHeaderId integer PRIMARY KEY,
        ThingId integer REFERENCES Things ON DELETE CASCADE,
        Header text, Value text,
        FirstSeen integer, LastSeen integer)''')

    cur.execute('''CREATE INDEX IF NOT EXISTS SsdpHeaderThingId
        ON SsdpHeaders (ThingId)''')

    cur.execute('''CREATE TABLE IF NOT EXISTS DnsQueries(
        DnsQueryId integer PRIMARY KEY,
        ThingId integer REFERENCES Things ON DELETE CASCADE,
        Fqdn text, Data text,
        FirstSeen integer, LastSeen integer, LastModified integer)''')

    cur.execute('''CREATE INDEX IF NOT EXISTS DnsQueryThingId
        ON DnsQueries (ThingId)''')

    cur.execute('''CREATE INDEX IF NOT EXISTS DnsQueryFqdn
        ON DnsQueries (Fqdn)''')

def read_command_line_arguments():
    parser = argparse.ArgumentParser(description= \
        "Discover devices in the network and collect traffic statistic")
    parser.add_argument("-c", "--configurationfile", \
        help="Noddos client configuration file", \
        default='/etc/noddos/noddosconfig.json')
    parser.add_argument("-v", "--verbose", help="Log verbosity level", \
        choices=('debug', 'info', 'warn','error', 'critical'))
    parser.add_argument("-n", "--nodaemon", help="Don't run as a daemon", \
        action="store_true")
    parser.add_argument("-d", "--dbfile", help="Noddos SQL database file")
    parser.add_argument("-l", "--logfile", help="Log file to send output to")
    parser.add_argument("-p", "--pidfile", help="File containing the process ID")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-a", "--ipaddress", \
        help="IP address of interface to listen for multicast")
    group.add_argument("-i", "--interface", \
        help="Interface on which to listen for multicast")
    args = parser.parse_args()

    # command line args take precedence over config file
    # if variable is not defined by either, default is taken
    config=json.loads(open(args.configurationfile).read())
    if args.verbose:
        config['client']['loglevelnodlisten'] = args.verbose
    if 'loglevelnodlisten' not in config['client']:
        config['client']['loglevelnodlisten'] = "warning"
    if args.nodaemon:
        config['client']['nodaemon'] = args.nodaemon
    if 'nodaemon' not in config['client']:
        config['client']['nodaemon'] = False
    if args.dbfile:
        config['client']['dbfile'] = args.dbfile
    if 'dbfile' not in config['client']:
        config['client']['dbfile'] = '/var/log/noddos/noddos.db'
    if args.pidfile:
        config['client']['pidfile'] = args.pidfile
    if 'pidfile' not in config['client']:
        config['client']['pidfile'] = '/var/log/noddos/noddos.pid'
    if args.logfile:
        config['client']['logfilenodlisten'] = args.logfile
    if 'logfilenodlisten' not in config['client']:
        config['client']['logfilenodlisten'] = '/var/log/noddos/nodlisten.log'
    if args.ipaddress:
        config['client']['ipaddress'] = args.ipaddress
    if args.interface:
        config['client']['interface'] = args.interface
        del config['client']['ipaddress'] 
    if 'ipaddress' not in config['client'] and interface not in config['client']:
        config['client']['interface'] = 'eth0'

    return config
 
def main(config):
    sock = open_multicast_socket(config['client']['ipaddress'], \
        MCAST_GRP, MCAST_PORT)

    # Inotify allows us to track changes to the dnsmasq log file
    inotify_fd = inotify.inotify_init()
    if inotify_fd == -1:
        logging.critical("Error initializing inotify")

    watch_fd = inotify.inotify_add_watch(inotify_fd, \
        bytes(b"/var/log/dnsmasq.log"), inotify.IN_CHANGED)
    if watch_fd == -1:
        logging.critical("Error adding inotify watch")

    # Open dnsmasq log file and go to end of file as we don't want
    # to process legacy data
    logfd = open(config['client']['dnsmasqlog'], 'r')
    logfd.seek (0, 2)

    # Create epoll object, add multicast socket and inotify to epoll list
    epoll = select.epoll()
    epoll.register(sock.fileno(),select.EPOLLIN)
    epoll.register(inotify_fd)

    # Open connection to SQLite database
    conn = sqlite3.connect(config['client']['dbfile'])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    create_tables(cur)

    # This is where we store all host information in memory
    # so that we don't have to read/write from SQLite DB all the time
    hosts = dict()
    dhcpqueries = dict()

    try: 
        while True:
            change = 0
            logging.debug('waiting to receive message')
            events = epoll.poll(60)
            logging.debug("Exiting epoll")
            for fileno, event in events:
                logging.debug("Checking events")
                if fileno == sock.fileno():
                    logging.debug("Received SSDP multicast packet")
                    change = recv_ssdp_packet(sock, hosts, conn)
                    conn.commit()
                elif fileno == inotify_fd:
                    logging.debug("Inotify event: %s", event)
                    if event and select.EPOLLIN:
                        logging.debug("EPOLLIN Inotify event")
                        read_file_events (inotify_fd, logfd, hosts, dhcpqueries, conn)
                        conn.commit()

    finally:
        epoll.unregister(sock.fileno())
        epoll.close()
        sock.close()
        os.close(inotify_fd)
        os.remove(config['client']['pidfile'])
        conn.commit()
        conn.close()

if __name__ == "__main__":
    config = read_command_line_arguments()
    if config['client']['logfilenodlisten']:
        logging.basicConfig(filename=config['client']['logfilenodlisten'],\
        level = getattr(logging, config['client']['loglevelnodlisten'].upper(), \
        None), format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %H:%M:%S')
    else:
        logging.basicConfig( level = \
        getattr(logging, config['client']['loglevelnodreporter'].upper(), \
        None), format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %H:%M:%S')

    # Check for a pidfile to see if the daemon already runs
    try:
        pid = int(open(config['client']['pidfile'],'r').read())
    except IOError:
        pid = None
   
    if pid:
        message = "pidfile %s already exist. Daemon already running?\n"
        sys.stderr.write(message % config['client']['pidfile'])
        sys.exit(1)
                
    if config['client']['nodaemon'] is False:
        """
        Start the daemon
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                #sys.exit(0)
                os._exit(0)
        except OSError as e:
            sys.stderr.write("fork #1 failed: {0}\n".format(err))
            sys.exit(1)

        # do second fork
        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)
    
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                #sys.exit(0)
                os._exit(0)
        except OSError as e:
            sys.stderr.write("fork #1 failed: {0}\n".format(err))
            sys.exit(1)
        
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open('/dev/null', 'r')
        so = open('/dev/null', 'a+')
        se = open('/dev/null', 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
       
    #
    # All the daemon related work is done
    #
    # write pidfile
    pid = str(os.getpid())
    open(config['client']['pidfile'],'w').write(pid)

    main(config)

