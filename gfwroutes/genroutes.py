#!/usr/bin/env python

import re
import urllib2
import sys
import argparse
import math
import textwrap
import dns.resolver
from netaddr import *

def generate_routes(metric):
    results = fetch_ip_data()
    upscript_header=textwrap.dedent("""\
    #!/bin/sh
    ip route add throw 127.0.0.0/8 table mesh
    ip route add throw 10.0.0.0/8 table mesh
    ip route add throw 172.16.0.0/12 table mesh
    ip route add throw 192.168.0.0/16 table mesh
    """)
    upfile=open('routes.sh','w')
    rfile=open('openvpn-cnroutes.conf','w')
    pfile=open('cn-bypass.conf','w')
    lfile=open('route-list.txt', 'w')
    upfile.write(upscript_header)
    upfile.write('\n')
    
    for ip,mask,prefix in results:
        #upfile.write('route ${ACT} -net %s netmask %s dev ${DEV}\n'%(ip,mask))
        upfile.write('ip route add throw %s/%s table mesh\n'%(ip,prefix))
        route_item="route %s %s net_gateway %d\n"%(ip,mask,metric)
        rfile.write(route_item)
        route_item="push \"route %s %s net_gateway\"\n"%(ip,mask)
        pfile.write(route_item)
        list_item="%s/%s\n"%(ip,prefix)
        lfile.write(list_item)
    rfile.close()
    upfile.write('ip rule add from all lookup mesh prio 32765\n')
    upfile.close()
    lfile.close()
    print "Usage: Append the content of the newly created routes.txt to your openvpn config file," \
          " and also add 'max-routes %d', which takes a line, to the head of the file." % (len(results)+20)

def fetch_ip_data():
    #fetch data from apnic
    print "Fetching data from apnic.net, it might take a few minutes, please wait..."
    url=r'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
    data=urllib2.urlopen(url).read()
    
    cnregex=re.compile(r'apnic\|cn\|ipv4\|[0-9\.]+\|[0-9]+\|[0-9]+\|a.*',re.IGNORECASE)
    cndata=cnregex.findall(data)
    chkhosts=[]
    results=[]
    ip_list=[]

    for item in cndata:
        unit_items=item.split('|')
        starting_ip=unit_items[3]
        num_ip=int(unit_items[4])

        #mask in *nix format
        mask2=32-int(math.log(num_ip,2))
        netnum="%s/%s"%(starting_ip,mask2)
        ip_list.append(IPNetwork(netnum))

    print "Processed %d allocations for China." % len(ip_list)

    #       Speedtest Known Owned Ranges: (per http://whois.arin.net/rest/org/NETRI-11/nets)
    ip_list.append(IPNetwork('74.209.160.0/19'))
    ip_list.append(IPNetwork('68.64.48.0/20'))
    ip_list.append(IPNetwork('69.46.32.0/20'))
    # UseNET over VPN? Right....
    # http://whois.arin.net/rest/customer/C02424347.html
    # http://whois.arin.net/rest/org/XEEX.html
    ip_list.append(IPNetwork('216.151.153.0/24'))
    ip_list.append(IPNetwork('207.246.207.0/24'))
    # http://whois.arin.net/rest/org/NEWSH/nets
    ip_list.append(IPNetwork('209.197.23.0/24'))
    ip_list.append(IPNetwork('208.197.28.0/24'))
    ip_list.append(IPNetwork('216.246.80.0/22'))
    ip_list.append(IPNetwork('209.197.12.0/22'))
    ip_list.append(IPNetwork('69.16.176.0/22'))
    ip_list.append(IPNetwork('74.209.132.0/23'))
    # http://whois.arin.net/rest/org/DAFA/nets (GigaNews)
    ip_list.append(IPNetwork('216.196.96.0/20'))
    # (highwinds?)
    ip_list.append(IPNetwork('178.22.82.0/24'))
    ip_list.append(IPNetwork('198.186.190.0/24'))
    print "There are %d entries in the list after merging exclusions." % len(ip_list)

    chkhosts.extend(['speedtest.net', 'www.speedtest.net', 'bandwidthplace.com', 'www.bandwidthplace.com'])

    for thishost in chkhosts:
        for rdata in dns.resolver.query(thishost, 'A'):
            # If they own the IP, we should just consider that they probably own *at least* the /28 block
            ip_list.append(IPNetwork('%s/28'%rdata.address))

    print "There are %d entries in the list after merging lookups." % len(ip_list)
    print "Merging netblocks..."
    merged = cidr_merge(ip_list)
    print "Merged to %d netblocks." % len(merged)
    print "-------------------------------------------------------------------------------"

    for ip in merged:
        results.append((ip.network,ip.netmask,ip.prefixlen))

    return results


if __name__=='__main__':
    parser=argparse.ArgumentParser(description="Generate routing rules for vpn.")
    parser.add_argument('-p','--platform',
                        dest='platform',
                        default='all',
                        nargs='?',
                        help="Target platforms, it can be all.")
    parser.add_argument('-m','--metric',
                        dest='metric',
                        default=5,
                        nargs='?',
                        type=int,
                        help="Metric setting for the route rules")
    
    args = parser.parse_args()
    generate_routes(args.metric)
