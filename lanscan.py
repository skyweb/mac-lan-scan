#!/usr/bin/env python
"""
Author:     skywebsys contact at gmail.com
License:    GPL v2
Use:        Simple network arp scanner
Dependencies:
        scapy
ChangeLog:
        v0.1 – first release
"""
 
import sys, csv, socket
from scapy.all import *

fin,fout=os.popen4("ip route list | grep proto | awk '{print $1}'")
lan_network = fout.read()
wr = csv.writer(open('mac.csv', 'wb'), delimiter=',', quoting=csv.QUOTE_ALL)

try:
	alive,dead=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=lan_network), timeout=2, verbose=1)
	print ''
        print "MAC\t\t\tIP"
	for i in range(0,len(alive)):
        	mac = alive[i][1].hwsrc
                cdr = alive[i][1].psrc
                print mac + "\t" + cdr  
                wr.writerow([mac, cdr])
except:
	pass


