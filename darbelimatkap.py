#!/usr/bin/python
#-*- coding: utf-8 -*-
# Winter/2014
# @bek_phys, @celilunuver from signalsec.com
# currently under development
# bug reports're welcome

import argparse, sys, socket, logging
from array import *
from random import choice
from time import sleep

#ipv6 warnings..
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try: from scapy.all import *
except: from scapy import *

from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import IP,UDP,TCP
from scapy.packet import Raw

NAME          = "DarbeliMatkap Network PCAP Fuzzer"
VERSION       = "0.1"
AUTHORS       = "Bekir Karul & Celil Unuver from SignalSEC"

#b_Smash definitions
INSERT_VALUES = ("41", "42")
SMASH_INT     = (1000, 3000)

#b_Flip definitions
FUZZ_BYTE     = ("ff", "ffff", "ffffffff", "7f", "7fff", "7fffffff", "80", "8000", "80000000", "fe", "feff", "feffffff")

def b_setParams():
	global args

	parser          = argparse.ArgumentParser(
	formatter_class = argparse.RawDescriptionHelpFormatter,
	description     = "%s - v%s\n%s\n" %(NAME, VERSION, AUTHORS),
	epilog          = """
Usage:
./%(prog)s -n -i input.pcap [-byteflip/-smash] [-d 0.2] [-ip 127.0.0.1] [-port 80]
	""")

	if len(sys.argv) == 1:   	
		parser.print_help()
	   	sys.exit(1)

	parser.add_argument("-n", metavar="", help="darbeleme/fuzzing on", const=True, action="store_const")
	parser.add_argument("-byteflip", metavar="", help="byte-flip fuzz", const=True, action="store_const")
	parser.add_argument("-smash", metavar="", help="smash fuzz", const=True, action="store_const")
	parser.add_argument("-i", default=True, metavar="", help="pcap input")
	parser.add_argument("-d", default=True, metavar="0.1", help="delay")
	parser.add_argument("-ip", default=True, metavar="127.0.0.1", help="ip address")
	parser.add_argument("-port", default=True, metavar="80", help="port address")

	args = parser.parse_args()

def b_Flip(packet_tchange):
	x = 0
	return_list = []
	while x < len(FUZZ_BYTE):
		for i in range(len(packet_tchange)):
			new_list    = packet_tchange[:]
			new_list[i] = FUZZ_BYTE[x]
			return_list.append(new_list)
		x += 1
	return return_list

def b_Smash(packet_tchange):
	return_list = []
	for insert_count in range(len(INSERT_VALUES)):
		for smash_count in range(len(SMASH_INT)):
			for i in range(len(packet_tchange)):
				new_list    = packet_tchange[:]
				new_list.insert(i, INSERT_VALUES[insert_count] * SMASH_INT[smash_count])
				return_list.append(new_list)
	return return_list

def b_Darbeleme(pcap_file):
	packets = rdpcap(pcap_file)
	
	for packet_content in packets:
		packet_list = []
		if packet_content.haslayer(TCP) and packet_content.dport == int(args.port):
		    for packet_payload in str(packet_content.getlayer(TCP).payload):
		    	if len(packet_payload) != 0:
		        	packet_list.append(packet_payload)

		if packet_content.haslayer(UDP) and packet_content.dport == int(args.port):
		    for packet_payload in str(packet_content.getlayer(UDP).payload):
		    	if len(packet_payload) != 0:	
		        	packet_list.append(packet_payload)	

		#if len packet_list == 0
		#XXX

		data = " ".join("{:02x}".format(ord(sla)) for sla in packet_list).split()

		if args.byteflip == True:
			fuzzed_list = b_Flip(data)

		elif args.smash == True:
			fuzzed_list = b_Smash(data)
		
		else:
			print "[!] Wrong method was chosen!"
			sys.exit(1)
		
		i = 0
		for sending_now in fuzzed_list:
			count_packet = range(len(sending_now))
			if i > len(sending_now)-1:
				i = 0
			i += 1
			last_tsend = "".join(sending_now).decode("hex")
			b_Connection(last_tsend, count_packet[i-1])

def b_Connection(packet, f_byte):
	try:
		sock    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		connect = sock.connect((args.ip, int(args.port)))
		print "Fuzz Byte: {1}\nPacket: {0}\n".format(packet.encode("hex"), f_byte)
		sock.send(packet)
		sock.close()
		sleep(float(args.d))
	except socket.error:
		print "[!] Looks like server down. Fuzz byte: {0}".format(f_byte)
		sys.exit(1)

def d_Matkap():
	b_setParams()
	try:
		if (args.n == True) and (args.i != True):
			print "\n[*] Network darbeleme starting...\n"
			b_Darbeleme(args.i)
		
		else:
			print "[!] Error!"
	
	except KeyboardInterrupt:
		print "\n\n[X] Terminated by the user...\n"

if __name__ == "__main__":
	d_Matkap()