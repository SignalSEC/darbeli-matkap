#!/usr/bin/python
#-*- coding: utf-8 -*-
# Winter/2014
# @bek_phys, @celilunuver from signalsec.com

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

ISIM          = "DarbeliMatkap Network PCAP Fuzzer"
VERSIYON      = "0.1"
YAZAR         = "Bekir Karul & Celil Unuver from SignalSEC"

INSERT_VALUES = ("41", "42")
SMASH_INT     = (1000, 3000)
FUZZ_BYTE     = ("ff", "ffff", "ffffffff", "7f", "7fff", "7fffffff", "80", "8000", "80000000", "fe", "feff", "feffffff")

def parametreler():
	global args

	parser          = argparse.ArgumentParser(
	formatter_class = argparse.RawDescriptionHelpFormatter,
	description     = "%s - v%s\n%s\n" %(ISIM, VERSIYON, YAZAR),
	epilog          = """
Usage:
./%(prog)s -n -i input.pcap [-byteflip/-smash] [-d 0.2] [-ip 127.0.0.1] [-port 80]
	""")

	if len(sys.argv) == 1:   	
		parser.print_help()
	   	sys.exit(1)

	parser.add_argument('-n', metavar='', help='darbeleme/fuzzing on', const=True , action='store_const')
	parser.add_argument('-byteflip', metavar='', help='byte-flip fuzz', const=True , action='store_const')
	parser.add_argument('-smash', metavar='', help='smash fuzz', const=True , action='store_const')
	parser.add_argument('-i', default=True, metavar='', help='pcap input')
	parser.add_argument('-d', default=True, metavar='0.1', help='delay')
	parser.add_argument('-ip', default=True, metavar='127.0.0.1', help='ip address')
	parser.add_argument('-port', default=True, metavar='80', help='port address')

	args = parser.parse_args()

def b_Flip(d_paket):
	x = 0
	donen_liste = []
	while x < len(FUZZ_BYTE):
		for i in range(len(d_paket)):
			y_liste    = d_paket[:]
			y_liste[i] = FUZZ_BYTE[x]
			donen_liste.append(y_liste)
		x += 1
	return donen_liste

def b_Insert(d_paket):
	donen_liste = []
	for harf in range(len(INSERT_VALUES)):
		for sayi in range(len(SMASH_INT)):
			for i in range(len(d_paket)):
				y_liste    = d_paket[:]
				y_liste.insert(i,INSERT_VALUES[harf] * SMASH_INT[sayi])
				donen_liste.append(y_liste)
	return donen_liste

def b_Darbeleme(pcap_dosya):
	paketler = rdpcap(pcap_dosya)
	
	for paketic in paketler:
		paket_liste = []
		if paketic.haslayer(TCP):
		    for icerik in str(paketic.getlayer(TCP).payload):
		    	if len(icerik) != 0:
		        	paket_liste.append(icerik)

		if paketic.haslayer(UDP) and paketic.dport == int(args.port):
		    for icerik in str(paketic.getlayer(UDP).payload):
		    	if len(icerik) != 0:	
		        	paket_liste.append(icerik)	

		#if len(paket_list == 0)
		#XXX

		data = " ".join("{:02x}".format(ord(sla)) for sla in paket_liste).split()

		if args.byteflip == True:
			t_degisen = b_Flip(data)

		elif args.smash == True:
			t_degisen = b_Insert(data)
		
		else:
			print "[!] Wrong method was chosen!"
			sys.exit(1)
		
		i = 0
		for degisen in t_degisen:
			say = range(len(degisen))
			if i > len(degisen)-1:
				i = 0
			i += 1
			c = "".join(degisen)
			gonder = c.decode("hex")
			b_Baglanti(gonder, say[i-1])

def b_Baglanti(paket,f_byte):
	if paket != "":
		try:
			sock    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			connect = sock.connect((args.ip, int(args.port)))
			print "Fuzz Byte: {1}\nPacket: {0}\n\n".format(paket.encode("hex"),f_byte)
			sock.send(paket)
			sock.close()
			sleep(float(args.d))
		except socket.error:
			print "[!] Looks like server down. Fuzz byte: {0}".format(f_byte)
			sys.exit(1)
	else:
		print "[!] Empty packet.."

def d_Matkap():
	parametreler()
	try:
		if (args.n == True) and (args.i != True):
			print '\n[*] Network darbeleme starting...\n'
			b_Darbeleme(args.i)
		
		else:
			print '[!] Error!'
	
	except KeyboardInterrupt:
		print '\n\n[X] Terminated by the user...\n'

if __name__ == "__main__":
	d_Matkap()
