#!/usr/bin/python3

import os
import sys
import time
import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/../scapy')

from subprocess import run
from scapy.all import *

if len(sys.argv) < 3:
	print("usage: " + sys.argv[0] + " AP_MAC FILE_PREFIX")
	sys.exit()

mac_addresses = {
	sys.argv[1] : "AP               "
}

def dump(obj):
	for attr in dir(obj):
		if hasattr( obj, attr ):
			print( "obj.%s = %s" % (attr, getattr(obj, attr)))

def mac_resolve(addr):
	return mac_addresses.get(addr, addr)

def addr_to_client(addr):
	addr_to_client.clients = []
	addr_to_client.addresses = []

	if not addr in addr_to_client.addresses:
		client = Client(addr)
		addr_to_client.addresses.append(addr)
		addr_to_client.clients.append(client)
		print("NEW: " + str(client))

	else:
		client = clients[addr_to_client.addresses.index(addr)]
		print("FOUND: " + str(client))

	return client


class Session:
	def __init__(self, client, packet):
		self.client = client
		self.start = packet

	def __str__(self):
		return "client: " + str(self.client) + " start: " + \
		str(datetime.fromtimestamp(self.start.time)) + " stop: " + \
		str(datetime.fromtimestamp(self.stop.time))

	def stop(self, packet):
		self.stop = packet

class Client:
	def __init__(self, addr):
		self.addr = addr
		self.session = []

	def __str__(self):
		# FIXME: use mac_addresses {} above (AP)
		return "addr: " + self.addr

	def auth(self, packet):
		if self.session: # FIXME: isactive() (Deauth frame)
			self.deauth(packet)

		self.session.append(Session(self, packet))
		print("Session started: " + str(self.session[-1]))

	def deauth(self, packet):
		# FIXME: implement latest packet seen and use it instead
		self.session[-1].stop(packet)
		print("Session terminated: " + str(self.session[-1]))

print("looking for management frames ...")
print("")

start = time.time()

for file_var in sorted(os.listdir(os.getcwd())):
	filename = os.fsdecode(file_var)

	if filename.startswith(sys.argv[2]):
		with PcapReader(filename) as pcap_reader:
			packet = pcap_reader.read_packet()

			print(filename + " starts at " + str(datetime.fromtimestamp(packet.time)))
			print("--------------------------------------------------------------")

			for index, packet in enumerate(pcap_reader):
				if packet.haslayer(Dot11AssoReq):
					frame_type = "AssReq  "

				elif packet.haslayer(Dot11AssoResp):
					frame_type = "AssRsp  "

				elif packet.haslayer(Dot11ReassoReq):
					frame_type = "ReassReq"

				elif packet.haslayer(Dot11ReassoResp):
					frame_type = "ReassRsp"

				elif packet.haslayer(EAPOL):
					frame_type = "EAPOL   "
					addr = packet[Dot11].addr1

					# FIXME: check if all EAPOL packets were received (no loss)
					if packet[EAPOL].len == 175: # Msg #3 always has this length
						client = addr_to_client(addr)
						client.auth(packet)

				elif packet.haslayer(Dot11Auth):
					frame_type = "Auth    "

				elif packet.haslayer(Dot11Deauth):
					frame_type = "Deauth  "

					client = addr_to_client(addr)
					client.deauth(packet)

				elif packet.haslayer(Dot11Disas):
					frame_type = "Disass  "

				else:
					continue

				print("[" + str(datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")) + "] ", end='', flush=True)
				print("[" + str(index) + "] [" + frame_type + "] ", end='', flush=True)
				print("addr1: " + mac_resolve(packet[Dot11].addr1) + " ", end='', flush=True)
				print("addr2: " + mac_resolve(packet[Dot11].addr2) + " ", end='', flush=True)
				print("addr3: " + mac_resolve(packet[Dot11].addr3) + " ", end='', flush=True)
				print("")

			print("")

end = time.time()

print("finished!")
print("took " + str(end - start) + "s")
