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

clients = []
addresses = []

def dump(obj):
	for attr in dir(obj):
		if hasattr( obj, attr ):
			print( "obj.%s = %s" % (attr, getattr(obj, attr)))

def mac_resolve(addr):
	return mac_addresses.get(addr, addr)

def addr_to_client(addr):
	if not addr in addresses:
		client = Client(addr)
		addresses.append(addr)
		clients.append(client)
		print("NEW: " + str(client))

	else:
		client = clients[addresses.index(addr)]

	return client


class Session:
	def __init__(self, client, packet):
		self.client = client
		self.start = packet
		self.active = True

	def __str__(self):
		return "client: " + str(self.client) + " start: " + \
		str(datetime.fromtimestamp(self.start.time)) + \
		("stop : " + str(datetime.fromtimestamp(self.stop.time)) if isinstance(self.stop, Packet) else "")

	def stop(self, packet):
		self.stop = packet
		self.active = False

class Client:
	def __init__(self, addr):
		self.addr = addr
		self.session = []

	def __str__(self):
		# FIXME: use mac_addresses {} above (AP)
		return "addr: " + self.addr

	def auth(self, packet):
		if self.session and self.session[-1].active:
			self.deauth(self.latest_seen)

		self.session.append(Session(self, packet))
		print("Session started: " + str(self.session[-1]))

	def deauth(self, packet):
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
				addr = packet[Dot11].addr1
				client = addr_to_client(addr)
				frame_type = None

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

					# FIXME: check if all EAPOL packets were received (no loss)
					if packet[EAPOL].len == 175: # Msg #3 always has this length
						client.auth(packet)

				elif packet.haslayer(Dot11Auth):
					frame_type = "Auth    "

				elif packet.haslayer(Dot11Deauth):
					frame_type = "Deauth  "

					client.deauth(packet)

				elif packet.haslayer(Dot11Disas):
					frame_type = "Disass  "

				if frame_type is not None:
					print("[" + str(datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")) + "] ", end='', flush=True)
					print("[" + str(index) + "] [" + frame_type + "] ", end='', flush=True)
					print("addr1: " + mac_resolve(packet[Dot11].addr1) + " ", end='', flush=True)
					print("addr2: " + mac_resolve(packet[Dot11].addr2) + " ", end='', flush=True)
					print("addr3: " + mac_resolve(packet[Dot11].addr3) + " ", end='', flush=True)
					print("")

				client.latest_seen = packet

			print("")

end = time.time()

print("finished!")
print("took " + str(end - start) + "s")
