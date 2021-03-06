#!/usr/bin/python3

import os
import sys
import time
import datetime

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/../scapy')

from subprocess import run
from scapy.all import *

if len(sys.argv) < 5:
	print("usage: " + sys.argv[0] + " SSID AP_MAC PASSPHRASE FILE_PREFIX")
	sys.exit()

SSID = sys.argv[1]
AP_MAC = sys.argv[2]
PASSPHRASE = sys.argv[3]
FILENAME = "wcap"

mac_addresses = {
	AP_MAC : "AP               "
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
	if not addr:
		return None

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
		self.end = None
		self.active = True
		self.filename = FILENAME + "-" + self.client.addr.replace(":","") + "-" + str(client.session_id) + ".pcap"
		self.writer = PcapWriter(self.filename)
		client.session_id += 1
		print("Session started: " + str(self))

	def __str__(self):
		return "client: " + str(self.client) + " start: " + \
		str(datetime.fromtimestamp(self.start.time)) + \
		(" end: " + str(datetime.fromtimestamp(self.end.time)) if isinstance(self.end, Packet) else "")

	def stop(self, packet):
		if self.active:
			self.end = packet
			self.active = False
			self.writer.close()
			print("### Decrypting " + self.filename + ":")
			subprocess.run(["airdecap-ng", "-e", SSID, "-b", AP_MAC, "-p", PASSPHRASE, self.filename])
			# FIXME: delete pcap file if EAPOL not completed
			print("Session terminated: " + str(self))

	def add(self, packet):
		if self.active:
			self.writer.write(packet)

class Client:
	session_id = 0

	def __init__(self, addr):
		self.addr = addr
		self.session = []
		# FIXME: last case with EAPOL spam does not work
		self.latest_seen = None
		self.latest_lock = True

	def __str__(self):
		# FIXME: use mac_addresses {} above (AP)
		return "addr: " + self.addr

	def auth(self, packet):
		if self.session:
			if self.latest_seen is not None:
				self.deauth(self.latest_seen)

			else:
				self.deauth(packet)

		self.session.append(Session(self, packet))
		self.latest_lock = False

	def deauth(self, packet):
		if self.session:
			self.session[-1].stop(packet)

	def add(self, packet):
		if self.session:
			self.session[-1].add(packet)

print("looking for management frames ...")
print("")

start = time.time()

for file_var in sorted(os.listdir(os.getcwd())):
	filename = os.fsdecode(file_var)

	if filename.startswith(sys.argv[4]):
		with PcapReader(filename) as pcap_reader:
			packet = pcap_reader.read_packet()

			# File is empty
			if not packet:
				continue

			print(filename + " starts at " + str(datetime.fromtimestamp(packet.time)))
			print("--------------------------------------------------------------")

			for index, packet in enumerate(pcap_reader):
				addr_src = packet[Dot11].addr1
				client_src = addr_to_client(addr_src)

				addr_dst = packet[Dot11].addr2
				client_dst = addr_to_client(addr_dst)

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
					if packet[Raw].load[1] == 0x00 and packet[Raw].load[2] == 0x8a:
						frame_type = "EAPOL #1"
						client_src.auth(packet)

					if packet[Raw].load[1] == 0x01 and packet[Raw].load[2] == 0x0a:
						frame_type = "EAPOL #2"

					if packet[Raw].load[1] == 0x13 and packet[Raw].load[2] == 0xca:
						frame_type = "EAPOL #3"

					if packet[Raw].load[1] == 0x03 and packet[Raw].load[2] == 0x0a:
						frame_type = "EAPOL #4"
						# FIXME: check if all EAPOL packets were received (no loss)

				elif packet.haslayer(Dot11Auth):
					frame_type = "Auth    "

					if client_src:
						client_src.latest_lock = True

					if client_dst:
						client_dst.latest_lock = True

				elif packet.haslayer(Dot11Deauth):
					frame_type = "Deauth  "

					# Either side can send a Deauth frame
					if addr_src != AP_MAC:
						client_src.deauth(packet)

					else:
						client_dst.deauth(packet)

				elif packet.haslayer(Dot11Disas):
					frame_type = "Disass  "

				else:
					# All the frames above should not count as latest_seen
					if client_src and not client_src.latest_lock:
						client_src.latest_seen = packet

					if client_dst and not client_dst.latest_lock:
						client_dst.latest_seen = packet

				if client_src:
					client_src.add(packet)

				if client_dst:
					client_dst.add(packet)

				if frame_type is not None:
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
