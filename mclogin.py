#!/usr/bin/env python

import threading
import sys
import struct
import hashlib
import urllib2
from socket import *
from codecs import utf_16_be_encode, utf_16_be_decode
from time import time
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, DES
from hashlib import md5
from Crypto import Random
import hashlib

class AuthThread(threading.Thread):
	def __init__(self, socket, keys):
		threading.Thread.__init__(self)
		# Raw sockect
		self.sock = socket[0]
		# File socket
		self.socket = self.sock.makefile("r")
		# Remote connection info
		self.addr = socket[1][0]
		self.remotePort = socket[1][1]
		# Storage for username, server hash, server address, and our personal authkey
		self.username = ""
		# The client tells us what address they are connecting to
		self.server = ""
		# Holds the hash you may use for external refernece
		self.externalAuthKey = ""
		# Rsa demon keys
		self.key = keys
		# Start it up
		self.start()
	def run(self):
		while True:
			# Listen for packet IDs
			pID = self.read_unsigned_byte()
			# Ping packet (from client server list)
			if pID == 0xFE:
				self.sock.send( packeter.build( [("id",0xFF), ("strping","\xa71\x0049\x001.4.5\x00Minecraft Login Server\x000\x001")] ) )
				self.socket.close()
				return
			# Handshake packet
			elif pID == 0x02:
				# First comes the client's protocol. 49 = 1.4.4
				ClientProtocolVersion = self.read_byte()
				# Then the Username
				self.username = self.read_string()
				# Then the server name
				self.server = self.read_string()
				# and the server port
				self.serverPort = self.read_int()
				
				self.serverId = self.genrateLocalHash()
				pubKeyASM1 = self.key.publickey().exportKey(format="DER")
				
				self.authToken = chr(random.randint(97, 122))+chr(random.randint(97, 122))+chr(random.randint(97, 122))+chr(random.randint(97, 122));
				# Send them back our 0xFD server id, pub key, and auth token
				#                                             Server ID,             Pub key length,             Pub key in ASM.1       Auth token length (always 4)    Auth token
				self.sock.send( packeter.build( [("id",0xFD), ("str",self.serverId), ("short", len(pubKeyASM1)), ("bytes", pubKeyASM1), ("short", len(self.authToken)), ("bytes", self.authToken)] ) )
			elif pID == 0xFC:
				# Shared secret value (used in the hash the client and we send to session.minecraft)
				sharedSecretEncoded = self.read_byteArray()
				# Token we send in 0xFD encoded with our pub key (Why is this here?)
				verifyToken = self.read_byteArray()
				
				# Decrypt the secret with our private keu
				self.sharedSecret = self._pkcs1_unpad(self.key.decrypt(sharedSecretEncoded))
				
				# Create the server hash
				m = hashlib.sha1();
				m.update(self.serverId)
				m.update(self.sharedSecret)
				m.update( self.key.publickey().exportKey(format="DER") )
				
				# twos' for negative signed numbers
				d = long(m.hexdigest(), 16)
				if d >> 39 * 4 & 0x8:
					d = "-%x" % ((-d) & (2 ** (40 * 4) - 1))
				else:
					d = m.hexdigest()
				sha = "%s" % d
				# Say hello to session
				sessionQuery = ""
				try:
					u = urllib2.urlopen("http://session.minecraft.net/game/checkserver.jsp?user=%s&serverId=%s" % (self.username, sha))
					sessionQuery = u.read(3);
				except:
					self.sock.send( packeter.build( [("id",0xFF), ("str","Minecraft Session server is down! Please try again later.")] ) )
					self.socket.close()
					return
				
				if sessionQuery == "YES":
					
					" Right here, you could send text in a kick packet to the client or do whatever else. "
					
					self.sock.send( packeter.build( [("id",0xFF), ("str","You were logged in successfully!")] ) )
					self.socket.close()
					
					return
				else:
					ping = packeter.build( [("id",0xFF), ("str","Login Failed!")] )
					self.sock.send(ping)
					self.socket.close()
					return
			else:
				# Wat? Lets assume incompatible protocol
				self.sock.send( packeter.build( [("id",0xFF), ("str","Incompatible Protocol")] ) )
				self.socket.close()
				return
	# Unpad padded encrypted data
	def _pkcs1_unpad(self, bytes):
		pos = bytes.find('\x00')
		if pos > 0:
			return bytes[pos+1:]
	# md5 hash
	def md5(self, st):
		m = hashlib.md5()
		m.update(st)
		return m.hexdigest()
	def read_byteArray(self):
		length = self.read_unsigned_short()
		return self.socket.read(length)
	# reads a string from the stream (ushort length descriptor + actual string)
	def read_string(self):
		length = self.read_unsigned_short()
		return self.socket.read(length*2).replace("\x00", "");
	# read unsigned short from stream
	def read_unsigned_short(self):
		return struct.unpack("!H", self.socket.read(2))[0]
	# read unsigned bye from stream
	def read_unsigned_byte(self):
		d=self.socket.read(1)
		if len(d)==0:
			return None
		return struct.unpack("!B", d)[0]
	# read signed int from stream
	def read_int(self):
		return struct.unpack("!i", self.socket.read(4))[0]
	# read signed byte from stream
	def read_byte(self):
		d=self.socket.read(1)
		if len(d)==0:
			return None
		return struct.unpack("!b", d)[0]
	# Create a hash for misc purposes
	def genrateLocalHash(self):
		return self.md5("DAEPython?"+str(time()))[0:16]

# Class for easily building notchian packets
class PacketBuilder(object):
	def __init__(self):
		""
	def build(self, data):
		"given a list of type:value tuples, returns the raw packet data ready be sent"
		packet = []
		for item in data:
			packet.append( getattr(self, 'add_'+item[0])(item[1]) )
		packet = ''.join(packet)
		return packet
	# Packet IDs
	def add_id(self, id):
		return struct.pack("!H", id)[1]
	# stings
	def add_str(self, st):
		if len(st)==0:
			return '\x00\x00'
		st = utf_16_be_encode(st)
		return struct.pack("!h", st[1]) + st[0]
	# strings in ping packets
	def add_strping(self, st):
		if len(st)==0:
			return '\x00\x00'
		return struct.pack("!h", len(st)) + self.packetize_str(st)
	# raw bytes
	def add_bytes(self, value):
		return value
	# 2 byte short
	def add_short(self, num):
		return self.to_short(num)
	# int to short
	def to_short(self, value):
		return struct.pack("!h", value)
	# int to happy int
	def to_int(self, value):
		return struct.pack("!i", value)
	# stupid encoding for ping packets
	def packetize_str(self, st):
		return '\x00'+'\x00'.join(st)

# Packet builder helper object
packeter = PacketBuilder()

sys.stdout.write("Generating RSA Keys... ")
keys = RSA.generate(1024)
sys.stdout.write("Done.\n")

# Start listening
mainsocket = socket( AF_INET,SOCK_STREAM)
mainsocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
mainsocket.bind(("0.0.0.0", 25565)) # Listening address and  port
mainsocket.listen(9999) # maxiumum concurrent connections
while True:
	# Start a new thread per client
	s = mainsocket.accept();
	x = AuthThread(s, keys);


print "Giving love to savoie..."
you = 1
me = 1
love = you + me
if love = 2:
    isSavoieLoved = loved
    print "Savoie status: " + isSavoieLoved + "!"
else:
    print "Could not give love to Savoie :(  Please give him a hug."