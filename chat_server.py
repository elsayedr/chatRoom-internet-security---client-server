# -*- encoding: utf-8 -*-

import os
import select
import socket
import sys
import signal
import ssl
import hashlib
from time import sleep
from communication import send, receive
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA512


class chat_server(object):
	def __init__(self):
		self.address = 'localhost'
		self.port = 3490

		print 'Generating Server Certificate...'
		self.createServerCert()
		print "Server certificate created"
		self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
		self.context.load_cert_chain(certfile="server.crt", keyfile="server.key")

		self.numOfClients = 0

		# Client map
		self.clientmap = {}

		# Output socket list
		self.outputs = []

		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind((self.address, self.port))

		print 'Generating RSA keys ...'
		self.server_privateKey = RSA.generate(4096, os.urandom)
		self.server_publicKey = self.server_privateKey.publickey()

		print 'Listening to port', self.port, '...'
		self.server.listen(5)

		# Trap keyboard interrupts
		signal.signal(signal.SIGINT, self.sighandler)

	def sighandler(self, signum, frame):
		# Close the server
		print 'Shutting down server...'

		# Close existing client sockets
		for o in self.outputs:
			o.close()

		self.server.close()

	def getName(self, client):
		# Return the printable name of the
		# client, given its socket...
		info = self.clientmap[client]
		host, name = info[0][0], info[1]
		return '@'.join((name, host))

	def get_just_name(self, client):
		return self.clientmap[client][1]

	def sendEncryptedMsg(self, to_who, message, name):
		try:
			encryptionKey = self.clientmap[to_who][2]
			msg = encryptionKey.encrypt(message, 0)
			send(to_who, msg)

		except IOError:
			send(to_who, 'PLAIN: cannot find public key for: %s' % name)

	def verifySignature(self, client, message, signature):
		try:
			key = self.clientmap[client][2]
			msg_hash = SHA512.new()
			msg_hash.update(message)

			verifier = PKCS1_PSS.new(key)
			return verifier.verify(msg_hash, signature)

		except IOError:
			return False

	def createServerCert(self):
		try:
			os.system("python createServerCert.py")
		except IOError:
			return False

	def lookup(dic, key, *keys):
		if keys:
			return lookup(dic.get(key, {}), *keys)
		return dic.get(key)

	# Function to read user and passwords from file
	def read_passwords(self, filename):
	    try:
	    	with open(filename, 'r') as f2:
	            return [x.strip() for x in f2.readlines()]
	    except:
	        print("There was a problem reading the file!")

	def serve(self):
		inputs = [self.server, sys.stdin]
		self.outputs = []

		#Create a password and Username Dictionary
		#passwordDict = {'rew': hashlib.sha1('123456'), 'set': hashlib.sha1('1230'), 'rew1': hashlib.sha1('23456'), 'set1': hashlib.sha1('1231'), 'rew2': hashlib.sha1('13456'), 'set2': hashlib.sha1('1232'), 'rew3': hashlib.sha1('12456'), 'set3': hashlib.sha1('1233'), 'rew4': hashlib.sha1('12356'), 'set4': hashlib.sha1('1234')}
		
		FILENAME = 'passwordHex.txt'
		# Converting data to dict where the key is the user and the value is the hashed password
		passwordDict = dict([x.split('::') for x in self.read_passwords(FILENAME)])

		existingCustomers = {}

		running = 1

		while running:
			try:
				inputready, outputready, exceptready = select.select(inputs, self.outputs, [])

			except select.error:
				break

			except socket.error:
				break

			for s in inputready:
				if s == self.server:
					# handle the server socket
					client, address = self.server.accept()
					connstream = self.context.wrap_socket(client, server_side=True)

					print 'chat_server: got connection %d from %s' % (client.fileno(), address)
					# Get client public key and send our public key
					publicKey = RSA.importKey(receive(connstream))
					send(connstream, self.server_publicKey.exportKey())

					# Read the login name
					cname = receive(connstream).split('NAME: ')[1]

					# Read the login password
					cpassword = receive(connstream).split('PASSWORD: ')[1]

					#if hashlib.sha1(cpassword).hexdigest() == passwordDict.get(cname).hexdigest():
					# Get hexdigest of clients password and see if it matches
					# our hexdigest
					# if cpassword == passwordDict.get(cname).hexdigest():
					if cpassword == passwordDict.get(cname):
						print "Username and Password Matched"
					else:
						send(connstream, 'CLIENT: Username and/or Password Does Not Match')
						continue
					
					if cname in existingCustomers.values():
						send(connstream, 'CLIENT: Customer with these Credentials is Already LoggedIn: Use Different Credentials')
						continue
					# Add customer's name to array
					existingCustomers[connstream] = cname
					print existingCustomers.values()
					send(connstream, 'Users connected: ' + str(existingCustomers.values()))

					# Compute client name and send back
					self.numOfClients += 1
					send(connstream, 'CLIENT: ' + str(address[0]))
					inputs.append(connstream)

					self.clientmap[connstream] = (address, cname, publicKey)

					# Send joining information to other clients
					msg = '\n(Connected: New client (%d) from %s)' % (self.numOfClients, self.getName(connstream))

					for o in self.outputs:
						try:
							self.sendEncryptedMsg(o, msg, self.get_just_name(o))

						except socket.error:
							self.outputs.remove(o)
							inputs.remove(o)

					self.outputs.append(connstream)

				elif s == sys.stdin:
					# handle standard input
					sys.stdin.readline()
					running = 0
				else:

					# handle all other sockets
					try:
						data = receive(s)

						if data:
							dataparts = data.split('#^[[')
							signature = dataparts[1]
							data = dataparts[0]

							verified = self.verifySignature(s, data, signature)
							data = self.server_privateKey.decrypt(data)

							if data != '\x00':
								if verified:
									data = '%s [verified]' % data

								else:
									data = '%s [Not verified]' % data

								
								# Send as new client's message...
								dataReceivers = data.split(' ')
								total = 0
								for rec in dataReceivers:
									total = total + 1
				
								dataReceivers = data.split(' ')
								try:
									numDataReceivers = int(dataReceivers[0])
									if numDataReceivers > 9:
										numDataReceivers = 0
					
									#print dataReceivers[0]

									if numDataReceivers != 0:
										print "Sending message to: "
										for k in xrange(1,numDataReceivers+1):
											print dataReceivers[k] + " "
										msg = '\n# [' + self.getName(s) + ']>> ' 
										for ltotal in xrange (1,total-numDataReceivers):
											msg = msg + dataReceivers[numDataReceivers+ltotal] + ' '

										for j in xrange(1, numDataReceivers+1):
											if dataReceivers[j] in existingCustomers.values():
												for o in self.outputs:
													if existingCustomers.get(o) == dataReceivers[j]:
														self.sendEncryptedMsg(o, msg, self.get_just_name(s))
											else:
												msg = '\n# [' + self.getName(s) + ']>> ' + 'Receiver ' + dataReceivers[j] + ' is NOT Logged In Now'
												self.sendEncryptedMsg(s, msg, self.get_just_name(s))
									else:
										# Send msg to all except ourselves
										print 'Sending message to all users'
										msg = '\nMessage from # [' + self.getName(s) + ']>> '
										for ltotal in xrange (1,total-numDataReceivers):
											msg = msg + dataReceivers[numDataReceivers+ltotal] + ' '
										for o in self.outputs:
											if o != s:
												self.sendEncryptedMsg(o, msg, self.get_just_name(s))
								
								except ValueError:
									msg = '\n# [' + self.getName(s) + ']>> ' + 'Message Not in Expected Format'
									self.sendEncryptedMsg(s, msg, self.get_just_name(s))
									continue

						else:

							print 'chat_server: Client %d hung up' % s.fileno()
							self.numOfClients -= 1
							s.close()
							inputs.remove(s)
							del existingCustomers[s]
							self.outputs.remove(s)

							# Send client-leaving information to others
							msg = '\n(Hung up: Client from %s)' % self.getName(s)

							for o in self.outputs:
								self.sendEncryptedMsg(o, msg, self.get_just_name(o))

					except socket.error:
						# Remove the input causing error
						inputs.remove(s)
						self.outputs.remove(s)

			sleep(0.1)

		self.server.close()

if __name__ == "__main__":

	if len(sys.argv) < 1:
		sys.exit('Usage: %s' % sys.argv[0])

	chat_server().serve()
