# -*- encoding: utf-8 -*-

import os
import select
import socket
import sys
import signal
from time import sleep
from communication import send, receive
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
import ssl




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
            msg_hash = SHA.new()
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

    def serve(self):
        inputs = [self.server, sys.stdin]
        self.outputs = []

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
                                msg = '\n# [' + self.getName(s) + ']>> ' + data

                                # Send msg to all except ourselves
                                for o in self.outputs:
                                    if o != s:
                                        self.sendEncryptedMsg(o, msg, self.get_just_name(s))

                        else:

                            print 'chat_server: Client %d hung up' % s.fileno()
                            self.numOfClients -= 1
                            s.close()
                            inputs.remove(s)
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
