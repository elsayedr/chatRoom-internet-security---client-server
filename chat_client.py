# -*- encoding: utf-8 -*-

import os
import socket
import sys
import select
import ssl
import getpass
import hashlib

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA512

from communication import send, receive

import requests
from OpenSSL import crypto

class chat_client(object):

    def __init__(self, name):
        self.name = name
        # Quit flag
        self.flag = False
        self.port = 3490
        self.host = 'localhost'

        print "Enter your password"
        #Encrypt the password
        self.password = hashlib.sha512(getpass.getpass())
        #print self.password.hexdigest()
        #print self.password.digest_size

        # Initial prompt
        self.prompt = '[' + '@'.join((name, socket.gethostname().split('.')[0])) + ']> '

        #May not need (Maximus)
        # Generate client certificate
        #print "Generating client certificate"
        #self.createClientCert(self.name)
        #print "Client certificate created"

        client_privateKey = RSA.generate(4096, os.urandom)
        client_pubkey = client_privateKey.publickey()

        self.decryptor = client_privateKey

        # Connect to server at port
        try:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.check_hostname = True

            #Get the servers CA certificate
            file_location = os.getcwd()
            self.context.load_verify_locations(file_location + "/server.crt")
            
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                # Check server certificate
                self.ssl_sock = self.context.wrap_socket(self.sock, server_hostname=self.host)
                self.ssl_sock.settimeout(2)
            except:
                print "Server certificate invalid, closing chat."
                exit(0)

            #Check cipher used, we expect none since we didn't specify any
            #print self.ssl_sock.cipher()

            self.ssl_sock.connect((self.host, self.port))
            print 'Connected to chat server %s:%d' % (self.host, self.port)
            # Send my pubkey...
            send(self.ssl_sock, client_pubkey.exportKey())
            server_pubkey = receive(self.ssl_sock)
            self.encryptionKey = RSA.importKey(server_pubkey)

            # Send my name...
            send(self.ssl_sock, 'NAME: ' + self.name)

            # Send my password...
            send(self.ssl_sock, 'PASSWORD: ' + self.password.hexdigest())
            #send(self.ssl_sock, 'PASSWORD: ' + self.password)
            # Print out users connected to server
            print receive(self.ssl_sock)

            data = receive(self.ssl_sock)
            # Contains client address, set it
            addr = data.split('CLIENT: ')[1]
            if  len(addr) > 15:#Means the server is not sending IP address of client
                print 'Password Verification Failed'
                print addr
                exit(0)
            self.prompt = '[' + '@'.join((self.name, addr)) + ']> '

        except socket.error:
            print 'Could not connect to chat server @%d' % self.port
            sys.exit(1)

    def cmdloop(self):
        while not self.flag:
            try:
                sys.stdout.write(self.prompt)
                sys.stdout.flush()

                # Wait for input from stdin & socket
                inputready, outputready, exceptrdy = select.select([0, self.sock], [], [])

                for i in inputready:
                    if i == 0:
                        # grab message
                        data = sys.stdin.readline().strip()

                        try:
                            # encrypt
                            data = self.encryptionKey.encrypt(data, 0)
                            data = data[0]

                            # append signature
                            signkey = self.decryptor
                            message_hash = SHA512.new()
                            message_hash.update(data)

                            signer = PKCS1_PSS.new(signkey)
                            signature = signer.sign(message_hash)
                            data = '%s#^[[%s' % (data, signature)

                        except ValueError:
                            print 'Too large text, cannot encrypt, not sending.'
                            data = None

                        if data:
                            send(self.ssl_sock, data)

                    elif i == self.sock:
                        data = receive(self.ssl_sock)

                        if not data:
                            print 'Shutting down.'
                            self.flag = True
                            break

                        else:
                            if 'PLAIN:' in data:
                                data = data.strip('PLAIN:').strip()
                            else:
                                #data = str(data)
                                data = self.decryptor.decrypt(data)


                            sys.stdout.write(data + '\n')
                            sys.stdout.flush()

            except KeyboardInterrupt:
                print 'Interrupted.'
                self.sock.close()
                break

    def createClientCert(self, name):
        try:
            os.system("python createClientCert.py %s" % name )
        except IOError:
            return False


if __name__ == "__main__":

    if len(sys.argv) < 2:
        sys.exit('Usage: python %s username' % sys.argv[0])

    client = chat_client(sys.argv[1])
    client.cmdloop()
