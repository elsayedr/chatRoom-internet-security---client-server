# -*- encoding: utf-8 -*-

import os
import socket
import sys
import select

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA

from communication import send, receive


class chat_client(object):

    def __init__(self, name, host='127.0.0.1', port=3490):
        self.name = name
        # Quit flag
        self.flag = False
        self.port = int(port)
        self.host = host

        # Initial prompt
        self.prompt = '[' + '@'.join((name, socket.gethostname().split('.')[0])) + ']> '

        client_privkey = RSA.generate(4096, os.urandom)
        client_pubkey = client_privkey.publickey()

        self.decryptor = client_privkey

        # Connect to server at port
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, self.port))
            print 'Connected to chat server %s:%d' % (self.host, self.port)
            # Send my pubkey...
            send(self.sock, client_pubkey.exportKey())
            server_pubkey = receive(self.sock)

            self.encryptor = RSA.importKey(server_pubkey)

            # Send my name...
            send(self.sock, 'NAME: ' + self.name)
            data = receive(self.sock)

            # Contains client address, set it
            addr = data.split('CLIENT: ')[1]
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
                            data = self.encryptor.encrypt(data, 0)
                            data = data[0]

                            # append signature
                            signkey = self.decryptor
                            message_hash = SHA.new()
                            message_hash.update(data)

                            signer = PKCS1_PSS.new(signkey)
                            signature = signer.sign(message_hash)
                            data = '%s#^[[%s' % (data, signature)

                        except ValueError:
                            print 'Too large text, cannot encrypt, not sending.'
                            data = None

                        if data:
                            send(self.sock, data)

                    elif i == self.sock:
                        data = receive(self.sock)

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


if __name__ == "__main__":

    if len(sys.argv) < 3:
        sys.exit('Usage: %s username host portno' % sys.argv[0])

    client = chat_client(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    client.cmdloop()
