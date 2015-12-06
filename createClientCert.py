# createClientCert.py

# Maximus Brandel
# Script to create a Self-Signed Certificate for a Client

import os
import sys

def createCert(uName):
	try:
		# Generate a Certificate Signing Request
		os.system('openssl req -nodes -newkey rsa:1024 -keyout %s.key -out %s.csr -subj "/C=US/ST=South Carolina/L=Columbia/O=CSCE813/OU=Internet Security/CN=%s"' % (uName, uName, uName))
		
		# Generate a Self-Signed Certificate
		os.system('openssl x509 -req -days 365 -in %s.csr -signkey %s.key -out %s.crt' % (uName , uName, uName))
	except:
		print "Error creating certificate"

if __name__ == "__main__":
	if len(sys.argv) < 1:
		sys.exit('Usage: %s username' % sys.argv[0])
	createCert(sys.argv[1])
