# createServerCert.py

# Maximus Brandel
# Script to create a Self-Signed Certificate for a Server

import os

# Generate a Certificate Signing Request
os.system('openssl req -nodes -newkey rsa:1024 -keyout server.key -out server.csr -subj "/C=US/ST=South Carolina/L=Columbia/O=CSCE813/OU=Internet Security/CN=localhost"')
# Generate a Self-Signed Certificate
os.system('openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt')