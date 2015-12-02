import hashlib  
import getpass  

FILENAME = 'passwordHex.txt'

#Write data to file
print "This script will create a hex digest of a password entered and associate it with a user name."
f = open(FILENAME, 'w')
iterations = int(raw_input("Enter how many users you want to create: "))
for i in range(0, iterations):
	username = raw_input("Please Enter User to save: ")
	password = getpass.getpass()
	#Writing username and password to file
	f.write('{}::{}\n'.format(username, hashlib.sha512(password).hexdigest()))
f.close()
print "Successfully created password hex digest for users!"
print "File is called " + FILENAME