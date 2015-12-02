#CSCE813 Internet Security Chat Project
#Authors: Maximus Brandel, Ibrahim Elsayed, Phani Soumya Inguva, and Ibrahim Alkhalifah
This is an open source client/server chat program we found that had no security implemented.
Our goal was to implement three security principles, confidentiality, integrity, and authentication.

We achieved confidentiality in two ways:
1.  RSA encryption:  The client and server both exchange their public keys.  They then use each others keys to encrypt their data between each other.  Once they have received their data, they then use their private keys to decrypt the data.  
2.  Messages for specific users:  A user can send a specific set of users a message intended only for them by typing a number which indicates how many users to send the message to, followed by their usernames, then followed by the message. Our program allows a user to send a message to all users who are connected by typing a "0" before the message.  We have included an example below showing the format for sending a message.

We achieved integrity in one way:
1.  SHA512:  We encrypt a message, append a signature using SHA512 to create a message digest, and finally sign it with our private key.  

We achieved authentication in two ways:  
1.  Certificates: We have a script that creates a server certificate and private key.  Using SSL allows us to easily have the client verify that they are indeed talking to the server by checking the server's certificate. 
2.  Passwords: We created a script that will create a hex digest of the users passwords using SHA512 and are stored in a file for the server to access.  The client then creates a hex digest of the password entered when prompted and sends that to the server for verification.  Since this program was more about testing security, we didn't worry about the server/client creating a password and storing it in a database.  We assume that the passwords/usernames are stored in passwordHex.txt for access by the server. 

#How to use our code

#User Authentication
We have created a script to create a hex digest of a password for a given user.
You should run that first if you want to try your own usernames and passwords.
Else, you can just run it with the given passwordHex.txt contents:
username, password
maximus, 111
ibrahim, 222
phani, 333

#Run the Server
python chat_server.py 

#Run the Client
python chat_client.py username

For example, python chat_client.py maximus
You will then be prompted to enter the password, which is 111 for maximus

You should run at least two clients if you want to try and send a message.

#Send Message to Multiple Clients
Message to be Entered at the Command Prompt follows this format:

[maximus@127.0.0.1]>1 phani This is a message. 
	-- sends message 'This is a message' to '1' client named 'phani'
[maximus@127.0.0.1]>2 phani ibrahim This is a message. 
	-- sends message 'This is a message.' to '2' clients named 'phani' and 'ibrahim'
[maximus@127.0.0.1]>0 This is a message. 
	-- sends message 'This is a message.' to all connected clients

Error message occurs if you try to send a message to a user who isn't logged in.
