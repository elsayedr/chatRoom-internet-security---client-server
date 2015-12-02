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
[set3@127.0.0.1]>2 phani ibrahim This is a message. 
	-- sends message 'This is a message.' to '2' clients named 'phani' and 'ibrahim'
[set3@127.0.0.1]>0 This is a message. 
	-- sends message 'This is a message.' to all connected clients

Error message occurs if you try to send a message to a user who isn't logged in.
