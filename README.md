#Run the Server
python chat_server.py 

#Run the Client
python chat_client.py username

For example, python chat_client.py maximus

#Existing Authentication  
#UserName Password
maximus     111
ibrahim     222
phani       333

#Send Message to Multiple Clients
Message to be Entered at the Command Prompt follows this format:

[maximus@127.0.0.1]>1 phani This is a message. 
	-- sends message 'This is a message' to '1' client named 'phani'
[set3@127.0.0.1]>2 phani ibrahim This is a message. 
	-- sends message 'This is a message.' to '2' clients named 'phani' and 'ibrahim'
[set3@127.0.0.1]>0 This is a message. 
	-- sends message 'This is a message.' to all connected clients

Error message occurs if you try to send a message to a user who isn't logged in.
