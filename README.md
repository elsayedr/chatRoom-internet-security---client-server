#How to use our code
-------------------------------------------
Run the Server
--------------------------------------------
python chat_server.py 

--------------------------------------------
Run the Client
--------------------------------------------
python chat_client.py username
For example, python chat_client.py rew

--------------------------------------------
Existing Authentication  
--------------------------------------------
UserName	Password
----------------------------
rew		123456
set		1230
rew1		23456
set1		1231
rew2		13456
set2		1232
rew3		12456
set3		1233
rew4		12356
set4		1234
--------------------------------------------


--------------------------------------------
Send Message to Multiple Clients
--------------------------------------------
Message to be Entered at the Command Prompt follows this format:
[set3@127.0.0.1]>1 set Testingsend 
	-- sends message 'Testingsend' to '1' client named 'set'
[set3@127.0.0.1]>2 set set2 Testingsend 
	-- sends message 'Testingsend' to '2' clients named 'set' and 'set2'
[set3@127.0.0.1]>0 Testingsend 
	-- sends message 'Testingsend' to all connected clients -- basically Boradcast

If any client that is not online is to be sent message, we get appropriate error for each unavailable user. 
--------------------------------------------
