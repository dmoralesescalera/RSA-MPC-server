from flask import Flask, request
from subprocess import Popen
from threading import Thread
from binascii import hexlify, unhexlify
import json
import sys
import time
import smtplib

####################
### INITIAL DATA ###
####################

app = Flask(__name__)

"""
	Information about the actual server.
"""
serverInfo = {
	"id": "s001",
	"ip": "1.1.1.1",
	"port": 5001
}

"""
	Port range is predefined and 3 servers that run a MPC instance use 
	the same port.
	"status": 0 - Free
	"status": 1 - Busy
"""
mpcPortList = [
	{"port": 9000, "status": 0}, {"port": 9001, "status": 0}, 
	{"port": 9002, "status": 0}, {"port": 9003, "status": 0},
	{"port": 9004, "status": 0}, {"port": 9005, "status": 0}, 
	{"port": 9006, "status": 0}, {"port": 9007, "status": 0},
	{"port": 9008, "status": 0}, {"port": 9009, "status": 0}
]

"""
	Information about all the servers that exist in the MPC server cloud.
"""
mpcServerList = [
	{
		"id": "serverInfo",
		"num": 3
	},
	{
		"id": "s001",
		"ip": "1.1.1.1"
	},
	{
		"id": "s002",
		"ip": "1.1.1.2"
	},
	{
		"id": "s003",
		"ip": "1.1.1.3"
	}
]

"""
	List of the orquestrators submitted to the server, and the associated
	Ids, with management information (thread, server1, server2, server3).

	idList = [
		{
			"keyId": Integer,
			"thread": Thread,
			"server1": String,
			"server2": String,
			"server3": String
		}, ...
	]
"""
orqList = [
	{"orqId": "o001", "idList": [
		{
			"keyId": 9999,
			"thread": Thread(None),
			"server1": "s001",
			"server2": "s002",
			"server3": "s003"		
		}
	]}
]

##########################
### AUXILIAR FUNCTIONS ###
##########################

def i2osp(x, xLen):		# Integer to list of Integers(bytes)
	if x >= 256**xLen:
		raise ValueError("integer too large")
	digits = []
	
	while x:
		digits.append(int(x % 256))
		x //= 256
	for i in range(xLen - len(digits)):
		digits.append(0)
	
	return digits[::-1]

def il2str(X):			# List of Integers to String
	cad = ''
	for i in range(len(X)):
		cad = cad + chr(X[i])

	return cad

def os2ip(X):			# List of Integers(bytes) to Integer
	xLen = len(X)
	X = X[::-1]
	x = 0
	for i in range(xLen):
		x += X[i] * 256**i

	return x

def bytestrToInt(bstr):		# Byte array to Integer
	intList = list(bstr)
	for e in range(0, len(intList)):
		intList[e] = ord(intList[e])
	intValue = os2ip(intList)
	return intValue

def intToBytestr(x, xLen):	# Integer to Byte String
	intList = i2osp(x, xLen)
	while(intList[0] == 0):
		intList.pop(0)
	bstr = il2str(intList)
	return bstr

def pretty_print(char, text):
	print char*40
	print text
	print char*40

def verify_orquestrator(orqId):
	for orq in orqList:
		if orq["orqId"] == orqId:
			return orq
	return None

def genKey_func(keyId, server1, server2, server3, port):
	print "Thread init"
	
	# The 3 servers use the same port for MPC
	if server1 == serverInfo["id"]:
		playerNumber = "player-1.ini"
	elif server2 == serverInfo["id"]:
		playerNumber = "player-2.ini"
	elif server3 == serverInfo["id"]:
		playerNumber = "player-3.ini"	

	for server in mpcServerList:
		if server["id"] == server1:
			sv1 = server["ip"] + ":" + str(port)
		if server["id"] == server2:
			sv2 = server["ip"] + ":" + str(port)
		if server["id"] == server3:
			sv3 = server["ip"] + ":" + str(port)

	arg0 = "python ~/viff/apps/generate-config-files.py -n 3 -t 1 " + sv1 + " " + sv2 + " " + sv3
	p0 = Popen(arg0, shell=True)
	p0.wait()

	arg = "mkdir ~/viff/apps/key" + keyId
	Popen(arg, shell=True).wait()	

	arg1 = "python ~/viff/apps/rsa_create_key.py ~/viff/apps/" + playerNumber + " ~/viff/apps/key" + keyId
	p1 = Popen(arg1, shell=True)
	p1.wait()
	
	"""
	# Send email notifying that generation process has finished
	server = smtplib.SMTP('localhost', 1025)
	message = "Key with keyId " + str(keyId) + " has been generated correctly.\nAsk to the orquestrator to get the public key."
	server.sendmail('sender@mail.com', 'receiver@mail.com', message)
	"""

	# Set port to available again
	for p in mpcPortList:
		if p["port"] == int(port):
			p["status"] = 0

	print "Thread finish"

def sign_method(message, keyId, port, server1, server2, server3):
	formatted_message = str(bytestrToInt(unhexlify(message)))
	
	# Write message to sign on buffer, Integer formatted
	f = open("./key" + str(keyId) + "/buffer.txt", "w+")
	f.write(formatted_message)
	f.close()
	
	# The 3 servers use the same port for MPC
	if server1 == serverInfo["id"]:
		playerNumber = "player-1.ini"
	elif server2 == serverInfo["id"]:
		playerNumber = "player-2.ini"
	elif server3 == serverInfo["id"]:
		playerNumber = "player-3.ini"	

	for server in mpcServerList:
		if server["id"] == server1:
			sv1 = server["ip"] + ":" + str(port)
		if server["id"] == server2:
			sv2 = server["ip"] + ":" + str(port)
		if server["id"] == server3:
			sv3 = server["ip"] + ":" + str(port)

	arg0 = "python ~/viff/apps/generate-config-files.py -n 3 -t 1 " + sv1 + " " + sv2 + " " + sv3
	p0 = Popen(arg0, shell=True)
	p0.wait()

	arg1 = "python ~/viff/apps/rsa_sign.py ~/viff/apps/" + playerNumber + " " + str(keyId)
	p1 = Popen(arg1, shell = True)
	p1.wait()

	f = open("./key" + str(keyId) + "/buffer.txt", "r")
	firma = f.readline()
	f.close()

	firma = hexlify(intToBytestr(int(firma), 2000))
	return firma

############################
### HTTP REQUEST METHODS ###
############################

@app.route('/generateKeys/<string:orqId>/<int:keyId>', methods=['POST'])
def handler_generateKeys(orqId,keyId):
	# Check json has 3 servers and MPC communication port
	if not request.json:
		abort(400)

	pretty_print('*', 'generateKey method')
	
	# Check for orquestrator identification
	orquestrator = verify_orquestrator(orqId)
	if orquestrator != None:
		# Orquestrator exists

		# Set port as not available port
		for p in mpcPortList:
			if p["port"] == request.json["port"]:
				p["status"] = 1
		
		# Create thread for MPC communication
		t = Thread(target=genKey_func, args=( 
						str(keyId), 
						str(request.json["server1"]), 
						str(request.json["server2"]),
						str(request.json["server3"]),
						str(request.json["port"])))

		# Create key information (after checking existence)
		keyIdItem = {
			"keyId": keyId,
			"thread": t,
			"server1": request.json["server1"],
			"server2": request.json["server2"],
			"server3": request.json["server3"]		
		}
		orquestrator["idList"].append(keyIdItem)

		# Start thread for keyPair creation
		t.start()
		return json.dumps({"status": "generatingKeys"})

	else:
		# Orquestrator does not exist
		return json.dumps({"status": "badOrqId"})

@app.route('/getPorts', methods=['GET'])
def handler_getPorts():
	availablePorts = []
	for item in mpcPortList:
		if item["status"] == 0:
			availablePorts.append(item["port"])
	return json.dumps({"availablePorts": availablePorts})

@app.route('/getKey/<string:orqId>/<int:keyId>', methods=['GET'])
def handler_getKey(orqId, keyId):
	pretty_print('*', 'getKey method')

	# Check for orquestrator identification
	orquestrator = verify_orquestrator(orqId)	
	if orquestrator != None:
		# Orquestrator exists
		
		thread_status = False
		for keyItem in orquestrator["idList"]:
			if keyItem["keyId"] == keyId:
				thread_status = keyItem["thread"].is_alive()

		if thread_status:
			return json.dumps({"status": "generatingKeys"})
		else:
			# Get public key
			f = open("./key" + str(keyId) + "/pub_key.txt", "r")
			pubKey = f.read()
			f.close()
			return json.dumps({"status": "generated", "pubKey": pubKey})

	else:
		# Orquestrator does not exist
		return json.dumps({"status": "badOrqId"})

@app.route('/signMessage/<string:orqId>/<int:keyId>', methods=['GET'])
def handler_signMessage(orqId, keyId):
	pretty_print('*', 'signMessage method')

	# Check for orquestrator identification
	orquestrator = verify_orquestrator(orqId)
	if orquestrator != None:
		# Orquestrator exists

		# Get servers info associated to keyId
		keyList = orquestrator["idList"]
		for keyData in keyList:
			if keyData["keyId"] == keyId:
				server1 = keyData["server1"]
				server2 = keyData["server2"]
				server3 = keyData["server3"]	

		# Check thread status - generation process finished
		thread_status = False
		for keyItem in orquestrator["idList"]:
			if keyItem["keyId"] == keyId:
				thread_status = keyItem["thread"].is_alive()

		if thread_status:
			return json.dumps({"status": "generatingKeys"})
		else:
			port = request.args["port"]
			sign = sign_method(request.args["message"], 
						keyId, 
						port, 
						server1, 
						server2, 
						server3)
			return json.dumps({"status": "signed", "sign": sign})

	else:
		# Orquestrator does not exist
		return json.dumps({"status": "badOrqId"})
			

if __name__ == '__main__':
	app.run(host='0.0.0.0',port=5000,debug=True)
