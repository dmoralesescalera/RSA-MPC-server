from flask import Flask, request, abort
from subprocess import Popen
from threading import Thread
import requests
import json
import sys
import os

app = Flask(__name__)

serviceThread = None

###############

def run_func():
	arg = "python ~/viff/apps/mpc_server_1.py"
	Popen(arg, shell=True)

###############

"""
	nodeInfo = {
		"id" : "s001",
		"ip" : "1.1.1.1",
		"port" : 5000	
	}
"""

@app.route('/configNode', methods=['POST'])
def handler_configNode():
	if not request.json:
		abort(400)

	nodeInfo = json.dumps(request.json)
	with open("nodeInfo.json", "w+") as json_file:
		json_file.write(nodeInfo)
	json_file.close()

	return json.dumps({ "status" : "ok" })

"""
	mpcNodeList = {
		"mpcNodeList" : {[
			{"id" : "serverInfo", "num" : 2},
			{"id" : "s001", "ip" : "1.1.1.1"},
			{"id" : "s002", "ip" : "1.1.1.2"}		
		]}
	}
"""

@app.route('/configNetwork', methods=['POST'])
def handler_configNetwork():
	if not request.json:
		abort(400)

	mpcNodeList = json.dumps(request.json)
	with open("mpcNodeList.json", "w+") as json_file:
		json_file.write(mpcNodeList)
	json_file.close()

	return json.dumps({ "status" : "ok" })

@app.route('/runService', methods=['GET'])
def handler_runService():
	
	arg = "python ~/viff/apps/mpc_server_1.py"
	serviceThread = Popen(arg, shell=True)

	return json.dumps({ "status" : "ok" })

	
	

###############

if __name__ == '__main__':
	print os.getpid()
	app.run(host='0.0.0.0', port=5000, debug=True)
