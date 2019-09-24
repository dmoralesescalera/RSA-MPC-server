from flask import Flask, jsonify, abort, make_response, request, url_for, redirect
#from flask_httpauth import HTTPTokenAuth
#from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
import requests
import json
import ssl
import OpenSSL
import random
from threading import Lock, Thread
from OpenSSL import crypto

app = Flask(__name__)

#########################
### PRE-SET RESOURCES ###
#########################

orqId = "o001"

serverList = [
	{
		"id": "serverInfo",
		"num": 3
	},
	{
		"id": "s001",
		"ip": "1.1.1.1",
		"port": 5000
	},
	{
		"id": "s002",
		"ip": "1.1.1.2",
		"port": 5000
	},
	{
		"id": "s003",
		"ip": "1.1.1.3",
		"port": 5000
	}
]


"""
keyList = [
	{
		"keyId": 9999,
		"publicKey": "30819e300d06092a864886f70d010101050003818c003081880281803af1017d70a6bb7f93e0cc369648cb4a3b3079877a5f00f8f6d76a1347291afea0c139b085724a35cf8e060b69070cc4470e327199fd72b5015f1845f21cfdd69fa235ac8129dd2c785cff47f36721238866d128ec4b27284e2750609f44e0ee93d7b0891aa2fa7303c2e638dfb9c0b94c5586c4d436a28cb64d84041951d4b10203010001",
		"server1": "s001",
		"server2": "s002",
		"server3": "s003"
	}
]
"""

"""
keyList = [
	{
		"keyId": Integer,
		"publicKey": String,
		"server1": String,
		"server2": String,
		"server3": String
	}
]
"""

responses = []

token = "randomGeneratedToken"

lock = Lock()


##############################
### AUTHENTICATION METHODS ###
##############################



########################
### AUXILIAR METHODS ###
########################

def pretty_print(char, text):
	print ""	
	print char*40
	print text
	print char*40
	print ""

def make_public_resource(resource):
	new_resource = {}
	for field in resource:
		if field == "id":
			new_resource["uri"] = url_for("get_resource", resource_title=resource["title"], _external=True)
		else:
			new_resource[field] = resource[field]
	return new_resource

def select_servers():
	server1 = random.randrange(1, serverList[0]["num"] + 1, 1)

	server2 = random.randrange(1, serverList[0]["num"] + 1, 1)	
	while server2 == server1:
		server2 = random.randrange(1, serverList[0]["num"] + 1, 1)

	server3 = random.randrange(1, serverList[0]["num"] + 1, 1)
	while server3 == server1 or server3 == server2:
		server3 = random.randrange(1, serverList[0]["num"] + 1, 1)

	return [serverList[server1], serverList[server2], serverList[server3]]
	#return [serverList[1], serverList[2], serverList[3]]

def gen_key_post(target, payload, headers):
	print "/// Init thread ///"	
	global responses
	r = requests.post(target, data=json.dumps(payload), headers=headers)
	lock.acquire()
	responses.append(dict(json.loads(r.text)))
	#pretty_print('$', responses)
	lock.release()
	print "/// Finish thread ///"

def sign_hash_get(target):
	print "/// Init thread ///"
	global responses
	r = requests.get(target)
	lock.acquire()
	responses.append(dict(json.loads(r.text)))
	pretty_print('$', responses)
	lock.release()
	print "/// Finish thread ///"

def verify_keyId(keyId):
	for item in keyList:
		if item["keyId"] == keyId:
			return item
	return None

def get_ListItem(item, itemList):
	for this in itemList:
		if this == item:
			return this
	return None

def create_cert(req, issuer_cert, issuer_sk, serial, valid=365, digest="sha1"):
	"""Generate a certificate given a certificate request."""
	cert = crypto.X509()
	cert.set_serial_number(serial)
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(valid * 60 * 60 * 24)
	cert.set_issuer(issuer_cert.get_subject())
	cert.set_subject(req.get_subject())
	cert.set_pubkey(req.get_pubkey())
	cert.sign(issuer_sk, digest)
	return cert

def load_key(filename):
	"""Open a key saved as a PEM file."""
	fp = open(filename, "r")
	dump_key = fp.read()
	fp.close()
	priv_key = crypto.load_privatekey(crypto.FILETYPE_PEM, dump_key)
	return priv_key

def load_cert(filename):
	"""Open a certificate saved as a PEM file."""
	fp = open(filename, "r")
	dump_cert = fp.read()
	fp.close()
	cert = crypto.load_certificate(crypto.FILETYPE_PEM, dump_cert)
	return cert

####################################
### CLIENT-SIDE REQUEST METHODS  ###
####################################

@app.route('/createCertificates', methods=['POST'])
def handler_getCert():
	pretty_print('*', "[CA] getCert")
	
	# Get cert_request from Node
	serial = request.json['serial']
	reqs = request.json['req']
	if len(reqs) != 3:
		print "ERROR - Bad requests array len"
		return json.dumps({ "status": "certError" })
	else:
		obj_req = []
		for dump_req in reqs:
			obj_req.append(crypto.load_certificate_request(crypto.FILETYPE_PEM, dump_req))
			
		# Load CA key and cert
		ca_key = load_key("ca.key")
		ca_cert = load_cert("ca.cert")
		dump_ca_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)

		# Create Node certificates
		dump_certs = []
		for req in obj_req:
			cert = create_cert(req, ca_cert, ca_key, serial)
			dump_certs.append(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

		pretty_print('X', dump_certs)
		return json.dumps({ "status": "certOK", "ca_cert": dump_ca_cert, "certs": dump_certs })
	
######################
### ERROR HANDLER  ###
######################

@app.errorhandler(404)
def not_found(error):
	return make_response(jsonify({'error': 'Not found'}), 404)


if __name__ == '__main__':
	
	app.run(host='0.0.0.0', port=5000, debug=True)
	#app.run(debug=True, ssl_context=ssl_context)

