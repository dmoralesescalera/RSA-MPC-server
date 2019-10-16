import requests
import json
from requests.exceptions import ConnectionError

def http_post_config_node(id, ip, port):

	''' Envia un mensaje post de configuracion de nodo '''
	
	data = { "id" : id, "ip": ip, "port": port }
	try:
		r = requests.post(
			"http://" + ip + ":" + str(port) + "/configNode",
			data = json.dumps(data),
			headers = { "content-type": "application/json" }
		)
		return r.text
	except ConnectionError as ce:
		return ce

def http_post_config_network(ip, port, network_list):

	''' Envia un mensaje post de configuracion de red '''
	
	try:
		r = requests.post(
			"http://" + ip + ":" + str(port) + "/configNetwork",
			data = json.dumps(network_list),
			headers = { "content-type": "application/json" }
		)
		return r.text
	except ConnectionError as ce:
		return ce

def http_get_certificates(ip, port):

	''' Envia un mensaje get al nodo para que solicite los
	certificados a la CA  '''	

	try:
		r = requests.get(
			"http://" + ip + ":" + str(port) + "/getCertificates"
		)
		return r.text
	except ConnectionError as ce:
		return ce


# Get every node's configuration info
ip_file = open("ips.txt", "r")
node_list = list()
ca = dict()
n_id = 0
for ip in ip_file:
	ip_fix_len = len(ip) - 2
	ip = ip[:ip_fix_len]
	if ip[:2] != "ca":
		n_id = n_id + 1
		n_id_s = "s00" + str(n_id)
		node = {"id": n_id_s, "ip": ip, "port": 5000}
		node_list.append(node)
	else:
		ca["ip"] = ip[4:]
print node_list
print ca		
			

# /configNode
for n in node_list:
	print http_post_config_node(n["id"], n["ip"], n["port"])

# /configNetwork
network_list = list()
for node in node_list:
	jnode = { "id": node["id"], "ip": node["ip"] }
	network_list.append(jnode)
jca = { "id": "ca", "ip": ca["ip"] }	
network_list.append(jca)
network_list = { "networkList": network_list }

for n in node_list:
	print http_post_config_network(n["ip"], n["port"], network_list)

for n in node_list:
	print http_get_certificates(n["ip"], n["port"])

for i in range(0,3):
	n = node_list[i]
	r = requests.post(
			"http://" + str(n["ip"]) + ":5000/generateKeys/o001/10",
			data = json.dumps(
					{"server1":"s001", 
					"server2":"s002", 
					"server3":"s003", 
					"port":9000}
				),
			headers = { "content-type": "application/json" }
		)