import subprocess
import json
import requests
from requests.exceptions import ConnectionError

def get_docker_container_ip(cont_name="rsa-docker_node_", net_name="rsa-net", max_iter=20):

	''' Itera sobre uno o varios contenedores en un rango y para
 	cuando llega al primer contenedor no existente'''

 	ips = list()
 	for i in range(1, max_iter):
		path = "docker container inspect " + cont_name + str(i)
		try:
			output = subprocess.check_output(path)
			l = len(output) - 3
			a = output[3:l]
			dic = dict(json.loads(a))
			ips.append(dic["NetworkSettings"]["Networks"][net_name]["IPAddress"])
		except subprocess.CalledProcessError:
			break
	return ips
	
cont_ip = get_docker_container_ip()
ca_ip = get_docker_container_ip("rsa-docker_ca_", "rsa-net", 2)

print cont_ip
print ca_ip

test_file = open("./test/ips.txt", "w")
for ip in cont_ip:
	test_file.write(str(ip) + "\n")
for ip in ca_ip:
	test_file.write("ca: " + str(ip) + "\n")
test_file.close()		

path = "docker build -t test ./test"
try:
	output = subprocess.check_output(path)
except subprocess.CalledProcessError:
	print "error"

path = "docker run -it --network rsa-net test"
try:
	output = subprocess.check_output(path)
except subprocess.CalledProcessError:
	print "error"