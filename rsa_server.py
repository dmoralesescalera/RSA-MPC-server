import socket
import sys
from subprocess import Popen


def generar_claves():

	print "\n" + "*"*40 + "\n" + "<< Generar claves >>\n" + "*"*40 + "\n"

	arg1 = "python rsa_create_key.py player-1.ini"
	arg2 = "python rsa_create_key.py player-2.ini"
	arg3 = "python rsa_create_key.py player-3.ini"

	p1 = Popen(arg1, shell = True)
	p2 = Popen(arg2, shell = True)
	p3 = Popen(arg3, shell = True)

	p1.wait()
	p2.wait()
	p3.wait()

def firmar():	

	print "\n" + "*"*40 + "\n" + "<< Firmar valor >>\n" + "*"*40 + "\n"

	arg1 = "python rsa_sign.py player-1.ini"
	arg2 = "python rsa_sign.py player-2.ini"
	arg3 = "python rsa_sign.py player-3.ini"

	p1 = Popen(arg1, shell = True)
	p2 = Popen(arg2, shell = True)
	p3 = Popen(arg3, shell = True)

	p1.wait()
	p2.wait()
	p3.wait()


# Bucle principal del servidor
print "### Inicio del servidor ###"

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(('127.0.0.1', 5000))
serversocket.listen(1)
while 1:
	print "### Esperando conexion con cliente ###"
	(clientsocket, address) = serversocket.accept()
	print "### Conexion con cliente realizada ###"
	c = clientsocket.recv(1)
	
	if c == 'g':
		generar_claves()
		f = open("pub_key.txt", "r")
		n = f.readline()
		e = f.readline()
		print "n: " + n
		print "e: " + e
		clientsocket.send(n)
		clientsocket.send(e)
		clientsocket.close()
	elif c == 'f':
		hashV = clientsocket.recv(20)
		f = open("buffer.txt", "w+")
		f.write(hashV)
		f.close()
		firmar()
		f = open("buffer.txt", "r")
		firma = f.readline()
		f.close()
		clientsocket.send(firma)
		clientsocket.close()

print "### Fin del servidor ###"
