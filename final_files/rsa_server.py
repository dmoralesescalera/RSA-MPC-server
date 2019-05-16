import socket
import sys
from subprocess import Popen
from binascii import hexlify, unhexlify

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
		#n = f.readline()
		#e = f.readline()
		#print "n: " + n
		#print "e: " + e
		#clientsocket.send(n)
		#clientsocket.send(e)
		clientsocket.send('o')
		clientsocket.close()
	elif c == 'f':
		hashLen = int(clientsocket.recv(2))
		hashV = clientsocket.recv(hashLen)
		print("[Server] hashLen: " + str(hashLen))
		print("[Server] hashV: " + str(hashV))
		f = open("buffer.txt", "w+")
		f.write(str(bytestrToInt(hashV)))
		f.close()
		firmar()
		f = open("buffer.txt", "r")
		firma = f.readline()
		f.close()
		print("[Server] IntFirma: " + firma)
		firma = intToBytestr(int(firma), 2000)
		print("[Server] Firma: " + hexlify(firma))
		clientsocket.send(str(len(firma)))
		print("[Server] firmaLen: " + str(len(firma)))
		clientsocket.send(firma)
		print("[Server] firma: " + hexlify(firma))
		clientsocket.close()

print "### Fin del servidor ###"
