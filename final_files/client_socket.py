import socket
import sys
import gmpy

def sign_check():
	base = gmpy.mpz(firma)
	power = gmpy.mpz(e)
	modulus = gmpy.mpz(n)
	m = int(pow(base, power, modulus))
	print "m: " + str(m)

while 1:
	command = raw_input("Comando: ")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('127.0.0.1', 5000))
	s.send(command)

	if command == 'g':
		n = int(s.recv(20))
		e = int(s.recv(10))
		print "n: " + str(n)
		print "e: " + str(e)
	elif command == 'f':
		hashV = raw_input("Hash: ")
		s.send(hashV)
		firma = int(s.recv(60))
		print "firma: " + str(firma)
		sign_check()

	s.close()


