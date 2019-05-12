from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import time
import socket

SERVER_ID = 3

def generate_keys():
	private_key = rsa.generate_private_key(
		public_exponent=65537,
 		key_size=2048,
 		backend=default_backend()
	)
	public_key = private_key.public_key()
	with open('public_key_3.pem','wb') as open_file:
		public_pem = public_key.public_bytes(
			encoding = serialization.Encoding.PEM,
			format = serialization.PublicFormat.SubjectPublicKeyInfo
		)
		open_file.write(public_pem)
	with open('not_the_private_key_3.pem','wb') as open_file:
		private_pem = private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
			)
		open_file.write(private_pem)

def send_file(socket,filename):

	file_size = os.path.getsize(filename)

	initial_metadata = (str(file_size) + ',' + filename).encode()

	socket.send(initial_metadata)
	time.sleep(1)
	
	file_to_send = open(filename,'r')
	while file_size>0:
		temp_data = file_to_send.read(1024)
		socket.send(temp_data.encode())
		file_size -= len(temp_data)

def recieve_share(sock):
	total_string = ''
	data = sock.recv(1024)
	while data:
		total_string += data.decode()
		data = sock.recv(1024)
	return data


#Only run once on startup if needed, but for now just manually generating and
#commenting this out.
# generate_keys()

main_server_IP = '127.0.0.1'
main_server_port = 8109

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect((main_server_IP,main_server_port))

while True:
	signal = ''
	signal = sock.recv(1024)

	if(signal.decode() == ''):
		sock.connect((main_server_IP,main_server_port))

	if(signal.decode()=='Send public key!'):
		send_file(sock,'public_key_3.pem')

	print(signal)

	if(signal.decode()=='Sending shares!'):
		share = recieve_share(sock)
		print(share)

