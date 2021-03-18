import socket
import json
import sys
import os
import hashlib
import random
import string

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from crypt import *


N = 64 #Length of salt (Should be good likes this)
PORT = 9876 #Server port - customizable

# Declaring socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('localhost', PORT))
s.listen(1)

# Decrypting RSA part of the combined encryption for accepted data
def rsa_decrypt(encrypted_data, key):
	with open(key, 'r') as f:
		priv_key = f.read()

	rsa_priv_key = RSA.importKey(priv_key)
	rsa_priv_key = PKCS1_OAEP.new(rsa_priv_key)
	data = rsa_priv_key.decrypt(encrypted_data)
	return data.decode('utf-8')

#Generating Salt and salting password, returning both in dict
def hash_pass(password):
	salt = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))
	dk = hashlib.pbkdf2_hmac('sha256', bytes(password, 'utf-8'), bytes(salt, 'utf-8'), 100000)

	return {'hash':dk.hex(), 'salt':salt}

#Hashing password with declared salt - used to check passwords against "database"
def rehash_pass(password, salt):
	dk = hashlib.pbkdf2_hmac('sha256', bytes(password, 'utf-8'), bytes(salt, 'utf-8'), 100000)

	return {'hash':dk.hex(), 'salt':salt}

#Figuring out which request has been recieved
def proccess_data(data):
	if "key" in data.keys():
		return save_key(data)

	elif "name" in data.keys():
		return send_key(data)

	elif "login" in data.keys():
		return check_creds(data)

	elif "id" in data.keys():
		return register_account(data)

	else:
		return "Unknown request!"

#Creating new .json file with user creds (named after user id)
def register_account(data):
	if data['id'] == "":
		return "No id was supplied"

	if os.path.isfile(f"{data['id']}.json"):
			return "id already taken!"

	else:
		hashed = hash_pass(data['pass'])
		data['salt'] = hashed['salt']
		data['pass'] = hashed['hash']
		with open(f"{data['id']}.json", 'w+') as file:
			file.write(json.dumps(data))
		return "Done"

#Hashing password and comparing it with entry in <id>.json
def check_creds(data):
	if os.path.isfile(f"{data['id']}.json"):

		with open(f"{data['id']}.json", 'r+') as file:
			stored = json.loads(file.read())

		passw = data['pass']
		salt = stored['salt']
		data['pass'] = rehash_pass(passw, salt)['hash']

		if data['pass'] == stored['pass']:
			return "Authenticated"
		else:
			return "Access Denied"

	else:
		return "id does not exist"

#If creds match it finds and sends key as response
def send_key(data):
	check = check_creds(data)
	if check == "Authenticated":

		if os.path.isfile(f"{data['id']}-{data['sha256']}.json"):

			with open(f"{data['id']}-{data['sha256']}.json", "r") as file:
				response = json.loads(file.read())

			if data['pass'] == response['pass']:
				os.remove(f"{data['id']}-{data['sha256']}.json")
				return response['key']

			else:
				return "wrong request"
		else:
			return "Key not found"

	else:
		return check

#Writing recieved key to <id>.json
def save_key(data):
	check = check_creds(data)
	if check == "Authenticated":
		jsn = json.dumps(data)
		with open(f"{data['id']}-{data['sha256']}.json", "w+") as file:
			file.write(jsn)
	else:
		return check


	return "Done"

#Decrypts request, calls rsa_decrypt and decrypts the rest of combinied encryption, returns dict
def decrypt(data):
	d = json.loads(b)

	keye = bytes.fromhex(d['ferkey'])
	key = rsa_decrypt(keye, "private.key")

	fer = Fernet(key)
	data = fer.decrypt(bytes.fromhex(d['data']))
	data = data.decode('utf-8')
	dict_data = json.loads(data)
	return dict_data


if __name__ == '__main__':
	#Listens on PORT
	while True:
		try:
			b = b''
			conn, addr = s.accept()
			tmp = conn.recv(4096)
			b += tmp
			#Sends back the return of procces_data, wich returnes response of the called function
			conn.sendall(proccess_data(decrypt(b)).encode('utf-8'))
			
		except Exception as e:
			conn.sendall(f"Error: {e}".encode('utf-8'))