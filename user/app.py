from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QPalette
from tkinter import *
import tkinter.messagebox
import easygui

from crypt import * 
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib

import socket
import json
import sys

#Declaring global variables
filename = ""
identity = ""
password = ""
w = ""
pswd = ""
iden = ""

#PKCS1 RSA encryption, it only encrypts the symetric key because of byte limitation of this algorithm
def rsa_encrypt(data, key):
	with open(key, 'r') as f:
		pub_key = f.read()

	rsa_pub_key = RSA.importKey(pub_key)
	rsa_pub_key = PKCS1_OAEP.new(rsa_pub_key)
	encrypted_data = rsa_pub_key.encrypt(data)
	return encrypted_data

#Returns SHA256 of a file (same as shasum command on linux) - used only to identify files
def shasum(file):
	BUF_SIZE = 65536
	sha256 = hashlib.sha256()

	with open(file, 'rb') as f:
		while True:
			data = f.read(BUF_SIZE)
			if not data:
				break
			sha256.update(data)
	return sha256.hexdigest()

#Uses easy gui to open file explorer, pyqt was crashing for some reason
def pick_file():
	global filename
	filename = easygui.fileopenbox()

#Opens the gui of the main application
def open_main():
	#Declare app and set colors
	app = QApplication([])
	app.setStyle("Fusion")
	qp = QPalette()
	qp.setColor(QPalette.ButtonText, Qt.black)
	qp.setColor(QPalette.Window, Qt.gray)
	qp.setColor(QPalette.Button, Qt.white)
	#More declerations and colors
	app.setPalette(qp)
	ww = QWidget()
	vb = QFormLayout(ww)
	ww.setWindowTitle("EncryptME")
	ww.resize(300,150)
	#Declare buttons
	butn1 = QPushButton("ENCRYPT")
	butn2 = QPushButton("PICK A FILE")
	butn3 = QPushButton("DECRYPT")
	#Connect button to functions
	butn1.clicked.connect(encrypt)
	butn2.clicked.connect(pick_file) 
	butn3.clicked.connect(decrypt)
	#Open window and render all buttons
	vb.addWidget(butn1)
	vb.addWidget(butn2)
	vb.addWidget(butn3)
	ww.show()
	app.exec_()

#File encryption using Fernet and crypt.py
def encrypt():
	#Check if creds have been suplied
	if identity == "":
		raise_error("No creds loaded")
	#Check if file has been picked
	else:
		if filename == "":
				raise_error("Pick a file!")
		else:
			#Generate and safe key (write it to file so if something fails we have it)
			k = Key()
			k.generate()
			k.setpath("key.key")
			k.write()
			#Set file and encrypt it
			f = File()
			f.setpath(filename)
			f.setkey(k.value)
			f.encrypt()
			#Send key to the server and delete it, the open popup
			ret = send_key(filename, k.value, identity, password)
			k.delete()
			raise_info("Enecryption successful")

			return ret

#Decrypts Fernet encrypted file with key from server, using crypt.py
def decrypt():
	if identity == "":
		raise_error("No creds loaded")
	else:
		if filename == "":
			raise_error("Pick a file!")
		else:
			k = req_key(filename, identity, password)
			#Lazy way to check if response is a valid key
			if len(k) > 20:
				f = File()
				f.setpath(filename)
				k = bytes(k, 'utf-8')
				f.setkey(k)
				f.decrypt()
				raise_info("Decryption successful")
			else:
				raise_error("No key found or other error!")

#Encrypts data with combined algortihm (RSA + Fernet) and sends it to the server
def send_data(data):
	#Open and set socket
	HOST, PORT = "127.0.0.1", 9876
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	#Trun dict to bytes
	d = json.dumps(data).encode('utf-8')
	#Encrypt data with Fernet
	senders_key = Key()
	senders_key.generate()
	fer = Fernet(senders_key.value)
	ed = fer.encrypt(d)
	#Encrypt the Fernet key and add it to dict with the rest of encrypted data
	enc_key = rsa_encrypt(senders_key.value, "public.key.pub")
	message = {'data':ed.hex(), 'ferkey':enc_key.hex()}
	#Turn dict into string and connect to server
	messjs = json.dumps(message)
	sock.connect((HOST, PORT))
	#Turn string to bytes and send it to the server
	sock.sendall(messjs.encode('utf-8'))
	#wait for response and return it
	response = sock.recv(4096).decode("utf-8")
	
	return response

#Send all data needed to save a key to server
def send_key(filename, key, iden, passwd):
	data = {'name':filename, 'sha256':shasum(filename), 'key':str(key, 'utf-8'), 'id':iden, 'pass':passwd}

	return send_data(data)

#Send all data needed to request a key to server
def req_key(filename, iden, passwd):
	data = {'name':filename, 'sha256':shasum(filename), 'id':iden, 'pass':passwd}

	return send_data(data)

#Calling functions around registering
def auto_register():
	if check_pass():
		response = register(identity, password)
		if response == "Done":
			w.close()
		else:
			raise_error("Id already taken")

#Send all data needed to register a account to server
def register(iden, passwd):
	data = {'id':iden, 'pass':passwd}
	return send_data(data)

#Send all data needed to login into a account to server
def login(iden, passwd):
	data = {'id':iden, 'pass':passwd, 'login':'True'}
	return send_data(data)

#Calling functions around login
def auto_login():
	if check_pass():
		response = login(identity, password)
		if response == "Authenticated":
			w.close()
		else:
			raise_error("Authentication failure")

#Check if password is 8 characters long
def check_pass():
	global password
	global identity
	password = str(pswd.text())
	identity = str(iden.text())
	if len(password) > 7:
		return True
	else:
		raise_error("Password has to be at least 8 characters")
		return False

#Opens up login gui with pyqt - works the same as main gui
def build_login():
	global pswd
	global iden
	global w

	app = QApplication([])
	app.setStyle("Fusion")
	qp = QPalette()
	qp.setColor(QPalette.ButtonText, Qt.black)
	qp.setColor(QPalette.Window, Qt.gray)
	qp.setColor(QPalette.Button, Qt.white)

	app.setPalette(qp)
	w = QWidget()
	vb = QFormLayout(w)
	w.setWindowTitle("EncryptME Login")
	w.resize(300,150)

	btn1 = QPushButton("login")
	btn2 = QPushButton("register")

	iden = QLineEdit()
	iden.setStyleSheet("color: black;")
	vb.addRow("name",iden)

	pswd = QLineEdit()
	pswd.setStyleSheet("color: black;")
	pswd.setEchoMode(QLineEdit.Password)
	vb.addRow("Password (min. 8)",pswd)


	btn1.clicked.connect(auto_login)
	btn2.clicked.connect(auto_register)

	vb.addWidget(btn1)
	vb.addWidget(btn2)
	w.show()
	app.exec_()

#Opens popup styled as error message
def raise_error(e):
	root = Tk()
	root.withdraw()
	tkinter.messagebox.showerror("Error", e)
	root.destroy()
	root.mainloop()

#Opens popup styled as information message
def raise_info(i):
	root = Tk()
	root.withdraw()
	tkinter.messagebox.showinfo("ECM", i)
	root.destroy()
	root.mainloop()	


if __name__ == '__main__':
	build_login()

	open_main()