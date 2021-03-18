from cryptography.fernet import Fernet
import os

class Key:
	def __init__(self):
		self.value = ""
		self.file = ""


	def setpath(self, path):
		self.file = path


	def write(self):
		with open(self.file, "wb") as file:
			file.write(self.value)


	def load(self):
		with open(self.file, "rb") as file:
			self.value = file.read()


	def generate(self):
		self.value = Fernet.generate_key()


	def delete(self):
		self.value = ""
		os.remove(self.file)


class File:
	def __init__(self):
		self.name = ""
		self.data = ""
		self.udata = ""
		self.keyval = ""


	def setpath(self, path):
		self.name = str(path)


	def load(self):
		with open(self.name, "rb") as d:
			self.data = d.read()


	def write(self):
		with open(self.name, "wb") as d:
			d.write(self.udata)


	def setkey(self, keyvalue):
		self.keyval = keyvalue


	def encrypt(self):
		self.load()
		fer = Fernet(self.keyval)
		self.udata = fer.encrypt(self.data)
		self.write()


	def decrypt(self):
		self.load()
		fer = Fernet(self.keyval)
		self.udata = fer.decrypt(self.data)
		self.write()