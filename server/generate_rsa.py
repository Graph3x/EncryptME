from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

def generate_rsa_keys():
	key = RSA.generate(2048)
	private_key = key.export_key('PEM')
	public_key = key.publickey().exportKey('PEM')
	keys = {'priv':private_key, 'pub':public_key}
	keys['pub'] = keys['pub'].decode('utf-8')
	keys['priv'] = keys['priv'].decode('utf-8')

	with open("private.key", 'w+') as f:
		f.write(keys['priv'])
	with open("public.key.pub", 'w+') as f:
		f.write(keys['pub'])

	return {'priv':private_key, 'pub':public_key}


def rsa_encrypt(key, data):
	data = str.encode(data, 'utf-8')

	with open(key, 'r') as f:
		pub_key = f.read()

	rsa_pub_key = RSA.importKey(pub_key)
	rsa_pub_key = PKCS1_OAEP.new(rsa_pub_key)
	encrypted_data = rsa_pub_key.encrypt(data)
	return encrypted_data


def rsa_decrypt(key, encrypted_data):
	with open(key, 'r') as f:
		priv_key = f.read()

	rsa_priv_key = RSA.importKey(priv_key)
	rsa_priv_key = PKCS1_OAEP.new(rsa_priv_key)
	data = rsa_priv_key.decrypt(encrypted_data)
	return data.decode('utf-8')


enc = rsa_encrypt("public.key.pub","doud")
print(enc)

print(rsa_decrypt("private.key", enc))
