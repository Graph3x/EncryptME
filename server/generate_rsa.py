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
