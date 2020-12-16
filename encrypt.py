import os
import sys
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Cipher import AES, PKCS1_OAEP
import random, string
import base64

BLOCK_SIZE = 32
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

#import public key
externKey = "key.pub"
publickey = open(externKey, "rb").read()
pubKey = RSA.importKey(publickey)
cipher_rsa = PKCS1_OAEP.new(pubKey)

#generate secret key and encrypt it
session_key = os.urandom(BLOCK_SIZE)
enc_session_key = cipher_rsa.encrypt(session_key)
cipheraes = AES.new(session_key)
content = open (<'file'>, encoding = "ISO-8859-1").read()
encoded = EncodedAES(cipher_aes, content)
f = open ('<file>', "wb")
f.write(encoded)
f.close()
