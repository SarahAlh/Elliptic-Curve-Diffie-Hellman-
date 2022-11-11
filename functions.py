import  binascii, rsa, hashlib
from Crypto.Cipher import AES
from params import readParams
from cryptography.hazmat.primitives.asymmetric import rsa as newrsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import exceptions
from Crypto.Util.number import *


  
def encrypt(plaintext,key, mode, iv):
  modeType = AES.new(key, AES.MODE_GCM)
  ciphertext,auth=modeType.encrypt_and_digest(plaintext)
  return(ciphertext,auth,modeType.nonce)
  
def decrypt(ciphertext,key, mode, iv):
  (ciphertext,  auth, nonce) = ciphertext
  modeType = AES.new(key,  mode, nonce)
  return(modeType.decrypt_and_verify(ciphertext, auth))
  
def readFile(file):
    f = open(file, 'r')
    lngstr = f.read()
    f.close()
    return lngstr

def PrivKey(file):
    stg = readFile(file)
    key = rsa.PrivateKey.load_pkcs1(stg)
    return key

def PubKey(file):
    stg = readFile(file)
    key = rsa.PublicKey.load_pkcs1(stg.encode('ascii'))
    return key

def sharedSecret(aPriv, receiverPub):
    return [aPriv * receiverPub[0], aPriv * receiverPub[1]]
def signInt(intg, key):
    return pow(intg, key.d, key.n)

def check(bytez, key):
    return pow(bytez, key.e, key.n)
  
def verify(bytez, key, pt_as_int):
    ver = check(bytez, key)
    return ver == pt_as_int
  
def signAndVerify(signer, sPriv, senderPub):
  signed = signInt(signer, sPriv)
  ver = verify(signed , senderPub, signer)
  return ver

def getKeyValsEcdh(key):
    return key.get('priv'), [key.get('priv')  * key.get('Gener')[0],key.get('priv')  * key.get('Gener')[1]] 
  
'''
# Generat Keys By Using Libraray: 
#from secp256k1 import curve,scalar_mult
SenderSecretKey  = random.randrange(1, curve.n)
SenderPublicKey = scalar_mult(SenderSecretKey, curve.g)
ReceiverSecretKey = random.randrange(1, curve.n)
ReceiverPublicKey = scalar_mult(ReceiverSecretKey, curve.g)
SenderSharedKey = scalar_mult(SenderSecretKey, ReceiverPublicKey)
ReceiverSharedKey = scalar_mult(ReceiverSecretKey, SenderPublicKey)
print ("The Shared Key: ", sShared [0])
'''