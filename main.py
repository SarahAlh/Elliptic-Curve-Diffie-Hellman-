#pip3 install -U PyCryptodome
#pip install rsa
from functions import *
import os

#By Using: ssh-keygen -t rsa && ssh-keygen -p -N "" -m pem -f /Users/sarahalharbi/sender 
#By Using: ssh-keygen -f senderRSA.pub -e -m pem > senderRSA_PUB
senderRSA = PrivKey('senderRSA')
receiverRSA = PrivKey('ReceiverRSA')
senderRSA_pub = PubKey('senderRSA_PUB')
receiverRSA_pub = PubKey('ReceiverRSA_PUB')

print("\nApplying ECDHE in Progress ... \n")
# By Using: openssl ecparam -genkey -name secp160r1 -noout -param_enc explicit -out sender_private.pem && openssl ec -in sender_private.pem -pubout -out sender_public.pem && openssl ec -in sender_private.pem -noout -text > SenderPrivateParmaters
  
senderKey = readParams('SenderPrivateParmaters')
SenderSecretKey = senderKey.get('priv')
SenderPublicKey = [senderKey.get('priv')  * senderKey.get('Gener')[0],senderKey.get('priv')  * senderKey.get('Gener')[1]] 
print ("Sender Private Key: ", SenderSecretKey)
print("Sender Public Key: ", SenderPublicKey)


receiverKey = readParams('ReceiverPrivateParmaters')
ReceiverSecretKey = receiverKey.get('priv')
ReceiverPublicKey = [receiverKey.get('priv')  * receiverKey.get('Gener')[0],receiverKey.get('priv')  * receiverKey.get('Gener')[1]] 
print ("\nReceiver Private Key: ", ReceiverSecretKey)
print("Receiver Public Key: ", ReceiverPublicKey)

sShared = sharedSecret(SenderSecretKey, ReceiverPublicKey)
rShared = sharedSecret(ReceiverSecretKey, SenderPublicKey)
print ("\nThe Shared Key: ", sShared)

print("\nApplying AES-GCM Mode in Progress .... \n")
plaintext= readFile('text.txt')
password= str(sShared[0])
key = hashlib.sha256(password.encode()).digest()
ivBefore = str(sShared[1])
iv = hashlib.sha256(ivBefore.encode()).digest()
print("Message: ",plaintext)
print("Key: ",password)

ciphertext = encrypt(plaintext.encode(),key,AES.MODE_GCM, iv)
print("Ciphertext: ",binascii.hexlify(ciphertext[0]))
print("Message authentication:\t",binascii.hexlify(ciphertext[1]))
print("Nonce:\t\t",binascii.hexlify(ciphertext[2]))

password=str(sShared[0])
key = hashlib.sha256(password.encode()).digest()

key2 = hashlib.sha256(password.encode()).digest()
plaintextGCM= decrypt(ciphertext,key2,AES.MODE_GCM, iv)
print ("Plaintext:\t",plaintextGCM.decode())

print("\nApplying RSA Digital Signature in Progress ... \n")
d = senderRSA.d
n = senderRSA_pub.n 
e = senderRSA_pub.e #65537
m = int(str(ciphertext).encode().hex(),16)
C = pow(m,d,n)

print ('RSA Digital Signature: ', C)
print ('Verification Signature of RSA number: it is ', pow(C,e,n) == m," , and it is equal to: ", pow(C,e,n))


'''
print("\nApplying RSA Digital Signature in Progress ..... \n")
message = plaintextGCM
print("Message: ", message)

private_key = newrsa.generate_private_key(public_exponent=65537,key_size=512)
pub = private_key.public_key()
signature = private_key.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
print ("Signature in base64:",binascii.b2a_base64(signature).decode())

try: rtn=pub.verify(signature,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

except exceptions.InvalidSignature:
    print("Signature failed")
else:
    print("Signature verified")

plaintext= readFile('text.txt')
password=str(rShared[0])
key = hashlib.sha256(password.encode()).digest()
print("Message: ",plaintext)
print("Key: ",password)

ciphertext = encrypt(plaintext.encode(),key,AES.MODE_GCM)
print("Ciphertext: ",binascii.hexlify(ciphertext[0]))
print("Message authentication:\t",binascii.hexlify(ciphertext[1]))
print("Nonce:\t\t",binascii.hexlify(ciphertext[2]))

password=str(rShared[0])
key2 = hashlib.sha256(password.encode()).digest()
plaintextGCM= decrypt(ciphertext,key2,AES.MODE_GCM)
print ("Plaintext:\t",plaintextGCM.decode())

print("\nApplying RSA in Progress ........ \n")
message = int.from_bytes(plaintextGCM, "big")
#From the Class "andyrulz"
p=getStrongPrime(512)
q=getStrongPrime(512)
N = p*q
encryptionRSA = pow(message, 65537, N)
phi_of_N = (p-1)*(q-1)
encryptText= inverse(65537, phi_of_N)
print("Cipher: ",encryptText)
decryptText= long_to_bytes(pow(encryptionRSA, encryptText, N))
print("Plaintext: ", decryptText)

'''