import time
import math
from base64 import b64decode, b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers, RSAPublicKey, RSAPrivateNumbers, RSAPrivateKey

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
        
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
   
def getSecretKey(key, password):
    digestAlg_obj = hashes.SHA1()
    digest_obj = hashes.Hash(digestAlg_obj, backend = default_backend())
    digest_obj.update(password.encode())
    digest_bytv = digest_obj.finalize()
    cipher = Cipher(algorithms.TripleDES(digest_bytv+b'\x00'+b'\x00'+b'\x00'+b'\x00'), mode=modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = decryptor.update(b64decode(key)) + decryptor.finalize()
    return ct 
    
def privKeyToRSA(key):
    #get available RSA components from private key
    eLength = 3
    pLength = 65
    qLength = 65
    components = [None,None,None,None,None,None,None,None]
    if (len(key) > eLength + pLength + qLength):
        abyte2 = key[0:4]
        privExponentLength = ((abyte2[0]&0xFF)<<24)|((abyte2[1]&0xFF)<<16)|((abyte2[2]&0xFF)<<8)|((abyte2[3]&0xFF)<<0)
        components[1] = key[4:4 + privExponentLength]
        components[2] = key[4 + privExponentLength:4 + privExponentLength + eLength]
        components[3] = key[4 + privExponentLength + eLength:4 + privExponentLength + eLength + pLength]
        components[4] = key[4 + privExponentLength + eLength + pLength:4 + privExponentLength + eLength + pLength + qLength]
    else:
        components[2] = key[0:eLength]
        components[3] = key[eLength:eLength + pLength]
        components[4] = key[eLength + pLength:eLength + pLength + qLength]

	#compute missing RSA components
    bigints = [None,None,None,None,None,None,None,None]
    for x,component in enumerate(components, start=0):
        if component is not None:
            bigints[x] = ((int.from_bytes(component,byteorder='big')))

    if (bigints[3]<bigints[4]):
        bigint = bigints[3]
        bigints[3] = bigints[4]
        bigints[4] = bigint
        bigint = bigints[5]
        bigints[5] = bigints[6]
        bigints[6] = bigint
        bigints[7] = None
    
    if (bigints[7] is None):
        bigints[7] = modinv(bigints[4],(bigints[3]))
    if (bigints[0] is None):
        bigints[0] = bigints[3]*bigints[4]
    if (bigints[1] is None):
        bigints[1] = modinv(bigints[2],((bigints[3]-1)*(bigints[4]-1)))
    if (bigints[5] is None):
        bigints[5] = bigints[1]%(bigints[3]-1)
    if (bigints[6] is None):
        bigints[6] = bigints[1]%(bigints[4]-1)

    #construct the RSA object
    #n:		modulus		    bigints[0]
    #d:		private exponent    bigints[1]
    #e:		public exponent	    bigints[2]	
    #p:		prime1 		    bigints[3]
    #q:		prime2		    bigints[4]
    #dmp1: 	exponent1	    bigints[5]
    #dmq1: 	exponent2	    bigints[6]
    #coeff:	coefficient	    bigints[7]
    rsa=RSAPrivateNumbers(bigints[3],bigints[4], bigints[1], bigints[5], bigints[6], bigints[7], RSAPublicNumbers(bigints[2],bigints[0])).private_key(backend = default_backend())
    return rsa

def pubKeyToRSA (key):
	#get available RSA components from public key
    buff = b64decode(key)
    mod = (int.from_bytes(buff[0:129],byteorder='big'))
    exp = (int.from_bytes(buff[129:132],byteorder='big'))
    
    #construct the RSA object
    rsa=RSAPublicNumbers(exp,mod).public_key(backend = default_backend())
    return rsa;
    
def signLtpaToken2 (data, rsa):
    digestAlg_obj = hashes.SHA1()
    digest_obj = hashes.Hash(digestAlg_obj, backend = default_backend())
    digest_obj.update(data.encode())
    digest_bytv = digest_obj.finalize()
    signature = rsa.sign(digest_bytv, padding.PKCS1v15(), hashes.SHA1())
    return (b64encode(signature)).decode("utf-8")

def encryptLtpaToken2 (data,key):
    #calculate padding
    pad_len = 16 - (len(data) % 16)
    padding = (chr(pad_len) * pad_len)
    data = data + padding
    
    #encryption
    cipher = Cipher(algorithms.AES(key[0:16]), modes.CBC(key[0:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data.encode()) + encryptor.finalize()
    return ((b64encode(ct).decode("utf-8")))

def decryptLtpaToken2 (data,key):
    #decryption
    cipher = Cipher(algorithms.AES(key[0:16]), modes.CBC(key[0:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = decryptor.update(b64decode(data)) + decryptor.finalize()
    return ((ct.decode("utf-8")))

def verifyLtpaToken2 (data, rsa):
    body = data[0]
    expire = data[1]
    signature = data[2]
    digestAlg_obj = hashes.SHA1()
    digest_obj = hashes.Hash(digestAlg_obj, backend = default_backend())
    digest_obj.update(body.encode())
    digest_bytv = digest_obj.finalize()
    verification=rsa.verify(b64decode(signature), digest_bytv, padding.PKCS1v15(), hashes.SHA1())
    expiration=int(str(math.trunc(time.time()))+"000") < int(expire)
    if ((verification is None)&expiration):
        return True
    return False
    

_3DESKey = "QeVYdNvQbz7jyqbFu3wmeuyws96KwmvBEu3o6+o138E\="
_PrivateKey= "uHUSg2YvtKovgtQLX+SmtH4BPnyBy7cLnNsI+0QaC+KcMVKNuBYjYknyP0n+CCJgkDebdjz5vHqhqlg3abv/P19dzjvJCCHXzIDapYOPBBYcmWZGpMB19b6bsykwjdNbf+xjijRQvOXetf5///ljiHeq/NP58qpS9KXfyXcjXGdEAwFSKAFTG1bj9Cpy6iqWQ9SPFD3kiEhzNu16lSmR4BNtZTpZ0uy8hfYB1u9HB3/sJ0ih2iw7qR8fnhVuKbpIyAtio5sPOHfgayI01vDhEdHNPcZaTxx5Ndf1MXq05Bv2ZEX3JRMtVsLfOvNBnz5PdmPj74CH8Qy7oa4ZX2bDEWF9pBkS7B9rPKDe291/d7M\="
_PublicKey = "ALTw+Sy9dQSv8lQ6JPX/zhqwLtua6yo9mmrC55NAxu7SLXx2Ee+A8OBMTH4+4OIk0pnNAqfR8AKARY4D3fqEJB5z+V/6Zh9Gap3tGT7wmTf0mrtF9EqgLCiVqfBq+0LM+ZfvT6YC6PG1CFVM1kkuuvn2Sc2T+tuiTQSX+zWauR45AQAB"
password="lotus123"

#decrypt encrypted 3DES key
TrippleDESKey=getSecretKey(_3DESKey,password)

#decrypt encrypted private key
PrivateKey = getSecretKey(_PrivateKey,password)

#get RSA object from private key
rsa1=privKeyToRSA(PrivateKey)

#calculate the epoch expiration, set at 2hours
expire=str(math.trunc(time.time())+7200)+"000"
#expire="1596469487000"

#add expire to the body and add some fields like user DN etc
body="expire:"+expire+"$u:user\:defaultWIMFileBasedRealm/CN=Pieter Geerts,O=beibm"

#calculate signature for LtpaToken2 as BASE64(SHA1_WITH_RSA(SHA_DIGEST(body)))
signature = signLtpaToken2(body,rsa1)

#raw token as body%expiration%signature
rawToken = "%".join([body,expire,signature])

#encrypt the raw token and return as base64 string
encToken=encryptLtpaToken2(rawToken,TrippleDESKey)
print (encToken)

#decrypt the LtpaToken2
rawToken2=decryptLtpaToken2(encToken,TrippleDESKey)

#get RSA object from unencrypted public key
rsa2 = pubKeyToRSA(_PublicKey);

#verify the LtpaToken and return the raw token
if (verifyLtpaToken2(rawToken2.split('%'),rsa2)):
    print (rawToken2)
