import time
import math
import sys
from base64 import b64decode, b64encode
from Crypto.Cipher import DES3, AES
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def load_key_file(key_file_path):
    """Load properties from LTPA key file"""
    props = {}
    try:
        with open(key_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line.startswith('#') or not line or '=' not in line:
                    continue
                # Split on first '=' only
                key, value = line.split('=', 1)
                props[key] = value
    except FileNotFoundError:
        print(f"Error: Key file '{key_file_path}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading key file: {e}")
        sys.exit(1)
    return props

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
    # Create SHA1 hash of password
    hash_obj = SHA1.new(password.encode())
    digest_bytv = hash_obj.digest()
    
    # Pad to 24 bytes for 3DES
    des3_key = digest_bytv + b'\x00' * 4
    
    # Decrypt using 3DES ECB mode
    cipher = DES3.new(des3_key, DES3.MODE_ECB)
    ct = cipher.decrypt(b64decode(key))
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

    # Ensure p > q for PyCryptodome
    if (bigints[3]<bigints[4]):
        bigint = bigints[3]
        bigints[3] = bigints[4]
        bigints[4] = bigint
        bigint = bigints[5]
        bigints[5] = bigints[6]
        bigints[6] = bigint
        bigints[7] = None
    
    if (bigints[0] is None):
        bigints[0] = bigints[3]*bigints[4]
    if (bigints[1] is None):
        bigints[1] = modinv(bigints[2],((bigints[3]-1)*(bigints[4]-1)))
    if (bigints[5] is None):
        bigints[5] = bigints[1]%(bigints[3]-1)
    if (bigints[6] is None):
        bigints[6] = bigints[1]%(bigints[4]-1)
    
    # Construct the RSA object using PyCryptodome
    # n: modulus, e: public exponent, d: private exponent, p: prime1, q: prime2
    # Convert to int to ensure they're proper integers
    n = int(bigints[0])
    e = int(bigints[2])
    d = int(bigints[1])
    p = int(bigints[3])
    q = int(bigints[4])
    
    # PyCryptodome can calculate u automatically if we provide (n, e, d, p, q)
    rsa = RSA.construct((n, e, d, p, q))
    return rsa

def pubKeyToRSA(key):
    #get available RSA components from public key
    buff = b64decode(key)
    mod = (int.from_bytes(buff[0:129],byteorder='big'))
    exp = (int.from_bytes(buff[129:132],byteorder='big'))
    
    #construct the RSA object using PyCryptodome
    rsa = RSA.construct((mod, exp))
    return rsa
    
def signLtpaToken2(data, rsa):
    # Create SHA1 hash of data
    hash_obj = SHA1.new(data.encode())
    digest_bytv = hash_obj.digest()
    
    # Sign the hash using PKCS#1 v1.5
    signature = pkcs1_15.new(rsa).sign(hash_obj)
    return b64encode(signature).decode("utf-8")

def encryptLtpaToken2(data, key):
    # AES encryption with CBC mode
    # Use first 16 bytes of key for both key and IV
    cipher = AES.new(key[0:16], AES.MODE_CBC, key[0:16])
    
    # Calculate padding (PKCS7)
    pad_len = 16 - (len(data) % 16)
    padding = chr(pad_len) * pad_len
    data = data + padding
    
    # Encrypt
    ct = cipher.encrypt(data.encode())
    return b64encode(ct).decode("utf-8")

def decryptLtpaToken2(data, key):
    # AES decryption with CBC mode
    cipher = AES.new(key[0:16], AES.MODE_CBC, key[0:16])
    
    # Decrypt
    ct = cipher.decrypt(b64decode(data))
    
    # Remove PKCS7 padding
    pad_len = ct[-1]
    return ct[:-pad_len].decode("utf-8")

def verifyLtpaToken2(data, rsa):
    body = data[0]
    expire = data[1]
    signature = data[2]
    
    # Create SHA1 hash of body
    hash_obj = SHA1.new(body.encode())
    
    # Verify signature
    try:
        pkcs1_15.new(rsa).verify(hash_obj, b64decode(signature))
        verification = True
    except (ValueError, TypeError):
        verification = False
    
    # Check expiration
    expiration = int(str(math.trunc(time.time())) + "000") < int(expire)
    
    return verification and expiration
    

if __name__ == "__main__":
    # Allow command line argument to specify key file
    key_file_path = sys.argv[1]
    password = sys.argv[2]

    # Load the key file
    key_props = load_key_file(key_file_path)

    # Extract keys from properties file
    _3DESKey = key_props.get("com.ibm.websphere.ltpa.3DESKey")
    _PrivateKey = key_props.get("com.ibm.websphere.ltpa.PrivateKey")
    _PublicKey = key_props.get("com.ibm.websphere.ltpa.PublicKey")
    realm = key_props.get("com.ibm.websphere.ltpa.Realm")

    # Validate that required properties are present
    if not _3DESKey or not _PrivateKey or not _PublicKey:
        print("Error: Key file is missing required properties")
        print("Required: com.ibm.websphere.ltpa.3DESKey, com.ibm.websphere.ltpa.PrivateKey, com.ibm.websphere.ltpa.PublicKey")
        sys.exit(1)

    print(f"Using key file: {key_file_path}")
    if realm:
        print(f"Realm: {realm}")

    #decrypt encrypted 3DES key
    TrippleDESKey=getSecretKey(_3DESKey,password)

    #decrypt encrypted private key
    PrivateKey = getSecretKey(_PrivateKey,password)

    #get RSA object from private key
    rsa1=privKeyToRSA(PrivateKey)

    #calculate the epoch expiration, set at 2hours
    expire=str(math.trunc(time.time())+7200)+"000"

    #add expire to the body and add some fields like user DN etc
    body="expire:"+expire+r"$u:user\:defaultWIMFileBasedRealm/CN=Pieter Geerts,O=beibm"

    #calculate signature for LtpaToken2 as BASE64(SHA1_WITH_RSA(SHA_DIGEST(body)))
    signature = signLtpaToken2(body,rsa1)

    #raw token as body%expiration%signature
    rawToken = "%".join([body,expire,signature])

    #encrypt the raw token and return as base64 string
    encToken=encryptLtpaToken2(rawToken,TrippleDESKey)
    print(f"Token: {encToken}")

    #decrypt the LtpaToken2
    rawToken2=decryptLtpaToken2(encToken,TrippleDESKey)

    #get RSA object from unencrypted public key
    rsa2 = pubKeyToRSA(_PublicKey)

    #verify the LtpaToken and return the raw token
    if (verifyLtpaToken2(rawToken2.split('%'),rsa2)):
        print(f"RawToken: {rawToken2}")