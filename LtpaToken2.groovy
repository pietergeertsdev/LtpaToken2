def getSecretKey (String key,String password) {
	def md = java.security.MessageDigest.getInstance("SHA")
	md.update(password.getBytes())
	def hash3DES = new byte[24]
	System.arraycopy(md.digest(), 0, hash3DES, 0, 20)
	Arrays.fill(hash3DES, 20, 24, (byte) 0)
	def cipher = javax.crypto.Cipher.getInstance("DESede/ECB/PKCS5Padding")
	cipher.init(javax.crypto.Cipher.DECRYPT_MODE, javax.crypto.SecretKeyFactory.getInstance("DESede").generateSecret(new javax.crypto.spec.DESedeKeySpec(hash3DES)))
	return cipher.doFinal((key.replace('\\=','').decodeBase64()))
}

def privKeyToRSA (key) {
	//get available RSA components from private key
	def eLength = 3
	def pLength = 65
	def qLength = 65
	def components = new byte[8][]
	
	components[2] = new byte[eLength]
	components[3] = new byte[pLength]
	components[4] = new byte[qLength]
	
	if (key.length > eLength + pLength + qLength) {
		def abyte2 = key[0..3]
		def privExponentLength = ((abyte2[0]&0xFF)<<24)|((abyte2[1]&0xFF)<< 16)|((abyte2[2]&0xFF)<< 8)|((abyte2[3]&0xFF)<<0)
		components[1] = new byte[privExponentLength]
		System.arraycopy(key, 4, components[1], 0, privExponentLength)
		System.arraycopy(key, privExponentLength + 4 , components[2] , 0 , eLength)
		System.arraycopy(key, privExponentLength + 4 + eLength, components[3] , 0 , pLength)
		System.arraycopy(key, privExponentLength + 4 + eLength + pLength, components[4] , 0 , qLength)
	} 
	else {
		System.arraycopy(key, 0, components[2], 0, eLength)
		System.arraycopy(key, eLength, components[3], 0, pLength)
		System.arraycopy(key, eLength + pLength, components[4], 0, qLength)
	}

	//compute missing RSA components
	def bigints = new BigInteger[8]
	for (int i = 0; i <= 7; i++)
		if (components[i] != null)
			bigints[i] = new BigInteger(1, components[i])
	if (bigints[3].compareTo(bigints[4]) < 0) {
		def bigint = bigints[3]
		bigints[3] = bigints[4]
		bigints[4] = bigint
		bigint = bigints[5]
		bigints[5] = bigints[6]
		bigints[6] = bigint
		bigints[7] = null
	}
	if (bigints[7] == null)
		bigints[7] = bigints[4].modInverse(bigints[3])
	if (bigints[0] == null)
		bigints[0] = bigints[3].multiply(bigints[4])
	if (bigints[1] == null)
		bigints[1] = bigints[2].modInverse(bigints[3].subtract(BigInteger.ONE).multiply(bigints[4].subtract(BigInteger.ONE)))
	if (bigints[5] == null)
		bigints[5] = bigints[1].remainder(bigints[3].subtract(BigInteger.ONE))
	if (bigints[6] == null)
		bigints[6] = bigints[1].remainder(bigints[4].subtract(BigInteger.ONE))
		
	//construct the RSA object
	//n:		modulus				bigints[0]
	//d:		private exponent	bigints[1]
	//e:		public exponent		bigints[2]	
	//p:		prime1 				bigints[3]
	//q:		prime2				bigints[4]
	//dmp1: 	exponent1			bigints[5]
	//dmq1: 	exponent2			bigints[6]
	//coeff:	coefficient			bigints[7]
	return new java.security.spec.RSAPrivateCrtKeySpec(bigints[0], bigints[2], bigints[1], bigints[3], bigints[4], bigints[5], bigints[6], bigints[7])
}

def pubKeyToRSA (key) {
	byte[] parts = key.replace('\\=','').decodeBase64()
	
	//get available RSA components from public key
	def modulus = new BigInteger(Arrays.copyOfRange(parts, 0, 129))
	def exponent = new BigInteger(Arrays.copyOfRange(parts, 129, 129 + 3))
	
	//construct the RSA object
	//RSAPublicKeySpec(BigInteger modulus, BigInteger publicExponent)
	def pubKeySpec = new java.security.spec.RSAPublicKeySpec(modulus, exponent)
	return pubKeySpec
}

def signLtpaToken2 (data,rsa) {
	def md1JCE = java.security.MessageDigest.getInstance("SHA")
	def plainUserDataBytes = md1JCE.digest(data.getBytes())
	def encodedSignatureBytes = null
	def privatekey = java.security.KeyFactory.getInstance("RSA").generatePrivate(rsa)
	def signer = java.security.Signature.getInstance("SHA1withRSA")
	signer.initSign(privatekey)
	signer.update(plainUserDataBytes, 0, plainUserDataBytes.length)
	encodedSignatureBytes = signer.sign()
	return encodedSignatureBytes.encodeBase64().toString().replaceAll("[\r\n]","")
}

def encryptLtpaToken2 (data,key) {
	def cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
	cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, 0, 16, "AES"), new javax.crypto.spec.IvParameterSpec(key,0,16))
	return (cipher.doFinal(data.getBytes("UTF8"))).encodeBase64().toString().replaceAll( "[\r\n]","")
}

def decryptLtpaToken2 (data,key) {
	def cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
	cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, 0, 16, "AES"), new javax.crypto.spec.IvParameterSpec(key,0,16))
	return new String(cipher.doFinal(data.replace('\\=','').decodeBase64()))
}

def verifyLtpaToken2 (data, rsa) {
	def body = data[0]
	def expire = data[1]
	def signature = data[2]
	def retValue=false
	def kf = java.security.KeyFactory.getInstance("RSA")
	def pubkey = kf.generatePublic(rsa)
	def signer = java.security.Signature.getInstance("SHA1withRSA")
	signer.initVerify(pubkey)
	def hashedBody = java.security.MessageDigest.getInstance("SHA").digest(body.getBytes())
	signer.update(hashedBody)
	def verification = signer.verify(signature.decodeBase64())
	def expiration = new Date(System.currentTimeMillis())<new Date(Long.parseLong(expire))
	if (expiration&&verification)
		retValue=true
	return retValue
}

def _3DESKey = "QeVYdNvQbz7jyqbFu3wmeuyws96KwmvBEu3o6+o138E\\="
def _PrivateKey= "uHUSg2YvtKovgtQLX+SmtH4BPnyBy7cLnNsI+0QaC+KcMVKNuBYjYknyP0n+CCJgkDebdjz5vHqhqlg3abv/P19dzjvJCCHXzIDapYOPBBYcmWZGpMB19b6bsykwjdNbf+xjijRQvOXetf5///ljiHeq/NP58qpS9KXfyXcjXGdEAwFSKAFTG1bj9Cpy6iqWQ9SPFD3kiEhzNu16lSmR4BNtZTpZ0uy8hfYB1u9HB3/sJ0ih2iw7qR8fnhVuKbpIyAtio5sPOHfgayI01vDhEdHNPcZaTxx5Ndf1MXq05Bv2ZEX3JRMtVsLfOvNBnz5PdmPj74CH8Qy7oa4ZX2bDEWF9pBkS7B9rPKDe291/d7M\\="
def _PublicKey = "ALTw+Sy9dQSv8lQ6JPX/zhqwLtua6yo9mmrC55NAxu7SLXx2Ee+A8OBMTH4+4OIk0pnNAqfR8AKARY4D3fqEJB5z+V/6Zh9Gap3tGT7wmTf0mrtF9EqgLCiVqfBq+0LM+ZfvT6YC6PG1CFVM1kkuuvn2Sc2T+tuiTQSX+zWauR45AQAB"
def password="lotus123"

//decrypt encrypted 3DES key
byte[] TrippleDESKey = getSecretKey(_3DESKey,password)

//decrypt encrypted private key
byte[] PrivateKey = getSecretKey(_PrivateKey,password)

//get RSA object from private key
def rsa1 = privKeyToRSA(PrivateKey)

//calculate the epoch expiration, set at 2hours
def expire = ((int)(System.currentTimeMillis()/1000)+7200)+"000"

//add expire to the body and add some fields like user DN etc
def body = 'expire:'+expire+'$u:user\\:defaultWIMFileBasedRealm/CN=Pieter Geerts,O=beibm'

//calculate signature for LtpaToken2 as BASE64(SHA1_WITH_RSA(SHA_DIGEST(body)))
def signature = signLtpaToken2(body,rsa1)

//raw token as body%expiration%signature
def rawToken = [body, expire, signature].join('%')

//encrypt the raw token and return as base64 string
def encToken = encryptLtpaToken2(rawToken,TrippleDESKey)
println encToken

//decrypt the LtpaToken2
def rawToken2 = decryptLtpaToken2(encToken,TrippleDESKey)

//get RSA object from unencrypted public key
def rsa2 = pubKeyToRSA(_PublicKey)

//verify the LtpaToken and return the raw token
if (verifyLtpaToken2(rawToken2.split('%'),rsa2)){
	println rawToken2
}