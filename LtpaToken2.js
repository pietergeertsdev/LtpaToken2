const CryptoJS = require("crypto-js");
const NodeRSA = require('node-rsa');

function eGcd (a, b) {
  a = BigInt(a)
  b = BigInt(b)
  if (a <= 0n | b <= 0n) throw new RangeError('a and b MUST be > 0') // a and b MUST be positive
  let x = 0n
  let y = 1n
  let u = 1n
  let v = 0n
  while (a !== 0n) {
    const q = b / a
    const r = b % a
    const m = x - (u * q)
    const n = y - (v * q)
    b = a
    a = r
    x = u
    y = v
    u = m
    v = n
  }
  return {
    g: b,
    x: x,
    y: y
  }
}

function toZn (a, n) {
  n = BigInt(n)
  if (n <= 0) { return NaN }
  a = BigInt(a) % n
  return (a < 0) ? a + n : a
}

function modInv (a, n) {
  try {
    const egcd = eGcd(toZn(a, n), n)
    if (egcd.g !== 1n) {
      return NaN // modular inverse does not exist
    } else {
      return toZn(egcd.x, n)
    }
  } catch (error) {
    return NaN
  }
}

function wordToByteArray(wordArray) {
    var byteArray = [], word, i, j;
    for (i = 0; i < wordArray.length; ++i) {
        word = wordArray[i];
        for (j = 3; j >= 0; --j) {
            byteArray.push((word >> 8 * j) & 0xFF);
        }
    }
    return byteArray;
}

function getSecretKey(key, password){
	const hash = CryptoJS.lib.WordArray.create(CryptoJS.SHA1(CryptoJS.enc.Utf8.parse(password)).words.concat(0));
	return CryptoJS.TripleDES.decrypt({ciphertext:CryptoJS.enc.Base64.parse(key)},hash,{mode:CryptoJS.mode.ECB});
}

function privKeyToRSA(key){
	//get available RSA components from private key
	const eLength = 3;
	const pLength = 65;
	const qLength = 65;
	const components = Array(8).fill(null);

	components[2] = Buffer.alloc(eLength);
	components[3] = Buffer.alloc(pLength);
	components[4] = Buffer.alloc(qLength);
	
	if (key.length > eLength + pLength + qLength) {
		const abyte2 = Buffer.alloc(4);
		key.copy(abyte2, 0, 0, 4);
		const privExponentLength = abyte2.readUIntBE(0, 4);
		components[1] = Buffer.alloc(privExponentLength);
		key.copy(components[1], 0, 4, privExponentLength + 4);
		key.copy(components[2], 0, privExponentLength + 4, privExponentLength + 4 + eLength);
		key.copy(components[3], 0, privExponentLength + 4 + eLength, privExponentLength + 4 + eLength + pLength);
		key.copy(components[4], 0, privExponentLength + 4 + eLength + pLength, privExponentLength + 4 + eLength + pLength + qLength);
	}
	else {
		key.copy(components[2], 0, 0, eLength);
		key.copy(components[3], 0, eLength, eLength + pLength);
		key.copy(components[4], 0, eLength + pLength , eLength + pLength + qLength);  
	}

	//compute missing RSA components
	const bigints = Array(8).fill(null);
	for (i = 0; i <= 7; ++i) {
		if (components[i]!=null)
			bigints[i]= BigInt('0x'+components[i].toString('hex'))
	}
	
	if (bigints[3]<bigints[4]) {
		let bigint = bigints[3];
		bigints[3] = bigints[4];
		bigints[4] = bigint;
		bigint = bigints[5];
		bigints[5] = bigints[6];
		bigints[6] = bigint;
		bigints[7] = null;
	}
	
	if (bigints[7] == null)
		bigints[7] = modInv(bigints[4],bigints[3]);
	if (bigints[0] == null)
		bigints[0] = bigints[3]*(bigints[4]);
	if (bigints[1] == null)
		bigints[1] = modInv(bigints[2],((bigints[3]-1n)*(bigints[4]-1n)));
	if (bigints[5] == null)
		bigints[5] = bigints[1]%(bigints[3]-1n);
	if (bigints[6] == null)
		bigints[6] = bigints[1]%(bigints[4]-1n);

	//construct the RSA object
	//n:		modulus				bigints[0]
	//d:		private exponent	bigints[1]
	//e:		public exponent		bigints[2]	
	//p:		prime1 				bigints[3]
	//q:		prime2				bigints[4]
	//dmp1: 	exponent1			bigints[5]
	//dmq1: 	exponent2			bigints[6]
	//coeff:	coefficient			bigints[7]
	const rsa = NodeRSA({b:1024});
	rsa.setOptions({environment:'node',signingScheme:'sha1'});
	rsa.importKey({n:bigints[0].toString(),d:bigints[1].toString(),e:Number(bigints[2].toString()),p:bigints[3].toString(),q:bigints[4].toString(),dmp1:bigints[5].toString(),dmq1:bigints[6].toString(),coeff:bigints[7].toString()},'components',);
	return rsa;
}

function pubKeyToRSA (key) {
	//get available RSA components from public key
	let buff = Buffer.from(key,'base64');
	const mod = Buffer.alloc(129);
	const exp = Buffer.alloc(3);
	buff.copy(mod, 0, 0,129);
	buff.copy(exp, 0, 129, 132);
	
	//construct the RSA object
	const rsa = NodeRSA({b:1024});
	rsa.setOptions({environment:'node',signingScheme:'sha1'});	
	rsa.importKey({n:Buffer.from(mod),e:exp,},'components-public');
	return rsa;
};

function signLtpaToken2 (data, rsa) {
	const hashedBody = Buffer.from(wordToByteArray(CryptoJS.SHA1(data).words));
	const signature = rsa.sign(hashedBody,'base64')
	return signature;		
};

function encryptLtpaToken2 (data,key) {
	key = CryptoJS.lib.WordArray.create(key.words.slice(0,4));
	return CryptoJS.enc.Base64.stringify(CryptoJS.AES.encrypt(data,key,{iv:key}).ciphertext);
}

function decryptLtpaToken2 (data,key) {
	key = CryptoJS.lib.WordArray.create(key.words.slice(0,4));
	return CryptoJS.AES.decrypt({ciphertext:CryptoJS.enc.Base64.parse(data)},key,{iv:key}).toString(CryptoJS.enc.Utf8);
}

function verifyLtpaToken2 (data, rsa) {
	const body = data[0];
	const expire = data[1];
	const signature = data[2];
	var retValue=false;
	const hashedBody = Buffer.from(wordToByteArray(CryptoJS.SHA1(body).words));
	const verification = rsa.verify(hashedBody,signature,'buffer','base64');
	const expiration = new Date()<new Date(expire*1);
	if (expiration&&verification)
		retValue=true;
	return retValue;
};

const _3DESKey="QeVYdNvQbz7jyqbFu3wmeuyws96KwmvBEu3o6+o138E\=";
const _PrivateKey="uHUSg2YvtKovgtQLX+SmtH4BPnyBy7cLnNsI+0QaC+KcMVKNuBYjYknyP0n+CCJgkDebdjz5vHqhqlg3abv/P19dzjvJCCHXzIDapYOPBBYcmWZGpMB19b6bsykwjdNbf+xjijRQvOXetf5///ljiHeq/NP58qpS9KXfyXcjXGdEAwFSKAFTG1bj9Cpy6iqWQ9SPFD3kiEhzNu16lSmR4BNtZTpZ0uy8hfYB1u9HB3/sJ0ih2iw7qR8fnhVuKbpIyAtio5sPOHfgayI01vDhEdHNPcZaTxx5Ndf1MXq05Bv2ZEX3JRMtVsLfOvNBnz5PdmPj74CH8Qy7oa4ZX2bDEWF9pBkS7B9rPKDe291/d7M\=";
const _PublicKey = "ALTw+Sy9dQSv8lQ6JPX/zhqwLtua6yo9mmrC55NAxu7SLXx2Ee+A8OBMTH4+4OIk0pnNAqfR8AKARY4D3fqEJB5z+V/6Zh9Gap3tGT7wmTf0mrtF9EqgLCiVqfBq+0LM+ZfvT6YC6PG1CFVM1kkuuvn2Sc2T+tuiTQSX+zWauR45AQAB";
const password="lotus123";

//decrypt encrypted 3DES key
const TrippleDESKey = getSecretKey(_3DESKey,password)

//decrypt encrypted private key
const PrivateKey = getSecretKey(_PrivateKey,password)

//get RSA object from private key
const rsa1 = privKeyToRSA((Buffer.from(wordToByteArray(PrivateKey.words))));

//calculate the epoch expiration, set at 2hours
var expire = Math.floor((new Date() / 1000)+7200) + "000";

//add expire to the body and add some fields like user DN etc
const body = "expire:"+expire+"$u:user\\:defaultWIMFileBasedRealm/CN=Pieter Geerts,O=beibm";

//calculate signature for LtpaToken2 as BASE64(SHA1_WITH_RSA(SHA_DIGEST(body)))
const signature = signLtpaToken2(body,rsa1);

//raw token as body%expiration%signature
const rawToken = [body, expire, signature].join('%');

//encrypt the raw token and return as base64 string
const encToken = encryptLtpaToken2(rawToken,TrippleDESKey);
console.log(encToken);

//decrypt the LtpaToken2
const rawToken2 = decryptLtpaToken2(encToken,TrippleDESKey);

//get RSA object from unencrypted public key
const rsa2 = pubKeyToRSA(_PublicKey);

//verify the LtpaToken and return the raw token
if (verifyLtpaToken2(rawToken2.split('%'),rsa2))
	console.log(rawToken2);
