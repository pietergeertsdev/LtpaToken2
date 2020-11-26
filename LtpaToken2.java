import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Cipher;

public class LtpaToken2 {

	private static byte[] getSecretKey(String key, String password) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA");
		md.update(password.getBytes());
		byte[] hash3DES = new byte[24];
		System.arraycopy(md.digest(), 0, hash3DES, 0, 20);
		Arrays.fill(hash3DES, 20, 24, (byte) 0);
		Cipher cipher = javax.crypto.Cipher.getInstance("DESede/ECB/PKCS5Padding");
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, javax.crypto.SecretKeyFactory.getInstance("DESede").generateSecret(new javax.crypto.spec.DESedeKeySpec(hash3DES)));
		return cipher.doFinal(Base64.getDecoder().decode(key.getBytes()));
	}

	private static RSAPrivateCrtKeySpec privKeyToRSA(byte[] key) {
		// get available RSA components from private key
		int eLength = 3;
		int pLength = 65;
		int qLength = 65;
		byte[][] components = new byte[8][];

		components[2] = new byte[eLength];
		components[3] = new byte[pLength];
		components[4] = new byte[qLength];

		if (key.length > eLength + pLength + qLength) {
			byte[] abyte2 = new byte[4];
			for (int i = 0; i < 4; i++) {
				abyte2[i] = key[i];
			}
			int privExponentLength = ((abyte2[0] & 0xFF) << 24) | ((abyte2[1] & 0xFF) << 16) | ((abyte2[2] & 0xFF) << 8) | ((abyte2[3] & 0xFF) << 0);
			components[1] = new byte[privExponentLength];
			System.arraycopy(key, 4, components[1], 0, privExponentLength);
			System.arraycopy(key, privExponentLength + 4, components[2], 0, eLength);
			System.arraycopy(key, privExponentLength + 4 + eLength, components[3], 0, pLength);
			System.arraycopy(key, privExponentLength + 4 + eLength + pLength, components[4], 0, qLength);
		} else {
			System.arraycopy(key, 0, components[2], 0, eLength);
			System.arraycopy(key, eLength, components[3], 0, pLength);
			System.arraycopy(key, eLength + pLength, components[4], 0, qLength);
		}

		// compute missing RSA components
		BigInteger[] bigints = new BigInteger[8];
		for (int i = 0; i <= 7; i++)
			if (components[i] != null)
				bigints[i] = new BigInteger(1, components[i]);
		if (bigints[3].compareTo(bigints[4]) < 0) {
			BigInteger bigint = bigints[3];
			bigints[3] = bigints[4];
			bigints[4] = bigint;
			bigint = bigints[5];
			bigints[5] = bigints[6];
			bigints[6] = bigint;
			bigints[7] = null;
		}
		if (bigints[7] == null)
			bigints[7] = bigints[4].modInverse(bigints[3]);
		if (bigints[0] == null)
			bigints[0] = bigints[3].multiply(bigints[4]);
		if (bigints[1] == null)
			bigints[1] = bigints[2].modInverse(bigints[3].subtract(BigInteger.ONE).multiply(bigints[4].subtract(BigInteger.ONE)));
		if (bigints[5] == null)
			bigints[5] = bigints[1].remainder(bigints[3].subtract(BigInteger.ONE));
		if (bigints[6] == null)
			bigints[6] = bigints[1].remainder(bigints[4].subtract(BigInteger.ONE));

		//construct the RSA object
		//n:		modulus				bigints[0]
		//d:		private exponent	bigints[1]
		//e:		public exponent		bigints[2]	
		//p:		prime1 				bigints[3]
		//q:		prime2				bigints[4]
		//dmp1: 	exponent1			bigints[5]
		//dmq1: 	exponent2			bigints[6]
		//coeff:	coefficient			bigints[7]
		return new java.security.spec.RSAPrivateCrtKeySpec(bigints[0], bigints[2], bigints[1], bigints[3], bigints[4], bigints[5], bigints[6], bigints[7]);
	}

	private static RSAPublicKeySpec pubKeyToRSA(String key) {
		//get available RSA components from public key
		byte[] parts = Base64.getDecoder().decode(key);
		BigInteger modulus = new BigInteger(Arrays.copyOfRange(parts, 0, 129));
		BigInteger exponent = new BigInteger(Arrays.copyOfRange(parts, 129, 129 + 3));
		
		//construct the RSA object
		//RSAPublicKeySpec(BigInteger modulus, BigInteger publicExponent)
		RSAPublicKeySpec pubKeySpec = new java.security.spec.RSAPublicKeySpec(modulus, exponent);
		return pubKeySpec;
	}
	
	private static String signLtpaToken2(String data, RSAPrivateCrtKeySpec rsa) throws Exception {
		MessageDigest md1JCE = MessageDigest.getInstance("SHA");
		byte[] plainUserDataBytes = md1JCE.digest(data.getBytes());
		byte[] encodedSignatureBytes = null;
		PrivateKey privatekey = java.security.KeyFactory.getInstance("RSA").generatePrivate(rsa);
		Signature signer = java.security.Signature.getInstance("SHA1withRSA");
		signer.initSign(privatekey);
		signer.update(plainUserDataBytes, 0, plainUserDataBytes.length);
		encodedSignatureBytes = signer.sign();
		return Base64.getEncoder().encodeToString(encodedSignatureBytes);
	}

	private static String encryptLtpaToken2(String data, byte[] key) throws Exception {
		Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, 0, 16, "AES"), new javax.crypto.spec.IvParameterSpec(key, 0, 16));
		return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes("UTF8")));
	}

	private static String decryptLtpaToken2(String data, byte[] key) throws Exception {
		Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, 0, 16, "AES"), new javax.crypto.spec.IvParameterSpec(key, 0, 16));
		return new String(cipher.doFinal(Base64.getDecoder().decode(data)));
	}

	private static boolean verifyLtpaToken2(String[] data, RSAPublicKeySpec rsa) throws Exception {
		String body = data[0];
		String expire = data[1];
		String signature = data[2];
		boolean retValue = false;
		KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
		PublicKey pubkey = kf.generatePublic(rsa);
		Signature signer = java.security.Signature.getInstance("SHA1withRSA");
		signer.initVerify(pubkey);
		byte[] hashedBody = java.security.MessageDigest.getInstance("SHA").digest(body.getBytes());
		signer.update(hashedBody);
		boolean verification = signer.verify(Base64.getDecoder().decode(signature));
		boolean expiration = (new Date(System.currentTimeMillis())).compareTo(new Date(Long.parseLong(expire))) < 0 ? true : false;
		if (expiration && verification)
			retValue = true;
		return retValue;
	}

	public static void main(String[] args) throws Exception {

		String _3DESKey = "QeVYdNvQbz7jyqbFu3wmeuyws96KwmvBEu3o6+o138E";
		String _PrivateKey = "uHUSg2YvtKovgtQLX+SmtH4BPnyBy7cLnNsI+0QaC+KcMVKNuBYjYknyP0n+CCJgkDebdjz5vHqhqlg3abv/P19dzjvJCCHXzIDapYOPBBYcmWZGpMB19b6bsykwjdNbf+xjijRQvOXetf5///ljiHeq/NP58qpS9KXfyXcjXGdEAwFSKAFTG1bj9Cpy6iqWQ9SPFD3kiEhzNu16lSmR4BNtZTpZ0uy8hfYB1u9HB3/sJ0ih2iw7qR8fnhVuKbpIyAtio5sPOHfgayI01vDhEdHNPcZaTxx5Ndf1MXq05Bv2ZEX3JRMtVsLfOvNBnz5PdmPj74CH8Qy7oa4ZX2bDEWF9pBkS7B9rPKDe291/d7M";
		String _PublicKey = "ALTw+Sy9dQSv8lQ6JPX/zhqwLtua6yo9mmrC55NAxu7SLXx2Ee+A8OBMTH4+4OIk0pnNAqfR8AKARY4D3fqEJB5z+V/6Zh9Gap3tGT7wmTf0mrtF9EqgLCiVqfBq+0LM+ZfvT6YC6PG1CFVM1kkuuvn2Sc2T+tuiTQSX+zWauR45AQAB";
		String password = "lotus123";

		// decrypt encrypted 3DES key
		byte[] TrippleDESKey = getSecretKey(_3DESKey, password);

		// decrypt encrypted private key
		byte[] PrivateKey = getSecretKey(_PrivateKey, password);

		// get RSA object from private key
		RSAPrivateCrtKeySpec rsa1 = privKeyToRSA(PrivateKey);

		// calculate the epoch expiration, set at 2hours
		String expire = ((int) (System.currentTimeMillis() / 1000) + 7200) + "000";

		// add expire to the body and add some fields like user DN etc
		String body = "expire:" + expire + "$u:user\\:defaultWIMFileBasedRealm/CN=Pieter Geerts,O=beibm";

		// calculate signature for LtpaToken2 as BASE64(SHA1_WITH_RSA(SHA_DIGEST(body)))
		String signature = signLtpaToken2(body, rsa1);

		// raw token as body%expiration%signature
		String rawToken = String.join("%", body, expire, signature);

		// encrypt the raw token and return as base64 string
		String encToken = encryptLtpaToken2(rawToken, TrippleDESKey);
		System.out.println(encToken);

		// decrypt the LtpaToken2
		String rawToken2 = decryptLtpaToken2(encToken, TrippleDESKey);

		// get RSA object from unencrypted public key
		RSAPublicKeySpec rsa2 = pubKeyToRSA(_PublicKey);

		// verify the LtpaToken and return the raw token
		if (verifyLtpaToken2(rawToken2.split("%"), rsa2)) {
			System.out.println(rawToken2);
		}
	}
}
