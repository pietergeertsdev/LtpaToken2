# LtpaToken2
**Lightweight Third-Party Authentication (LTPA)**, is an authentication technology used in IBM WebSphere and Lotus Domino products. When accessing web servers that use the LTPA technology it is possible for a web user to re-use their login across physical servers.

A **Lotus Domino** server or an **IBM WebSphere** server that is configured to use the LTPA authentication will challenge the web user for a name and password. When the user has been authenticated, their browser will have received a session cookie - a cookie that is only available for one browsing session. This cookie contains the LTPA token.

If the user – after having received the LTPA token – accesses a server that is a member of the same authentication realm as the first server, and if the browsing session has not been terminated (the browser was not closed down), then the user is automatically authenticated and will not be challenged for a name and password. Such an environment is also called a Single-Sign-On (SSO) environment.

This article focuses only on Version 2 of the LtpaToken. Version 1 is outdated and less secure.

The Plain text token consist of a **token body**%**expiration time**%**signature**
  
**Token body** is composed by some of the following fields:
- Username: u:realm+distinguished name
- Hostname: host:server hostname
- Port: port:server port
- Naming Provider: java.naming.provider.url:url of the jndi provider
- Server Name: process.serverName:servername
- Authentication Method: security.authMechOID:auth method
- Type: type:protocol type
- Expiation Time: expire:timestamp

Concatenated by the symbol "$", eg: u:user\:defaultWIMFileBasedRealm/CN=Pieter Geerts,O=beibm$expire:123123123

A valid token can just have the username.

**expiration time** is the timestamp for a valid session

**signature** for LtpaToken2 is BASE64(SHA1_WITH_RSA(SHA_DIGEST(Token body)))
  
These scripts can encrypt, decrypt, sign and verify a WebSphere/Domino LtpaToken2 based on the server ltpa keyfile.
The ltpa keyfile consist of the following variables:
- The **3DESKey** is a base64 encoded string, representing the result of encrypting the actual 3DESKey with a key that was derived from SHA1 hashing the password. 
The result of SHA1 hash is always 20 bytes, therefore the result need to be right padded with 0x0 bytes to a total length of 24 bytes for **DES-EDE3 ECB** decrypting the secret.
The first 16 bytes from the decrypted secret are only necessary for **AES-128 CBC** encryption and decryption of a LtpaToken2.
- The **PrivateKey** is a **DES-EDE3 ECB** encrypted base64 representation of the Private Key. It contains the minimal amount of RSA components in order to reconstruct the full RSA object. This Key is only necessary for **signature** creation.
- The **PublicKey** is an unencrypted base64 representation of the Public Key. This Key is only necessary for **signature** validation.

The sample code flow goes as:
1. create hashed password
2. decrypt encrypted 3DES key
3. decrypt encrypted private key
4. reconstruct RSA object from private key
5. calculate the epoch expiration, set default at 2hours
6. add expire to the body and add some fields like user DN etc
7. create signature for LtpaToken2 as BASE64(SHA1_WITH_RSA(SHA_DIGEST(body)))
8. create raw token as body%expiration%signature
9. encrypt the raw token and return as base64 string
10. decrypt the LtpaToken2
11. get RSA object from unencrypted public key
12. verify the LtpaToken and return the raw token

## node

Uses BigInt primitive which is natively supported from Node.js version > 10.4.0 so no need for additional packages to support Big Integers.

Requires **crypto-js** package for encryption and decryption.
crypto-js is a JavaScript library of crypto standards compatible with openssl (https://www.npmjs.com/package/crypto-js)
```
npm install crypto-js
```
Requires  **node-rsa** for signature creation and validation.
node-rsa is a RSA library, based on jsbn library (https://www.npmjs.com/package/node-rsa)
```
npm install node-rsa
```
## groovy
no additional packages are required to run the code

## java
no additional packages are required to run the code

## python
pycrypto package seems to have issues with signature creation and validation but is also outdated(2013).pycryptodome seems to be working for signature validation, however the signature creation is still not working correctly hence a wrong LtpaToken2 creation. cryptography package seems to be working correctly for encryption&decryption and signature creation&validation
```
pip install cryptography
```
### run
```
eTuRcNLOkWDFe4a3hRQe26i1M7c4voxigCrK5WGw6Q1/754nGxIV4hS4euYtpKPe6yCxL+RqpELpSitoUR3Iq3pbDpss8SmjXgNtmUk77y6MvRRqD/sLP1QK5NM5UyvJkdCa6Y92Xx5pgp+u3rXM8x+f0zG9vOR5oMozWTtTE0H9sxiLDXqQfly+xWsamoTrhxUqwxGcTfWTf/oTJlQRtI9m4TVBDMGT8+dM/2KtrxiySCsVZiit1YkrImRFB+Z4TJLqFQhzabY2XfwAT9DgUleJst5PjwtaONLIuET/SLY28aqCgiXDFUFEXO8V2D9ijTtVm8hmtOxDJofn9fyQktLUivxcYMWxWb2PBSXIBJ4=
expire:1596214193000$u:user\:defaultWIMFileBasedRealm/CN=Pieter Geerts,O=beibm%1596214193000%FwlAr5Z9dV1yA4IoH7bJeXLLWhwwIZ10QSP0KzZrPhOwVz/vgWkMLvssEGN3D2+n1A7FcJIsFv6AH0bjtXcJ/JCwBdAs5Vw3Q0i/4jD+p59kZaPx95xwaUIhsKpYe37RgGU/V+LBWNsAIF0Rml5e93eSY/P3cm/yjHCaaMznL4c=
```
