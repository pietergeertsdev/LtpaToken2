# LtpaToken2 - IBM WebSphere & Lotus Domino Authentication

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-8%2B-orange.svg)](https://www.java.com)
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org)
[![Node.js](https://img.shields.io/badge/Node.js-10.4%2B-green.svg)](https://nodejs.org)

A cross-platform implementation for creating, validating, and managing LtpaToken2 (Lightweight Third-Party Authentication) tokens used in IBM WebSphere Application Server and Lotus Domino environments.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Technical Details](#technical-details)
- [Security Considerations](#security-considerations)

## Overview

**LTPA (Lightweight Third-Party Authentication)** is an authentication technology used in IBM WebSphere and Lotus Domino products. This project provides implementations in Java, Python and Node.js for:

- Creating valid LtpaToken2 tokens
- Validating and verifying tokens
- Encrypting/decrypting token data
- Managing RSA signatures

### What is LtpaToken2?

LtpaToken2 enables **Single Sign-On (SSO)** across multiple servers in the same authentication realm. When a user authenticates with one server, they receive a session cookie containing the LTPA token, which can be used to access other servers without re-authentication.

## Features

- **Full LTPA Token Lifecycle**: Create, encrypt, decrypt, sign, and verify tokens
- **Cross-Platform**: Implementations in Java, Python and Node.js
- **Secure Cryptography**: Uses industry-standard encryption (3DES, AES-128, RSA with SHA1)

## Quick Start

### Prerequisites

- **Java**: JDK 8 or higher
- **Python**: Python 3.7+ with `pycryptodome`
- **Node.js**: Node.js 10.4+ with `crypto-js` and `node-rsa`

## Installation

### Java

No external dependencies required.

Run the script:

```bash
java LtpaToken2.java [keyfile] [password]
```

### Python

Install dependencies:

```bash
pip install pycryptodome
```

Run the script:

```bash
python3 LtpaToken2.py [keyfile] [password]
```

### Node.js

Install dependencies:

```bash
npm install crypto-js node-rsa
```

Run the script:

```bash
node LtpaToken2.js [keyfile] [password]
```

### Key File Format

LTPA key files are Java properties files containing:

```properties
#IBM WebSphere Application Server key file
com.ibm.websphere.ltpa.version=1.0
com.ibm.websphere.ltpa.3DESKey=<base64_encoded_key>
com.ibm.websphere.ltpa.PrivateKey=<base64_encoded_key>
com.ibm.websphere.ltpa.PublicKey=<base64_encoded_key>
com.ibm.websphere.ltpa.Realm=<realm>
```

## Technical Details

### Token Structure

An LtpaToken2 consists of three parts separated by `%`:

```
<token_body>%<expiration_time>%<signature>
```

**Token Body** contains fields separated by `$`:
- `u:` - Username with realm (e.g., `u:user\:realm/CN=Name,O=Org`)
- `host:` - Server hostname (optional)
- `port:` - Server port (optional)
- `java.naming.provider.url:` - url of the jndi provider (optional)
- `process.serverName:` - servername (optional)
- `security.authMechOID:` - Authentication Method (optional)
- `type:` - Protocol Type (optional)
- `expire:` - Expiration timestamp
- Additional custom fields

**Expiration Time**: Unix timestamp in milliseconds

**Signature**: `BASE64(SHA1_WITH_RSA(SHA_DIGEST(token_body)))`

### Cryptographic Operations

#### 1. Key Derivation

The 3DES key is encrypted with a key derived from the password:

```
SHA1(password) → 20 bytes → pad to 24 bytes → 3DES key
```

#### 2. Token Encryption

Tokens are encrypted using AES-128-CBC:

```
AES-128-CBC(raw_token, key=first_16_bytes, iv=first_16_bytes)
```

#### 3. Signature Creation

Signatures use RSA with SHA1:

```
SHA1(token_body) → RSA_sign(hash, private_key) → BASE64(signature)
```

### RSA Key Reconstruction

The private key file contains minimal RSA components:
- Public exponent (e)
- Prime 1 (p)
- Prime 2 (q)
- Optional: Private exponent (d)

Missing components are calculated:
- Modulus: `n = p × q`
- Private exponent: `d = e^(-1) mod ((p-1)(q-1))`
- CRT exponents: `dP = d mod (p-1)`, `dQ = d mod (q-1)`
- CRT coefficient: `qInv = q^(-1) mod p`

## Security Considerations

### ⚠️ Important Security Notes

1. **SHA1 Usage**: LTPA tokens use SHA1 for hashing, which is cryptographically weak by modern standards. This is a limitation of the LTPA specification, not this implementation.

2. **Key File Protection**: LTPA key files contain sensitive cryptographic material. Protect them with appropriate file permissions:
   ```bash
   chmod 600 *.key
   ```

3. **Password Security**: Never hardcode passwords in production code. Use environment variables or secure key management systems.

4. **Token Expiration**: Always validate token expiration times. Default is 2 hours.

5. **HTTPS Only**: LTPA tokens should only be transmitted over HTTPS to prevent interception.

6. **Key Rotation**: Regularly rotate LTPA keys in production environments.

### Best Practices

- Store key files outside the web root
- Use strong passwords for key encryption
- Implement proper session management
- Log authentication attempts
- Monitor for suspicious activity
- Keep dependencies updated
