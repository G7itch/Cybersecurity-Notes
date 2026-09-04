# Cryptography and PKI

PKI is the implementation of cryptology on a computer network. It facilitates cryptography of a computer or the internet.

**Encryption**: The process of converting plaintext to ciphertext.

**Digital signature**: Ties the signee to the information signed. (Authentication)

**Non-repudiation**: Ensures that that actions taken are tied to users without any doubt.

### Ciphers

A cipher is a secret or disguised way or writing a code. Cryptographic algorithms and digital keys allow you to encrypt and decrypt information. The simplest cipher is a substitution cipher - one character is directly replaced with another character. A transposition cipher is about rearranging letters - one such example is a rail fence cipher. A one-time pad cipher introduces randomness.

Stream and block ciphers are commonly used by computers. Stream ciphers encrypt one character at a time and are generally much faster. Examples of stream ciphers are FISH and RC4. Block ciphers encrypt plain text in blocks. The size of the block depends on the size of the key. Some examples are DES, 3DES, AES.

### Keys and Cryptographic Algorithms

A digital key is a value that is used to perform cryptographic operations. Keys can be used to encrypt data or create a digital signature. Keys can either be private or public. Public keys are often 1024 bits or larger, these are often used to encrypt small pieces of data. Small keys are better for encrypting streams or bulk data for performance reasons.

Key stretching is a method to strengthen keys or passwords. They initial key is passed into a new algorithm to get an enhanced key or password. Examples include BCRYPT and PBKDF2. A salt is a random value added to increase entropy.

A symmetric algorithm is a cipher used to encrypt and decrypt data using the same key. Example include: DES, 3DES, IDEA, AES, RC4, Blowfish. The main advantage of symmetric cryptography is that it is faster to encrypt and decrypt. The main disadvantage to symmetric encryption is that it requires a secret key that must stay private.

An asymmetric algorithm is a cipher used for cryptographic operations using a pair of mathematically related keys. Asymmetric algorithms are also known as public-key algorithms. Examples include: Diffie-Hellman, RSA, ECC, PGP/GPG, DSA. The main advantage of asymmetric algorithms is that users do not need to share their private keys. The main disadvantage is that it is very slow.

Symmetric and asymmetric encryption should be combined to get the benefits of both types of algorithm.

### Hashing and Digital Signatures

Hashing is the process of converting data of an arbitrary size to a unique value a fixed size. Some of the benefits for hashing in cryptography are:

1. Output value is a fixed length. This denies the bad actor information about the nature of the input data

2. Output value is unique. This denies the bad actor the ability to alter data.

3. Hashing is not reversible. This denies the bad actor the ability to use the output value to determine the input value.

Hashing and asymmetric cryptography are needed to produce a digital signature. The input value gets hashed, which then has an asymmetric algorithm applied to it. This forms the signature which is attached to data. In order to verify this data, we need the public key.

Public keys are written to certificates which are issued by a certificate authority (CA).

There are many popular hashing functions including: MD5, SHA1, SHA2, NTLM, HAVEL. MD5 has fallen out of favour because of its susceptibility to collisions. SHA2 is really a suite of algorithms include the very common SHA-256 and SHA-512. SHA3 lets you choose how long the output should be.

One of the most common attacks against hashing is brute forcing. This is just hashing every combination and comparing the results to try and recover the original value. This usually has a ridiculous amount of possibilities and thus is not really possible. However, the more information the threat actor has about the input, the more possibilities they can reduce. Since servers do not store actual passwords, attackers do not care if they get the "correct" input as long as they find a value that also hashes to the same password. The best example of this is a birthday attack.

### PKI

Public Key Infrastructure is an ecosystem comprised of the policies, procedures, software and hardware needed to create, distribute, store, use and revoke digital certificates. There are 4 entities that compose a PKI:

- Certification Authority (CA)

- Registration Authority (RA)

- Directory server

- End entity

A digital certificate is an electronic document issued and signed by a trusted entity. Certificates can contain public keys but are not required to. The most important certificate standard is X.509 version 3. Common fields found in a certificate are:

- Serial number

- Algorithm,

- Validity period

- Issuer name

- Subject name

- Key value

- Key usage

The CA performs two primary functions: Issues certificates to end entities, and establishes an ecosystem of trust based on the CA's private key.

In a PKI implementation, we can have multiple CA's. These can be organised in a hierarchical structure or a lateral structure.

PKI standards expect users to fetch other certificates from X.500 LDAP compliant servers. These servers are called directory servers.

A registration authority is a function for certificate enrolment used in PKIs. The RA verifies and forwards certificate requests to the CA. 

### Introducing Quantum Security

Almost all of online life is reliant on cryptography. Currently large digital keys and sophisticated algorithms have made brute forcing attacks impossible. However, quantum computing may threaten the integrity of some of our existing algorithms.

Modern digital security relies heavily on asymmetric cryptography. These algorithms are secure because they are hard problems for computers to solve. With the rise of quantum computing, it may be possible that these algorithms could be compromised and become simpler to solve.

Symmetric encryption would not be inherently broken, provided that key lengths increase. The same goes for hashing.

Quantum cryptography operates based on the laws of physics which makes behaviour inherently unpredictable. QKD is a protocol the enables two parties to generate a shared encryption key using the principles of quantum mechanics. Post-quantum cryptography (PQC) refers to algorithms designed to remain secure even if large-scale quantum computers become practical.

Note that QC is not the same as PQC. QC uses physics based on quantum mechanics with limited practical applications. PQC is based on mathematics and does not require quantum hardware.

NIST now have standards for establishing PQC. For key establishment, NIST choose CRYSTALS-KYBER (ML-KEM). For digital signatures, NIST chose:

- CRYSTALS-Dilithium (ML-DSA)

- SPHINCS+ (SLP-DSA)

- FALCON (FN-DSA)
