# Python Encryption/Decryption for SR25519 Keypairs based on ECIES

This package provides simple encryption/decryption functions for Schnorrkel (SR25519) type keypairs following 
Elliptic Curve Integrated Encryption Scheme (ECIES).

Credits to [SubMessage Dapp](https://github.com/Polkadot-DevCamp-2022/submessage-dapp) team for the base idea, 
implemented on JS.

Scheme explanation available here:

https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption

## Implementation Details

The encryption process consist following steps:

1. **Ephemeral key generation (optional)**

Generate new keypair using the `substrateinterface.Keypair.create_from_mnemonic()` with a random seed. Otherwise, 
uses the provided keypair from the sender.

2. **Key agreement** 

Use `rbcl.crypto_scalarmult_ristretto255()` function to create shared secret for the message private key and 
the recipient public key. Since keypairs are already in SR25519, they can be used as the scalar and the point for this
operation.

3. **Key derivation**

Use PBKDF2 (with random salt and 2048 rounds) to derive a new secret from the previous step output. The derived secret 
is split into:
- MAC key (first 32 bytes)
- encryption key (last 32 bytes)

4. **Message encryption**

Use `nacl.secret.secretbox` symmetric encryption to encrypt the message with the encryption key generated at step 3. 
A nonce (24 bytes) is randomly generated.

5. **MAC Generation**

Generate MAC data using HMAC SHA256 (using the MAC key from step 3) of the concatenation of the encryption nonce, 
message public key and encrypted message.

The encrypted message is the concatenation of the following elements:
- `nonce` (24 bytes) : random generated nonce used for the symmetric encryption (step 4)
- `salt` (32 bytes) : random generated salt used for the key derivation (step 3)
- `msg_public_key` (32 bytes): public key of the message keypair (step 1)
- `mac_value` (32 bytes): mac value computed at step 5
- `encrypted_message` (remaining bytes): encrypted message (step 4)