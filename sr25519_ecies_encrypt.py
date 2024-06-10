import hmac
import os
import hashlib
import rbcl
import typing as tp
from nacl.secret import SecretBox
from substrateinterface import KeypairType, Keypair

# Consts for encryption
ENCRYPTION_KEY_SIZE = 32
PUBLIC_KEY_SIZE = 32
MAC_KEY_SIZE = 32
MAC_VALUE_SIZE = 32
DERIVATION_KEY_SALT_SIZE = 32
DERIVATION_KEY_ROUNDS = 2048        # Number of iterations
DERIVATION_KEY_SIZE = 64            # Desired length of the derived key
PBKDF2_HASH_ALGORITHM = 'sha512'    # Hashing algorithm
NONCE_SIZE = 24


def sr25519_encrypt(message: str | bytes,
                    receiver_public_key: bytes,
                    sender_keypair: tp.Optional[Keypair] = None
                    ) -> bytes:

    # 1. Ephemeral key generation if no sender keypair is provided
    if sender_keypair is not None:
        message_keypair = sender_keypair
    else:
        message_keypair = Keypair.create_from_mnemonic(
            mnemonic=Keypair.generate_mnemonic(),
            crypto_type=KeypairType.SR25519
        )

    # 2. Key agreement
    agreement_key = get_sr25519_agreement(secret_key=message_keypair.private_key,
                                          public_key=receiver_public_key)

    # 2.5 Master secret and cryptographic random salt with KEY_DERIVATION_SALT_SIZE bytes
    master_secret = bytes_concat(message_keypair.public_key, agreement_key)
    salt = os.urandom(DERIVATION_KEY_SALT_SIZE)

    # 3. Key derivation
    encryption_key, mac_key = derive_key(master_secret, salt)

    # 4 Encryption
    nonce = os.urandom(NONCE_SIZE)
    encrypted_message = nacl_encrypt(message, encryption_key, nonce)

    # 5 MAC Generation
    mac_value = generate_mac_data(
        nonce=nonce,
        encrypted_message=encrypted_message,
        message_public_key=message_keypair.public_key,
        mac_key=mac_key
    )

    return bytes_concat(nonce, salt, message_keypair.public_key, mac_value, encrypted_message)


def get_sr25519_agreement(secret_key: bytes, public_key: bytes) -> bytes:
    try:
        # Get canonical part of secret key
        canonical_secret_key = secret_key[:32]

        # Perform elliptic curve point multiplication
        # Since secret and public key are already in sr25519, that can be used as scalar and Ristretto point
        shared_secret = rbcl.crypto_scalarmult_ristretto255(s=canonical_secret_key, p=public_key)

        return shared_secret
    except Exception as e:
        raise ValueError("Invalid secret or pubkey provided") from e


def derive_key(master_secret: bytes, salt: bytes) -> tuple:
    # Derive a 64-byte key using PBKDF2
    password = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_ALGORITHM,
        master_secret,
        salt,
        DERIVATION_KEY_ROUNDS,  # Number of iterations
        dklen=DERIVATION_KEY_SIZE  # Desired length of the derived key
    )

    assert len(password) >= MAC_KEY_SIZE + ENCRYPTION_KEY_SIZE, "Wrong derived key length"

    # Split the derived password into encryption key and MAC key
    mac_key = password[:MAC_KEY_SIZE]
    encryption_key = password[MAC_KEY_SIZE: MAC_KEY_SIZE + ENCRYPTION_KEY_SIZE]

    return encryption_key, mac_key


def nacl_encrypt(message: str | bytes, encryption_key: bytes, nonce: bytes) -> bytes:
    # Ensure the encryption key is 32 bytes
    if len(encryption_key) != 32:
        raise ValueError("Encryption key must be 32 bytes long.")

    # Create a nacl SecretBox using the encryption key
    box = SecretBox(encryption_key)

    try:
        # Encrypt the message
        encrypted_message = box.encrypt(message_to_bytes(message), nonce)
        return encrypted_message.ciphertext
    except Exception as e:
        raise ValueError("Invalid secret or pubkey provided") from e


def generate_mac_data(nonce: bytes, encrypted_message: bytes, message_public_key: bytes, mac_key: bytes) -> bytes:
    if len(mac_key) != 32:
        raise ValueError("MAC key must be 32 bytes long.")

    # Concatenate nonce, message public key, and encrypted message
    data_to_mac = bytes_concat(nonce, message_public_key, encrypted_message)

    # Generate HMAC-SHA256
    mac_data = hmac.new(
        key=mac_key,
        msg=data_to_mac,
        digestmod=hashlib.sha256).digest()
    return mac_data


def bytes_concat(*arrays) -> bytes:
    """
    Concatenate multiple byte arrays into a single byte array.

    Args:
        *arrays: Variable length argument list of byte arrays to concatenate.

    Returns:
        bytes: A single concatenated byte array.
    """
    return b''.join(arrays)


def message_to_bytes(value):
    if isinstance(value, (bytes, bytearray)):
        return value
    elif isinstance(value, str):
        return value.encode('utf-8')
    else:
        raise TypeError("Unsupported message type for encryption")