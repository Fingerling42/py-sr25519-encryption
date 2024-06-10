from substrateinterface import Keypair, KeypairType
from sr25519_ecies_encrypt import sr25519_encrypt
from sr25519_ecies_decrypt import sr25519_decrypt

sender_mnemonic = 'regular among cause gloom else session rifle absorb humor owner awful zebra'
receiver_mnemonic = 'intact eight crunch slogan stairs coin odor pudding cushion waste electric raw'

sender_keypair: Keypair = Keypair.create_from_mnemonic(
    mnemonic=sender_mnemonic,
    crypto_type=KeypairType.SR25519
)

print('Sender public key:', sender_keypair.public_key.hex())

receiver_keypair: Keypair = Keypair.create_from_mnemonic(
    mnemonic=receiver_mnemonic,
    crypto_type=KeypairType.SR25519
)

test_message_string = 'This is the test message'
test_message_bytes = bytes('Some bytes', 'utf-8')

# Encrypt string message with sender keypair
encrypted_string = sr25519_encrypt(test_message_string, receiver_keypair.public_key, sender_keypair)
print('Encrypted string:', encrypted_string.hex())

# Encrypt byte message with ephemeral keypair
encrypted_bytes = sr25519_encrypt(test_message_bytes, receiver_keypair.public_key)
print('Encrypted bytes:', encrypted_bytes.hex())

# Decrypt string
decrypted_string, message_public_key = sr25519_decrypt(encrypted_string, receiver_keypair.private_key)
print('Public key of message:', message_public_key.hex())
print('Decrypted string:', decrypted_string.decode())

# Decrypt bytes
decrypted_bytes, message_public_key = sr25519_decrypt(encrypted_bytes, receiver_keypair.private_key)
print('Decrypted bytes:', decrypted_bytes.decode())