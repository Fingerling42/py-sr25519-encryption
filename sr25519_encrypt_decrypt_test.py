from substrateinterface import Keypair, KeypairType
from sr25519_ecies_encrypt import sr25519_encrypt

sender_mnemonic = ''
receiver_mnemonic = ''

sender_keypair: Keypair = Keypair.create_from_mnemonic(
            mnemonic=sender_mnemonic,
            crypto_type=KeypairType.SR25519
        )

receiver_keypair: Keypair = Keypair.create_from_mnemonic(
            mnemonic=receiver_mnemonic,
            crypto_type=KeypairType.SR25519
        )

test_message_string = 'This is the test message'
test_message_bytes = bytes('Some bytes', 'utf-8')


encrypted_string = sr25519_encrypt(test_message_string, receiver_keypair.public_key, sender_keypair)
print(encrypted_string.hex())

encrypted_bytes = sr25519_encrypt(test_message_bytes, receiver_keypair.public_key, sender_keypair)
print(encrypted_bytes.hex())
