from itertools import product
from Crypto.Cipher import DES
from binascii import hexlify, unhexlify


def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)  # ECB mode is used for simplicity
    print("Encrypt with key")
    print(key)
    return cipher.encrypt(plaintext)

def des_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    print("Decryption with key:")
    print("key")
    return cipher.decrypt(ciphertext)

def complement(data):
    return bytes([b ^ 0xFF for b in data]) 

def generate_half_keys():
    # Generate half of the possible 8-byte keys (with the least significant bit set to 0)
    for key_tuple in product(range(256), repeat=7):
        yield bytes(list(key_tuple) + [0])
    print("Keys produced")
def find_key(P1, T1, P2, T2):
    for key in generate_half_keys():
        if des_encrypt(P1, key) == T1:
            return key
        elif des_encrypt(P1, key) == T2:
            return complement(key)
    return None

# Example
key = b'12345670'  # 8-byte key for DES with the least significant bit set to 0
P1 = b'ABCDEFGH'
T1 = des_encrypt(P1, key)

P2 = complement(P1)
T2 = des_encrypt(P2, key)

# Try to find the key using the cryptanalysis method
found_key = find_key(P1, T1, P2, T2)

print(f"Original Key: {hexlify(key).decode()}")
print(f"Found Key: {hexlify(found_key).decode()}")
