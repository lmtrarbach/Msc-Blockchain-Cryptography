import numpy as np

ROUNDS = 4

def function_feal_G0_and_G1(a, b, add_constant):
    """
    http://theamazingking.com/crypto-feal.php#:~:text=help%20a%20lot.-,Round%20Function,-The%20round%20function
    Perform the G0 or G1 operations
        Testing python Overload operator
    Args:
        a uint8: 8 bit 
        b uint8: 8 bit 
        add_constant uint8 Need to understand why need constant.

    Returns:
        uint8
    """
    result = (a + b + add_constant) % 256
    return np.left_shift(result, 2) | np.right_shift(result, 6)

def bytes_to_word32(byte_array):
    """
    4 bytes into a 32 bit word  like unsigned integer.

    Args:
        byte_array list[int]:  4 bytes list

    Returns:
        uint32: 32 bit
    """
    return np.uint32(byte_array[0] << 24 | byte_array[1] << 16 | byte_array[2] << 8 | byte_array[3])

def word32_to_bytes(word32, byte_array):
    """
    32-bit word into 4 bytes.

    Args:
        word32 uint32: 32-bit
        byte_array: list: 4 bytes.
    """
    byte_array = [0, 0, 0, 0]  # Initialize a list to store the bytes
    byte_array[0] = np.uint8(word32 >> 24)
    byte_array[1] = np.uint8((word32 >> 16) & 0xFF)
    byte_array[2] = np.uint8((word32 >> 8) & 0xFF)
    byte_array[3] = np.uint8(word32 & 0xFF)
    return byte_array

def function_f(input_word32):
    """
    F function of the FEAL
    http://theamazingking.com/crypto-feal.php#:~:text=the%20G%20function.-,Differential%20Basics,-Now%20its%20time

    Args:
        input_word32 uint32: 32 bit input

    Returns:
        uint32: result 
    """
    x = np.zeros(4, dtype=np.uint8)
    y = np.zeros(4, dtype=np.uint8)
    word32_to_bytes(input_word32, x)
    y[1] = function_feal_G0_and_G1(x[1] ^ x[0], x[2] ^ x[3], 1)
    y[0] = function_feal_G0_and_G1(x[0], y[1], 0)
    y[2] = function_feal_G0_and_G1(y[1], x[2] ^ x[3], 0)
    y[3] = function_feal_G0_and_G1(y[2], x[3], 1)
    return bytes_to_word32(y)

def feal_encrypt(data, key):
    """
    Encrypt data using the cipher.

    Args:
        data list: data 8 bytes
        key list: list of 6 keys 32-bit

    Returns:
        None
    """
    data = np.array(data, dtype=np.uint8)
    key = np.array(key, dtype=np.uint32)

    left = bytes_to_word32(data[:4])
    right = left ^ bytes_to_word32(data[4:])

    for i in range(ROUNDS):
        temp = right
        right = left ^ function_f(right ^ key[i])
        left = temp

    temp = left
    left = right ^ key[4]
    right = temp ^ right ^ key[5]

    encrypted_left = word32_to_bytes(left, data[:4])
    encrypted_right = word32_to_bytes(right, data[4:])
    return encrypted_left + encrypted_right
   

def feal_decrypt(data, key):
    """
    Decrypt of data encrypted

    Args:
        data list: ciphertext 8 bytes
        key list: 6 keys 32 bit

    Returns:
        None
    """
    data = np.array(data, dtype=np.uint8)
    key = np.array(key, dtype=np.uint32)

    right = bytes_to_word32(data[:4]) ^ key[4]
    left = right ^ bytes_to_word32(data[4:]) ^ key[5]

    for i in range(ROUNDS):
        temp = left
        left = right ^ function_f(left ^ key[ROUNDS - 1 - i])
        right = temp

    right ^= left

    decrypted_left = word32_to_bytes(left,[0, 0, 0, 0])
    decrypted_right = word32_to_bytes(right, [0, 0, 0, 0])

    return decrypted_left + decrypted_right


data = np.loadtxt("know.txt", dtype=str, unpack=False)
key = [0x0, 0x00, 0x08080, 0x8080, 0x11, 0x13]
i = 0
decrypted_keys = []
intersects = []
while i < len(data):

    plaintext_line = data[i]
    ciphertext_line = data[i + 1]
    # Extract the hexadecimal values from the lines
    plaintext_hex = plaintext_line[1]
    ciphertext_hex = ciphertext_line[1]
    
    plaintext = list(bytearray.fromhex(plaintext_hex))

    # Encrypt the data
    feal_encrypt(plaintext, key)
    ciphertext_array = list(bytearray.fromhex(ciphertext_hex))
    print("Cyphertext from file:", list(bytearray.fromhex(ciphertext_hex)))
    encrypted_ciphertext = feal_encrypt(plaintext, key)
    print("Encrypted Ciphertext", encrypted_ciphertext)
    # Decrypt the data
    decrypted_plaintext = feal_decrypt(ciphertext_array, key)
    print("Decrypted: ", decrypted_plaintext)

    if decrypted_plaintext == ciphertext_array:
        decrypted_keys.append(f'{ciphertext_hex}:{decrypted_plaintext}')
        print("Encryption and Decryption Successful")
    else:
        print("Encryption and Decryption Failed")
    i += 2

print('Decrypted keys:', decrypted_keys)