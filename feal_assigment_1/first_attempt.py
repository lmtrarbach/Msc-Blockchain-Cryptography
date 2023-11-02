import numpy as np

ROUNDS = 4

def rotate_left_2_bits(x):
    """
    Rotate an 8-bit value to the left by 2 bits.
    
    Args:
        x (int): The 8-bit input value.

    Returns:
        int: The result of the left rotation by 2 bits.
    """
    return ((x << 2) | (x >> 6)) & 0xFF

def feal_g0(a, b):
    """
    Perform a + B and executes left rotation

    Args:
        a (int): 8-bit input.
        b (int): 8-bit input.

    Returns:
        int: The result of the G0 operation.
    """
    return rotate_left_2_bits((a + b) & 0xFF)

def feal_g1(a, b):
    """
    Perform the G1 operation same thing as G0, why is used like that? Replace it with one function Review it before deliver

    Args:
        a (int): 8-bit input.
        b (int): 8-bit input.

    Returns:
        int: The result of the G1 operation.
    """
    return rotate_left_2_bits((a + b + 1) & 0xFF)

def pack_bytes_to_word32(byte_array):
    """
    Pack 4 bytes into a 32-bit word (unsigned integer).

    Args:
        byte_array (list[int]): A list of 4 bytes.

    Returns:
        int: The 32-bit word.
    """
    return (byte_array[3] | (byte_array[2] << 8) | (byte_array[1] << 16) | (byte_array[0] << 24)) & 0xFFFFFFFF

def unpack_word32_to_bytes(word32, byte_array):
    """
    Unpack a 32-bit word into 4 bytes.

    Args:
        word32 (int): The 32-bit word.
        byte_array (list[int]): A list to store the 4 bytes.
    """
    byte_array[0] = (word32 >> 24) & 0xFF
    byte_array[1] = (word32 >> 16) & 0xFF
    byte_array[2] = (word32 >> 8) & 0xFF
    byte_array[3] = word32 & 0xFF

def feal_f(input_word32):
    """
    Implement the 'F' function of the FEAL cipher.

    Args:
        input_word32 (int): The 32-bit input.

    Returns:
        int: The result of the 'F' function.
    """
    x = [0] * 4
    y = [0] * 4
    unpack_word32_to_bytes(input_word32, x)
    y[1] = feal_g1(x[1] ^ x[0], x[2] ^ x[3])
    y[0] = feal_g0(x[0], y[1])
    y[2] = feal_g0(y[1], x[2] ^ x[3])
    y[3] = feal_g1(y[2], x[3])
    return pack_bytes_to_word32(y)

def feal_encrypt(data, key):
    """
    Encrypt an 8-byte block of data using the FEAL cipher.

    Args:
        data list[int]: The plaintext data in 8 bytes
        key list[int]: The list of 6 keys 32-bit

    Returns:
        None
    """
    left = pack_bytes_to_word32(data[:4])
    right = left ^ pack_bytes_to_word32(data[4:])

    for i in range(ROUNDS):
        temp = right
        right = left ^ feal_f(right ^ key[i])
        left = temp

    temp = left
    left = right ^ key[4]
    right = temp ^ right ^ key[5]

    unpack_word32_to_bytes(left, data[:4])
    unpack_word32_to_bytes(right, data[4:])

def feal_decrypt(data, key):
    """
    Decrypt an 8-byte block of data encrypted with the FEAL cipher.

    Args:
        data list[int]: ciphertext data 8 bytes
        key (list[int]): list of 6 keys 32-bit

    Returns:
        None
    """
    right = pack_bytes_to_word32(data[:4]) ^ key[4]
    left = right ^ pack_bytes_to_word32(data[4:]) ^ key[5]

    for i in range(ROUNDS):
        temp = left
        left = right ^ feal_f(left ^ key[ROUNDS - 1 - i])
        right = temp

    right ^= left

    unpack_word32_to_bytes(left, data[:4])
    unpack_word32_to_bytes(right, data[4:])

if __name__ == "__main__":
    key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
    data = 'a7f1d92a82c8d8fe'

    ciphertext = feal_encrypt(data, key)
    plaintext = feal_decrypt(ciphertext, key)
    print(f'Plaintext: {plaintext} and ciphertext: {ciphertext} key: {key}')
