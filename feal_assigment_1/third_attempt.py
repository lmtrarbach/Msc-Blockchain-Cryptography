import numpy as np
import random


ROUNDS = 4

class CryptanalysisFEAL:
    def __init__(self):
        self.decrypted_keys_hex = []
        self.decrypted_keys = []

    def function_feal_G0_and_G1(self, a, b, add_constant):
        result = (a + b + add_constant) % 256
        print(f'GBox output:{result}')
        return np.left_shift(result, 2) | np.right_shift(result, 6)

    def bytes_to_word32(self, byte_array):
        return np.uint32(byte_array[0] << 24 | byte_array[1] << 16 | byte_array[2] << 8 | byte_array[3])

    def word32_to_bytes(self, word32, byte_array):
        byte_array = [0, 0, 0, 0]
        byte_array[0] = np.uint8(word32 >> 24)
        byte_array[1] = np.uint8((word32 >> 16) & 0xFF)
        byte_array[2] = np.uint8((word32 >> 8) & 0xFF)
        byte_array[3] = np.uint8(word32 & 0xFF)
        return byte_array

    def function_f(self, input_word32):
        x = np.zeros(4, dtype=np.uint8)
        y = np.zeros(4, dtype=np.uint8)
        self.word32_to_bytes(input_word32, x)
        y[1] = self.function_feal_G0_and_G1(x[1] ^ x[0], x[2] ^ x[3], 1)
        y[0] = self.function_feal_G0_and_G1(x[0], y[1], 0)
        y[2] = self.function_feal_G0_and_G1(y[1], x[2] ^ x[3], 0)
        y[3] = self.function_feal_G0_and_G1(y[2], x[3], 1)
        return self.bytes_to_word32(y)

    def feal_encrypt(self, data):
        data = np.array(data, dtype=np.uint8)
        key = np.array(self.key, dtype=np.uint32)
        left = self.bytes_to_word32(data[:4])
        right = left ^ self.bytes_to_word32(data[4:])
        for i in range(ROUNDS):
            temp = right
            right = left ^ self.function_f(right ^ key[i])
            left = temp
        temp = left
        left = right ^ key[4]
        right = temp ^ right ^ key[5]
        encrypted_left = self.word32_to_bytes(left, data[:4])
        encrypted_right = self.word32_to_bytes(right, data[4:])
        return encrypted_left + encrypted_right

    def feal_decrypt(self, data):
        data = np.array(data, dtype=np.uint8)
        key = np.array(self.key, dtype=np.uint32)
        right = self.bytes_to_word32(data[:4]) ^ key[4]
        left = right ^ self.bytes_to_word32(data[4:]) ^ key[5]
        for round in range(ROUNDS):
            print(f'Executing round {round} key slice {key[ROUNDS - 1 - round]}')
            temp = left
            print(f'data slice {data[4:]}')
            left = right ^ self.function_f(left ^ key[ROUNDS - 1 - round])
            right = temp
            print(f'left after f round:{left}')
            print(f'right after f round:{right}')

        right ^= left
        decrypted_left = self.word32_to_bytes(left, [0, 0, 0, 0])
        decrypted_right = self.word32_to_bytes(right, [0, 0, 0, 0])
        print(f'decrypted_left:{decrypted_left}')
        print(f'decrypted_right:{decrypted_right}')
        return decrypted_left + decrypted_right,key
    
    def cryptanalysis_test_keys(self, data, key):
        self.key = key
        data_length = len(data)
        i = 0
        while i < data_length:
            plaintext_line = data[i]
            ciphertext_line = data[i + 1]
            plaintext_hex = plaintext_line[1]
            ciphertext_hex = ciphertext_line[1]
            plaintext = list(bytearray.fromhex(plaintext_hex))
            encrypted_ciphertext = self.feal_encrypt(plaintext)
            decrypted_plaintext, key = self.feal_decrypt(encrypted_ciphertext)
            decrypted_plaintext_hex = ''.join([f'{x:02X}' for x in decrypted_plaintext])
            print(f'Decrypted on code in hex {decrypted_plaintext_hex}')
            print(f'Original plaintext {plaintext_hex}')
            print(f'Keys {key}')
            if decrypted_plaintext == plaintext:
                self.decrypted_keys_hex.append(decrypted_plaintext_hex)
                self.decrypted_keys.append(key)
                print("Encryption and Decryption Successful")
                print(f'{plaintext_hex}:{decrypted_plaintext_hex} with subkey {key}')
            else:
                print("Encryption and Decryption Failed")
            i += 2

    def linear_cryptanalysis(self, data):  
        data_length = len(data)
        self.keys_found = []
        while len(self.keys_found) < 1:
            key_guess = random.randint(0, 255)
            i = 0
            while i < data_length:
                plaintext_line = int.from_bytes(list(bytearray.fromhex(data[i][1])), byteorder='big')
                ciphertext_line = int.from_bytes(list(bytearray.fromhex(data[i + 1][1]) ),byteorder='big')
                equation = (plaintext_line ^ key_guess) & 0x0F
                print(f'equation: {equation}')
                print(f'ciphertext_line {ciphertext_line}')
                if equation == ciphertext_line & 0x0F:
                    print(f'Found key {key_guess}')
                    print(f'{plaintext_line}:{ciphertext_line}')
                    self.keys_found.append(key_guess)
                i += 2


if __name__ == "__main__":
    data = np.loadtxt("know.txt", dtype=str, unpack=False)
    
    
    # Zero for sure is one key
    initial_key = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    
    cryptanalysis = CryptanalysisFEAL()
    cryptanalysis.linear_cryptanalysis(data)
    cryptanalysis.cryptanalysis_test_keys(data, initial_key) 
   
    if len(cryptanalysis.keys_found) > 0:
        cryptanalysis.cryptanalysis_test_keys(data, cryptanalysis.keys_found)

    keys =np.unique(np.array(cryptanalysis.decrypted_keys_hex))
    if len(keys) > 0:
        print(f'Keys found: {len(keys)}')
        
        

    
    

