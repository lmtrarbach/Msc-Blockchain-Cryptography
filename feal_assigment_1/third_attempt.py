import numpy as np

ROUNDS = 4

class InitialApproximation:
    def __init__(self, key, bias):
        self.key = key 
        self.bias = bias

class WeightedApproximation:
    def __init__(self, a, log2_bias):
        self.approximation = a
        self.log2_bias = log2_bias
        self.bias = 2 ** log2_bias
        self.transmitted_bits = 1 + a.transmitted_bits

    def key(self):
        return self.approximation.key()

    def generate_round_approximations(self):
        a = self.approximation
        a.generate_weighted_one_round_approximations(self.transmitted_bits)
        result = []
        for o in a.weighted_approximations:
            transmitted_bits = self.transmitted_bits + o.transmitted_bits
            if transmitted_bits <= 6:
                w = WeightedApproximation(a, self.log2_bias + o.log2_bias)
                w.transmitted_bits = transmitted_bits
                result.append(w)
        return result

class CryptanalysisFEAL:
    def __init__(self, key, initial_approximation):
        self.key = key
        self.decrypted_keys = []
        self.initial_approximation = initial_approximation

    def function_feal_G0_and_G1(self, a, b, add_constant):
        result = (a + b + add_constant) % 256
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
        for i in range(ROUNDS):
            temp = left
            left = right ^ self.function_f(left ^ key[ROUNDS - 1 - i])
            right = temp
        right ^= left
        decrypted_left = self.word32_to_bytes(left, [0, 0, 0, 0])
        decrypted_right = self.word32_to_bytes(right, [0, 0, 0, 0])
        return decrypted_left + decrypted_right
    
    def best_initial_approximation(self):
        if self.initial_approximation:
            return WeightedApproximation(self.initial_approximation, 0)
        else:
            return None


    def cryptanalyze(self, data):
        queue = []
        seen = {}
        data_length = len(data)
        i = 0
        while i < data_length:
            plaintext_line = data[i]
            ciphertext_line = data[i + 1]
            plaintext_hex = plaintext_line[1]
            ciphertext_hex = ciphertext_line[1]
            plaintext = list(bytearray.fromhex(plaintext_hex))
            encrypted_ciphertext = self.feal_encrypt(plaintext)
            decrypted_plaintext = self.feal_decrypt(encrypted_ciphertext)
            if decrypted_plaintext == plaintext:
                self.decrypted_keys.append(f'{ciphertext_hex}:{decrypted_plaintext}')
                print("Encryption and Decryption Successful")
                print(f'{ciphertext_hex}:{decrypted_plaintext}')
            else:
                print("Encryption and Decryption Failed")
            i += 2

        while queue:
            v = min(queue, key=lambda x: x[1])
            queue.remove(v)
            v = v[0]
            seen[v] = True
            for w in v.generate_round_approximations():
                if w.key() not in seen:
                    queue.append(w)
        return min(queue, key=lambda x: x[1])

if __name__ == "__main__":
    data = np.loadtxt("know.txt", dtype=str, unpack=False)
    key = [0x1, 0x3, 0x7, 0x9, 0x11, 0x13]
    
   
    initial_approximation = InitialApproximation(key=[0, 0, 0, 0], bias=0.1)
    
    cryptanalysis = CryptanalysisFEAL(key, initial_approximation)
    best_approximation = cryptanalysis.cryptanalyze(data) 
    print('Decrypted keys:', cryptanalysis.decrypted_keys)
    print('Best approximation:', best_approximation)
