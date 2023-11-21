import numpy as np

class CryptanalysisFEAL:
    def __init__(self):
        self.k0_candidate = set()

    def F(self, x0, x1, x2, x3):
        def G0(a, b):
            result = ((a + b) % 256)
            return np.left_shift(result, 2) | np.right_shift(result, 6)
        
        def G1(a, b):
            result = ((a + b + 1) % 256)
            return np.left_shift(result, 2) | np.right_shift(result, 6)

        y0 = G0(x0, x1)
        y1 = G1(x0 ^ x1, x2 ^ x3)
        y2 = G0(y1, x2 ^ x3)
        y3 = G1(y2, x3)

        return np.uint32(y3 << 24 | y1 << 16 | y2 << 8 | y3)

    def calculate_a(self, K0, plaintext, ciphertext):
        L0 = int.from_bytes(bytes.fromhex(plaintext[:8]), byteorder='big')
        R0 = int.from_bytes(bytes.fromhex(plaintext[8:]), byteorder='big')
        L4 = int.from_bytes(bytes.fromhex(ciphertext[:8]), byteorder='big')
        R4 = int.from_bytes(bytes.fromhex(ciphertext[8:]), byteorder='big')
        s_23_29 = (L0 ^ R0 ^ L4) & 1
        s_31 = (L0 ^ L4 ^ R4) & 1
        xor_result = L0 ^ R0 ^ K0
        x0 = xor_result & 0xFF      
        x1 = (xor_result >> 8) & 0xFF 
        x2 = (xor_result >> 16) & 0xFF
        x3 = (xor_result >> 24) & 0xFF
        s_31_f_round = self.F(x0,x1,x2, x3) & 1
        a = (s_23_29 ^ s_31 ^ s_31_f_round)
        return a

    def linear_cryptanalysis_single_thread(self, data):
        bias = len(data) - 10
        keys = np.arange(0, 2 ** 28)
        for K0 in keys:
            key = K0 & 0xFFFFFFFF
            print(f'Key: {key}')
            count = [0, 0]
            for d in data:
                a = self.calculate_a(key , d["plaintext"], d["ciphertext"])
                count[a] += 1
                if count[0] > 30 and count[1] > 30:
                    break
                if count[0] == bias or count[1] == bias:
                    print(f'Found key {key}')
                    self.k0_candidate.add(key)
                    break
                if key == 0:
                    break



