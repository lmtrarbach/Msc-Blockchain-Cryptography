import numpy as np

print(np.get_include())
class CryptanalysisFEAL:
    def __init__(self, data):
        self.k0_candidate = set()
        self.array_range = (2 ** 32) - 1  
        self.chunk_size = 28000000
        self.bias = 200 - 1
        self.data = data
        self.L0 = np.array([int(pair["plaintext"][:8], 16) for pair in self.data], dtype=np.uint32)
        self.R0 = np.array([int(pair["plaintext"][8:], 16) for pair in self.data], dtype=np.uint32)
        self.L4 = np.array([int(pair["ciphertext"][:8], 16) for pair in self.data], dtype=np.uint32)
        self.R4 = np.array([int(pair["ciphertext"][8:], 16) for pair in self.data], dtype=np.uint32)
        self.L0_XOR_R0 =  np.bitwise_xor(self.L0, self.R0)
        self.L4_XOR_R4 = np.bitwise_xor(self.L4, self.R4)
        self.s_23 = np.array(np.bitwise_xor(self.L0_XOR_R0, self.L4 ) >>  2)
        self.s_29 = np.array(np.bitwise_xor(self.L0_XOR_R0, self.L4 ) >> 8)
        self.s_23_29 = np.array(np.bitwise_xor(self.s_23,  self.s_29))
        self.s_31 = np.array(np.bitwise_xor(self.L4_XOR_R4,self.L0))
        self.s_23_29_s_31 = np.array(np.bitwise_xor(self.s_23_29, self.s_31))

        print('Xor of s_23_29_s_31:',self.s_23_29_s_31)
        del data, self.data, self.L4, self.R4

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

        return np.uint32(y3 << 24 | y2 << 16 | y3 << 8 | y0)

    
    def linear_cryptanalysis_multiprocess(self):
        def count_ones_zeros(key):
            KEY = key & 0xFF
            xor_result = np.bitwise_xor(KEY, self.L0_XOR_R0)      
            x0 = xor_result & 0xFF      
            x1 = (xor_result >> 8) & 0xFF 
            x2 = (xor_result >> 16) & 0xFF
            x3 = (xor_result >> 24) & 0xFF
            s_31_f_round = self.F(x0, x1, x2, x3)
            a = np.bitwise_xor(self.s_23_29_s_31,s_31_f_round) & 1
            ones = np.count_nonzero(a == 1)
            zeros = np.count_nonzero(a == 0)
            if (ones > self.bias) or (zeros > self.bias):
                print(f'Possible key at: ones:{ones} zeros:{zeros} key:{key}')
                return key

        array_range = np.arange(0, self.array_range, self.chunk_size, dtype='int32')
        for index in range(len(array_range) - 1): 
            elem = array_range[index]
            next_elem = array_range[index + 1]
            print(f'Starting from range: {elem}')
            keys_range = np.arange(elem, next_elem, dtype='int32') 
            result = [count_ones_zeros(key) for key in keys_range]
            result = result[result is not None]
            if result:
                for each in result:
                    self.k0_candidate.add(result)
            with open("found_keys.txt", mode='+a') as file_keys:
                for each in self.k0_candidate:
                    file_keys.write(f'{each}\n')
        print(f'All keys finished from 0 to {self.array_range}')

