import numpy as np
from multiprocessing import Pool, cpu_count

class CryptanalysisFEAL:
    def __init__(self, data, process_per_core, bias_margin):
        self.k0_candidates = set()
        self.data = data
        self.bias = 200 - bias_margin
        self.process_per_core = process_per_core

    def F(self, x0, x1, x2, x3):
        """
        Receives the specific bits for the key
        Execute the G0 and G1 and returns as int32

        Input:
            x0, x1, x2, x3 np.uint8 of specific bits
        Return: 
            y0, y1, y2, y3 as single np.uint32

        """
        def G0(a, b):
            """
            Apply module of the sum of a + b as for example G0(x0, x1)

            Input:
                a, b np.uint8
            Return:
                shift lef or shift right of a bitwise OR
                
            """
            result = ((a + b) % 256)
            return result << 2 | result >> 6
        
        def G1(a, b):
            result = ((a + b + 1) % 256)
            return result << 2 | result >> 6

        y0 = G0(x0, x1) & 0xFF
        y1 = G1(x0 ^ x1, x2 ^ x3) & 0xFF
        y2 = G0(y1, x2 ^ x3) & 0xFF
        y3 = G1(y2, x3) & 0xFF

        return np.int32(y3 & 1 << 24 | y2 & 1 << 16 | y3 & 1  << 8 | y0 & 1)

    def calculate_a(self, K0, plaintext, ciphertext):
        """
        Function calculate the value of a for the equation

        """
        # Extract L0, R0, L4, and R4
        
        L0 = int.from_bytes(list(bytearray.fromhex(plaintext[:8])), byteorder='big')
        R0 = int.from_bytes(list(bytearray.fromhex(plaintext[8:] )), byteorder='big')
        L4 = int.from_bytes(list(bytearray.fromhex(ciphertext[:8])), byteorder='big')
        R4 = int.from_bytes(list(bytearray.fromhex(ciphertext[:8])), byteorder='big')
        KEY = K0 & 0xFF
        L0_XOR_R0 =  np.bitwise_xor(L0, R0)
        L4_XOR_R4 = np.bitwise_xor(L4, R4)
        
        xor_result = np.bitwise_xor(KEY, L0_XOR_R0) 

        x0 =  (xor_result >> 24) & 0xFF
        x1 =  (xor_result >> 16) & 0xFF
        x2 =  (xor_result >> 8)  & 0xFF
        x3 =  xor_result & 0xFF
        s_29 = (np.bitwise_xor(L0_XOR_R0, L4) >> 8) & 1
        s_23 = (np.bitwise_xor( L0_XOR_R0, L4) >> 2) & 1
        s_23_29 =  np.bitwise_xor(s_23 , s_29)
        s_31 =  np.bitwise_xor(L0 , L4_XOR_R4) & 1
        s_31_f_round = (self.F(x0,x1,x2, x3)) & 1 
        s_23_29_XOR_s_31 =  np.bitwise_xor(s_23_29 , s_31) 
        a =  np.bitwise_xor(s_23_29_XOR_s_31,  s_31_f_round)
        return a
    
    def test_key_range(self, start_key_end_key):
        start_key, end_key = start_key_end_key
        keys = np.arange(start_key, end_key, dtype='int32')
        for K0 in keys:
            count = [0, 0]
            for d in self.data:
                a = self.calculate_a(K0, d["plaintext"], d["ciphertext"])
                count[a] += 1
                print(f'Key {K0} count:{count}')
                #if count[0] > 10 and count[1] > 10:
                #    break
                if count[0] > self.bias or count[1] > self.bias:
                    print(f'Found key {K0 & 0xFF} count:{count}')
                    print(f'Adding key: {K0 & 0xFF} to Queue')
                    self.k0_candidates.add(K0 & 0xFF)
                    break

    def linear_cryptanalysis_multiprocessing(self):
        key_range = (2 ** 32) - 1
        process_chunks = cpu_count() * 4
        chunk_size = key_range // process_chunks
        ranges = [(i * chunk_size, (i + 1) * chunk_size) for i in range(process_chunks)]

        with Pool(processes=cpu_count()) as pool:
            pool.map(self.test_key_range, ranges)