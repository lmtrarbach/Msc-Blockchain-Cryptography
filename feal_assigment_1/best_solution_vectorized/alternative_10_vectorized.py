import numpy as np
from multiprocessing import Pool, cpu_count,set_start_method
class CryptanalysisFEAL:
    def __init__(self, data, output_file, bias, statistics):
        self.output_file = output_file
        self.statistics = statistics
        self.k0_candidate = set()
        self.array_range = (2 ** 32) - 1 
        self.bias = 200 - bias
        self.data = data
        self.L0 = np.array([int(pair["plaintext"][:8], 16) for pair in self.data], dtype=np.uint32)
        self.R0 = np.array([int(pair["plaintext"][8:], 16) for pair in self.data], dtype=np.uint32)
        self.L4 = np.array([int(pair["ciphertext"][:8], 16) for pair in self.data], dtype=np.uint32)
        self.R4 = np.array([int(pair["ciphertext"][8:], 16) for pair in self.data], dtype=np.uint32)
        self.L0_XOR_R0 = np.array([np.bitwise_xor(self.L0, self.R0)])
        self.L4_XOR_R4 = np.array([np.bitwise_xor(self.L4, self.R4)])
        self.s_23 = np.array(np.bitwise_xor(self.L0_XOR_R0, self.L4 ) >>  2) & 1
        self.s_29 = np.array(np.bitwise_xor(self.L0_XOR_R0, self.L4 ) >> 8) & 1
        self.s_23_29 = np.array(np.bitwise_xor(self.s_23,  self.s_29))
        self.s_31 = np.array(np.bitwise_xor(self.L4_XOR_R4,self.L0)) & 1
        self.s_23_29_s_31 = np.array(np.bitwise_xor(self.s_23_29, self.s_31))
        del data, self.data, self.L4, self.R4

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

        y0 = G0(x0, x1)
        y1 = G1(x0 ^ x1, x2 ^ x3)
        y2 = G0(y1, x2 ^ x3) 
        y3 = G1(y2, x3)

        return np.int32(y3 << 24 | y2 << 16 | y3 << 8 | y0 )
    
    def workers(self, start_key_end_key):
        """
        Loop thought the range of keys and get the results
        """
        start_key, end_key = start_key_end_key
        print(f'Starting from range: {start_key} to {end_key}')
        keys_range = np.arange(start_key, end_key, dtype='int32') 
        result = np.array([self.count_ones_zeros(key) for key in keys_range])
        result = [each for each in result if each is not None]
        if len(result) > 0:
            for each in result:
                self.k0_candidate.add(each)
        with open(self.output_file, mode='a') as file_keys:
            for each_key in self.k0_candidate:
                        print(f'Adding key {each_key} to records ')
                        file_keys.write(each_key)
                        file_keys.write('\n')

    def count_ones_zeros(self, key):
        """
        Execute the a calculations as per Mark Stamps formula.
        If statistics is enabled provide statistics of the a values
        """
        KEY = key & 0xFF 
        xor_result = np.bitwise_xor(KEY, self.L0_XOR_R0)  
        x0 = xor_result  & 0xFF     
        x1 = (xor_result >> 8)  & 0xFF
        x2 = (xor_result >> 16)  & 0xFF
        x3 = (xor_result >> 24)  & 0xFF
        s_31_f_round = self.F(x0, x1, x2, x3)
        a = np.bitwise_xor(self.s_23_29_s_31,s_31_f_round) & 1
        ones = np.count_nonzero(a == 1)
        zeros = np.count_nonzero(a == 0)
        ones_mean = np.mean(ones)
        zeros_mean = np.mean(zeros)
        ones_std = np.std(ones)
        zeros_std = np.std(zeros)
        print(f'key:{key} ones_mean: {ones_mean} ones_std: {ones_std} zeros_mean: {zeros_mean} zeros_std:{zeros_std}')
        if (ones > self.bias) or (zeros > self.bias):
            print(f'Possible key at: ones:{ones} zeros:{zeros} key:{key}')
            return key
    
    def linear_cryptanalysis_multiprocess(self):

        key_range =  self.array_range
        process_chunks = cpu_count() * 2
        chunk_size = key_range // process_chunks
        ranges = [(i * chunk_size, (i + 1) * chunk_size) for i in range(process_chunks)]

        with Pool(processes=cpu_count()) as pool:
            pool.map(self.workers, ranges)
        print(f'All keys finished from 0 to {self.array_range}')


