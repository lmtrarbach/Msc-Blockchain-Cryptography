import numpy as np
from multiprocessing import Pool, cpu_count,Manager
import typing
import time

class CryptanalysisFEAL:
    def __init__(self, data, output_file, bias, statistics, key_range):
        self.output_file = output_file
        self.statistics = statistics
        manager = Manager()
        self.k0_candidate = manager.list()
        self.array_range = key_range
        self.bias = 200 * (bias/100)
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
        t0 = time.time()
        start_key, end_key = start_key_end_key
        print(f'Starting from range: {start_key} to {end_key}')
        keys_range = np.arange(start_key, end_key, dtype='int32')
        result = [self.count_ones_zeros(key) for key in keys_range]
        result = [each for each in result if each is not 0]
        if len(result) > 0:
            for each in result:
                self.k0_candidate.append(each)
        t1 = time.time()
        total = t1-t0
        print(f'Finished to process from range: {start_key} to {end_key} in {total} seconds')
                        
    @typing.no_type_check
    def count_ones_zeros(self, key):
        """
        Execute the a calculations as per Mark Stamps formula.
        If statistics is enabled provide statistics of the a values
        """
        KEY = key
        xor_result = np.bitwise_xor(self.L0_XOR_R0, KEY)  
        x0 = xor_result     
        x1 = (xor_result >> 8) & 0xFF
        x2 = (xor_result >> 16) & 0xFF
        x3 = (xor_result >> 24) & 0xFF
        s_31_f_round = self.F(x0, x1, x2, x3) & 1
        a = np.bitwise_xor(self.s_23_29_s_31,s_31_f_round)
        ones = np.count_nonzero(a == 1)
        zeros = np.count_nonzero(a == 0)
        print(ones, 'and', zeros)
        if self.statistics:
            ones_mean = np.mean(ones)
            zeros_mean = np.mean(zeros)
            ones_std = np.std(ones)
            zeros_std = np.std(zeros)
            ones_max = np.max(ones)
            zeros_max = np.max(zeros)
            print(f'key:{key} ones_mean: {ones_mean} ones_std: {ones_std} zeros_mean: {zeros_mean} \n' 
                  f' zeros_std:{zeros_std} ones_max: {ones_max} zeros_max: {zeros_max} \n')
        if (ones > self.bias) or (zeros > self.bias):
            print(f'Possible key at: ones:{ones} zeros:{zeros} key:{key}')
            return key
        return 0
    
    def linear_cryptanalysis_multiprocess(self):

        key_range =  self.array_range
        process_chunks = cpu_count() * 4
        chunk_size = key_range // process_chunks
        ranges = [(i * chunk_size, (i + 1) * chunk_size) for i in range(process_chunks)]

        with Pool(processes=cpu_count()) as pool:
            pool.map(self.workers, ranges)
            pool.close()
            pool.join()
            print(f'All keys finished from 0 to {self.array_range}')





