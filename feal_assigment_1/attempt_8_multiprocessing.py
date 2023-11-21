import numpy as np
import multiprocessing

class CryptanalysisFEAL:    
    def __init__(self, data, pool):
        self.k0_candidates = multiprocessing.Queue()
        self.data = data
        self.pool = pool
        

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
        
        xor_result = np.bitwise_xor(KEY, L0_XOR_R0) & 1  

        x0 =  np.uint8((xor_result >> 24)  & 0xFF)
        x1 =  np.uint8((xor_result >> 16) & 0xFF)
        x2 =  np.uint8((xor_result >> 8) & 0xFF)
        x3 =  np.uint8(xor_result & 0xFF) 
        s_29 = np.bitwise_xor(L0_XOR_R0, L4) >> 8
        s_23 = np.bitwise_xor( L0_XOR_R0, L4) >> 2
        s_23_29 =  np.bitwise_xor(s_23 , s_29)
        s_31 =  np.bitwise_xor(L0 , L4_XOR_R4)
        s_31_f_round = (self.F(x0,x1,x2, x3))
        s_23_29_XOR_s_31 =  np.bitwise_xor(s_23_29 , s_31)
        a =  np.bitwise_xor(s_23_29_XOR_s_31,  s_31_f_round) & 1
        return a 

    def linear_cryptanalysis_multiprocessing(self, num_processes):
        data = self.data
        bias = 110
        def test_key_range(start_key, end_key):
            array_range = np.arange(start_key, end_key, dtype='int32')
            for K0 in array_range:
                count = [0, 0]
                for d in data:
                    a = self.calculate_a(K0, d["plaintext"], d["ciphertext"])
                    count[a] += 1
                    print(f'Key:{K0} count:{count}')
                    if count[0] > 40 and count[1] > 40:
                        break
                    if count[0] > bias or count[1] > bias:
                        print(f'Found key {K0} count:{count}')
                        print(f'Adding key: {K0} to Queue')
                        self.k0_candidates.put(K0)
                        break
                    
        key_range = (2 ** 32) - 1  
        process_chunks = num_processes 
        chunk_size = key_range // process_chunks
        ranges = [(i * chunk_size, (i + 1) * chunk_size) for i in range(process_chunks)]
        processes = []
        for start_key, end_key in ranges:
            print(f'Starting on range {start_key} to {end_key}')
            process = multiprocessing.Process(target=test_key_range, args=(start_key, end_key))            
            # processes.append(process)
            # process.start()
            self.pool.apply_async(process)
 
        self.pool.close()
        self.pool.join()


        


        # for process in processes:
        #     process.start()
        #     process.join()
        #     process.terminate() 