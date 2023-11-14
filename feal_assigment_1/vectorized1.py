import numpy as np
from multiprocessing import Pool

class CryptanalysisFEAL:
    def __init__(self, data):
        self.k0_candidate = set()
        self.array_range = 2 ** 32 - 1
        self.chunk_size = 100000
        self.bias = 100
        self.data = data

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

        return y0, y1, y2, y3

    def calculate_a(self, keys, plaintext, ciphertext):
        L0 = int(plaintext[:8], 16)
        R0 = int(plaintext[8:], 16)
        L4 = int(ciphertext[:8], 16)
        R4 = int(ciphertext[8:], 16)

        s_23_29 = ((L0 ^ R0 ^ L4) >> 8) & 1
        s_31 = (L0 ^ L4 ^ R4) & 1
        s_31_f_round = (self.F(L0 ^ R0 ^ keys, 0, 0, 0)[0] >> 30) & 1
        a = (s_23_29 ^ s_31 ^ s_31_f_round)
        return a

    def worker(self, chunk_start):
        chunk_end = min(chunk_start + self.chunk_size, self.array_range)
        keys = np.arange(chunk_start, chunk_end) # Make an array from start to end
        calculate_a_vectorized = np.vectorize(self.calculate_a) # Transform the function in a vectorized function
        a = calculate_a_vectorized(keys, self.plaintext, self.ciphertext) # Call the function
        zero_counts = np.sum(a == 0)  # Counts of zeros 
        one_counts = np.sum(a == 1)  # Counts of ones 
        print(f'Zeros: {zero_counts}, Ones: {one_counts}')  # Print counts
        mask = (zero_counts >= self.bias) | (one_counts >= self.bias)
        keys_to_process = keys[mask]

        for key in keys_to_process:
            print(f'Found key for pair at chunk_start: {key}')
            self.k0_candidate.add(key) 

    def linear_cryptanalysis_multiprocess(self):
        for pair in self.data:
            self.plaintext = pair["plaintext"]
            self.ciphertext = pair["ciphertext"]
        pool = Pool()
        keys = np.arange(0, self.array_range, self.chunk_size) #  Make a array up to 2 ** N  but only the intervals for chunk
        pool.map(self.worker, keys)
        pool.close()
        pool.join()

if __name__ == "__main__":
    # Reading plaintext and ciphertext pairs
    with open("know.txt", "r") as file:
        data = []
        current_data = {}
        for line in file:
            if line.startswith("Plaintext="):
                current_data["plaintext"] = line.replace("Plaintext=", '').strip()

            elif line.startswith("Ciphertext="):
                current_data["ciphertext"] = line.replace("Ciphertext=", '').strip()
                data.append(current_data.copy())
                current_data = {}

    cryptanalysis = CryptanalysisFEAL(data)
    cryptanalysis.linear_cryptanalysis_multiprocess()
    # Writing found keys to a file
    with open("found_keys1.txt", "a") as file_keys:
        for each in cryptanalysis.k0_candidate:
            file_keys.write(f'{each}\n')
