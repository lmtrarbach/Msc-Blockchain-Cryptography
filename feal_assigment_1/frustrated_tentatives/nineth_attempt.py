import numpy as np
from multiprocessing import Pool

class CryptanalysisFEAL:
    def __init__(self):
        self.k0_candidates = set()
        self.chunk_size = 50000  # Adjust as needed
        self.bias = {'L0': 102, 'R0': 108, 'L4': 103, 'R4': 104}
        self.data = []

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

    def calculate_a(self, key, plaintext, ciphertext):
        L0 = int(plaintext[:8], 16)
        R0 = int(plaintext[8:], 16)
        L4 = int(ciphertext[:8], 16)
        R4 = int(ciphertext[8:], 16)

        s_23_29 = (L0 ^ R0 ^ L4) & 1
        s_31 = (L0 ^ L4 ^ R4) & 1
        s_31_f_round = (self.F(L0 ^ R0 ^ key, 0, 0, 0)[0]) & 1
        a = (s_23_29 ^ s_31 ^ s_31_f_round)
        return a

    def worker(self, chunk):
        local_candidates = set()

        for key in chunk:
            print(f'Key: {key}')
            count = {'L0': 0, 'R0': 0, 'L4': 0, 'R4': 0} 
            for pair in self.data:
                a = self.calculate_a(key, pair["plaintext"], pair["ciphertext"])
                count['L0'] += (a & 1) == self.bias['L0']
                count['R0'] += ((a >> 1) & 1) == self.bias['R0']
                count['L4'] += ((a >> 8) & 1) == self.bias['L4']
                count['R4'] += ((a >> 9) & 1) == self.bias['R4']

                if all(count[b] >= 10 for b in count):
                    break
            if all(count[b] >= 10 for b in count):
                local_candidates.add(key)

        self.k0_candidates |= local_candidates


    def linear_cryptanalysis_multiprocess(self):
        possible_keys = set()

        for pair in self.data:
            L0 = int(pair["plaintext"][:8], 16)
            R0 = int(pair["plaintext"][8:], 16)
            L4 = int(pair["ciphertext"][:8], 16)
            R4 = int(pair["ciphertext"][8:], 16)

            possible_keys.add(L0 ^ R0 ^ L4)

        keys = 2 ** 16
        keys_range = np.arange(0, keys)
        pool = Pool() 
        pool.map(self.worker, keys_range)
        pool.close()
        pool.join()

if __name__ == "__main__":
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
    cryptanalysis = CryptanalysisFEAL()
    cryptanalysis.data = data
    cryptanalysis.linear_cryptanalysis_multiprocess()

    with open("found_keys.txt", "a") as file_keys:
        for each in cryptanalysis.k0_candidates:
            file_keys.write(f'{each}\n')
