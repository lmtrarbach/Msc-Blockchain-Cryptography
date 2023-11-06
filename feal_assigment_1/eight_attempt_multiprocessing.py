import numpy as np
import multiprocessing

class CryptanalysisFEAL:
    def __init__(self, data):
        self.k0_candidates = set()
        self.data = data

    def F(self, x0, x1, x2, x3):
        """
        Calculate F round function as per equations:
        f(x_0,x_1,x_2,x_3) = (y_0,y_1,y_2,y_3)
        
        Where:
        y_0 = G_0(x_0,y_1)
        y_1 = G_1(x_0 \oplus x_1,x_2 \oplus x_3)
        y_2 = G_0(y_1,x_2 \oplus x_3)
        y_3 = G_1(y_2,x_3)


        """
        def G0(a, b):
            return ((a + b) % 256) << 2
        
        def G1(a, b):
            return ((a + b + 1) % 256) << 2

        # Get the Y as described for F round
        y0 = G0(x0, x1)
        y1 = G1(x0 ^ x1, x2 ^ x3)
        y2 = G0(y1, x2 ^ x3)
        y3 = G1(y2, x3)

        return y0, y1, y2, y3

    def calculate_a(self, K0, plaintext, ciphertext):
        """
        Function calculate the value of a for the equation

        """
        # Extract L0, R0, L4, and R4
        
        L0 = int.from_bytes(list(bytearray.fromhex(plaintext[:8])), byteorder='big')
        R0 = int.from_bytes(list(bytearray.fromhex(plaintext[8:] )), byteorder='big')
        L4 = int.from_bytes(list(bytearray.fromhex(ciphertext[:8])), byteorder='big')
        R4 = int.from_bytes(list(bytearray.fromhex(ciphertext[:8])), byteorder='big')
        KEY = np.uint32(K0)
        
        s_29 = (L0 ^ R0 ^ L4) & 1
        s_23 = ((L0 ^ R0 ^ L4) >> 8) & 1
        s_23_29 = s_23 ^ s_29
        s_31 = (L0 ^ L4 ^ R4) & 1
        s_31_f_round = (self.F((L0 ^ R0 ^ K0), 0, 0, 0)[0]) & 1
        a = (s_23_29 ^ s_31 ^ s_31_f_round)
        return a 

    def linear_cryptanalysis_multiprocessing(self, num_processes):
        data = self.data
        bias = len(data) - 10
        results = multiprocessing.Manager().list()

        def test_key_range(start_key, end_key, results):
            local_results = set()
            for K0 in range(start_key, end_key):
                count = [0, 0]
                for d in data:
                    a = self.calculate_a(K0, d["plaintext"], d["ciphertext"])
                    count[a] += 1
                    if count[0] > 10 and count[1] > 10:
                        break
                if count[0] == bias or count[1] == bias:
                    local_results.add(K0)
            results.extend(local_results)

        key_range = 2 ** 32 // num_processes
        processes = []

        for i in range(num_processes):
            start_key = i * key_range
            end_key = (i + 1) * key_range
            process = multiprocessing.Process(target=test_key_range, args=(start_key, end_key, results))
            process.start()
            processes.append(process)

        for process in processes:
            process.join()

        self.k0_candidates = set(results)

if __name__ == "__main__":
    with open("know.txt", "r") as file:
        data = []
        current_data = {}
        for line in file:
            if line.startswith("Plaintext="):
                current_data["plaintext"] = line.replace("Plaintext=", '').strip()
            elif line.startswith("Ciphertext="):
                current_data["ciphertext"] = line.replace("Ciphertext=", '').strip()
                data.append(current_data)
                current_data = {}
    print(f'Starting to analyze data with length of {len(data)}')
    cryptanalysis = CryptanalysisFEAL(data)
    cryptanalysis.linear_cryptanalysis_multiprocessing(num_processes=8)
    print("K0 Candidates:")
    with open("keys_file.txt", "a+") as keys_file:
        for each in cryptanalysis.k0_candidates:
            print(each)
            keys_file.write(str(each))
            keys_file.write('\n')


