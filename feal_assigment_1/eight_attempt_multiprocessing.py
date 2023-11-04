import numpy as np
import multiprocessing

class CryptanalysisFEAL:
    def __init__(self):
        self.k0_candidates = set()

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
            """
            G0 box calculate as per the following equation:
            G_0(a,b) = (a+b \pmod{256}) or S_5(G_0(a,b)) = S_7(a \oplus b)

            """
            result = (a + b) % 256
            return np.left_shift(result, 2) | np.right_shift(result, 6)
        # G1 box
        def G1(a, b):
            """
            G1 box calculate as per the following equation:
            G_1(a,b) = (a+b+1 \pmod{256})
            """
            result =  (a + b + 1) % 256
            return np.left_shift(result, 2) | np.right_shift(result, 6)

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
        s_23_29 = ((L0 ^ R0 ^ L4) >>8 & 1) ^ ((L0 ^ R0 ^ L4) >> 2 & 1) 
        s_31 = (L0 ^ L4 ^ R4) & 1
        s_31_f_round = (self.F((L0 ^ R0 ^ KEY), 0, 0, 0)[0]) & 1
        a = (s_23_29 ^ s_31 ^ s_31_f_round)
        return a 

    def linear_cryptanalysis_multiprocessing(self, data, num_processes):
        def test_key(K0, data,results):
            bias = 200
            count = [0, 0]
            for d in data:
                a = self.calculate_a(K0, d["plaintext"], d["ciphertext"])
                count[a] += 1
                print(f'Testing key:{K0} | Count:{count} of {bias} | a: {a}')
                if count[0] == bias or count[1] == bias:
                    print(f'Key  found: {K0}')
                    results.put(K0)
                    break
            print(f'Key found exiting')

        manager = multiprocessing.Manager()
        results = manager.Queue()

        processes = []
        for K0 in range(2**32):
            process = multiprocessing.Process(target=test_key, args=(K0, data, results))
            processes.append(process)
            process.start()

        for process in processes:
            process.join()

        while not results.empty():
            self.k0_candidates.add(results.get())

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
    cryptanalysis = CryptanalysisFEAL()
    cryptanalysis.linear_cryptanalysis_multiprocessing(data, num_processes=4)
    print("K0 Candidates:")
    for k0_candidate in cryptanalysis.k0_candidates:
        print(k0_candidate)
