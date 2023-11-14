import numpy as np

class CryptanalysisFEAL:
    def __init__(self):
        self.k0_candidate = set()

    def F(self, x0, x1, x2, x3):
        """
        Calculate F round function as per equations:
        f(x_0, x_1, x_2, x_3) = (y_0, y_1, y_2, y_3)
        Where:
        y_0 = G_0(x_0, y_1)
        y_1 = G_1(x_0 ^ x_1, x_2 ^ x_3)
        y_2 = G_0(y_1, x_2 ^ x_3)
        y_3 = G_1(y_2, x_3)
        """
        def G0(a, b):
            result =  ((a + b) % 256)
            return np.left_shift(result, 2) | np.right_shift(result, 6)
        
        def G1(a, b):
            result =  ((a + b + 1) % 256)
            return np.left_shift(result, 2) | np.right_shift(result, 6)

        y0 = G0(x0, x1)
        y1 = G1(x0 ^ x1, x2 ^ x3)
        y2 = G0(y1, x2 ^ x3)
        y3 = G1(y2, x3)

        return y0, y1, y2, y3

    def calculate_a(self, K0, plaintext, ciphertext):
        L0 = int.from_bytes(bytes.fromhex(plaintext[:8]), byteorder='big')
        R0 = int.from_bytes(bytes.fromhex(plaintext[8:]), byteorder='big')
        L4 = int.from_bytes(bytes.fromhex(ciphertext[:8]), byteorder='big')
        R4 = int.from_bytes(bytes.fromhex(ciphertext[8:]), byteorder='big')
        s_23_29 = ((L0 ^ R0 ^ L4) >> 8) & 1
        s_31 = (L0 ^ L4 ^ R4) & 1
        s_31_f_round = (self.F(L0 ^ R0 ^ K0, 0, 0, 0)[0] >> 30) & 1
        a = (s_23_29 ^ s_31 ^ s_31_f_round)
        return a

    def linear_cryptanalysis_single_thread(self, data):
        bias = len(data) - 10
        keys = np.arange(0, 2 **28)
        for K0 in keys:
            key = K0 & 0xFFFFFFFF
            print(f'Key: {key}')
            count = [0, 0]
            for d in data:
                a = self.calculate_a(key , d["plaintext"], d["ciphertext"])
                count[a] += 1
                if count[0] > 30 and count[1] > 30:
                    pass
                if count[0] == bias or count[1] == bias:
                    print(f'Found key {key}')
                    self.k0_candidate.add(key)
                    break
                if key == 0:
                    break

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

    cryptanalysis = CryptanalysisFEAL()
    cryptanalysis.linear_cryptanalysis_single_thread(data)
    with open("found_keys1.txt","a") as file_keys:
        for each in cryptanalysis.k0_candidate:
            file_keys.write(f'{each}')
            file_keys.write('\n')

