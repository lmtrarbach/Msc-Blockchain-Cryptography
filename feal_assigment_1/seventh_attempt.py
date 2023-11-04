import numpy as np

class CryptanalysisFEAL:
    def __init__(self):
        self.k0_candidates = set()

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
            return ((a + b) % 256) << 2
        
        def G1(a, b):
            return ((a + b + 1) % 256) << 2

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
        KEY = np.uint32(K0)
        s_23_29 = ((L0 ^ R0 ^ L4) >> 8) & 1
        s_31 = (L0 ^ L4 ^ R4) & 1
        s_31_f_round = (self.F(L0 ^ R0 ^ KEY, 0, 0, 0)[0] >> 30) & 1
        a = (s_23_29 ^ s_31 ^ s_31_f_round)
        print(f'Plaintext: {plaintext}| KEY: {KEY} | a: {a} | L0: {L0} | s_23_29: {s_23_29} | s_31: {s_31} |s_31_f_round: {s_31_f_round}')
        return a

    def linear_cryptanalysis_single_thread(self, data):
        bias = len(data) - 1
        for K0 in range(2 ** 64):
            count = [0, 0]
            for d in data:
                a = self.calculate_a(K0, d["plaintext"], d["ciphertext"])
                count[a] += 1
                print(f'Testing key:{K0} | Count:{count} of {bias} | a: {a}')
                if count[0] > 30 and count[1] > 30:
                    pass
                if count[0] == bias or count[1] == bias:
                    print(f'Found key {K0}')
                    self.k0_candidate = K0
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
    print("K0 Candidate:", cryptanalysis.k0_candidate)
