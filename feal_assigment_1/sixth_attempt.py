import sympy as sp

class CryptanalysisFEAL:
    def __init__(self):
        self.k0_candidates = set()

    def calculate_a(self, K0, L0, R0, L4, R4):
        # Define the symbols for K0, K1, K3, K4, K5
        K0_sym, K1_sym, K3_sym, K4_sym, K5_sym = sp.symbols('K0 K1 K3 K4 K5')

        # Compute the values of S-boxes
        S23_29_L0_R0_L4 = S23_29(L0 ^ R0 ^ L4)
        S31_L0_L4_R4 = S31(L0 ^ L4 ^ R4)

        # Calculate the value of 'a' using the provided equation
        a_expr = (S23_29_L0_R0_L4 ^ S31_L0_L4_R4 ^ S31(F(L0 ^ R0 ^ K0))).subs({K0_sym: K0})

        return a_expr

    def linear_cryptanalysis(self, data):
        n = len(data)  # Number of known plaintexts
        candidate_values = set()
        key_range = 2**32
        for K0 in range(key_range):
            print(f'Testing K0: {K0}')
            a_values = []  # To store 'a' values for this K0
            for i in range(n):
                plaintext = data[i]["plaintext"]
                ciphertext = data[i]["ciphertext"]

                a = self.calculate_a(K0, plaintext, ciphertext)
                a_values.append(a)
                print(f'Plaintext: {ciphertext} | {K0} of {key_range}')

            # Check if all 'a' values for this K0 are the same
            if all(a == a_values[0] for a in a_values):
                candidate_values.add(K0)

        self.k0_candidates = candidate_values

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
    cryptanalysis.linear_cryptanalysis(data)

    print("K0 Candidates:")
    for k0_candidate in cryptanalysis.k0_candidates:
        print(k0_candidate)
