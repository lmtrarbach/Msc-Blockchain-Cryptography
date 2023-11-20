import  vectorized2


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

cryptanalysis = vectorized2.CryptanalysisFEAL(data)
cryptanalysis.linear_cryptanalysis_multiprocess()

