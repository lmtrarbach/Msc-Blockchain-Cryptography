import multiprocessing
import  attempt_8_multiprocessing

with open('./feal_assigment_1/know.txt', "r") as file:
    data = []
    current_data = {}
    for line in file:
        if line.startswith("Plaintext="):
            current_data["plaintext"] = line.replace("Plaintext=", '').strip()
        elif line.startswith("Ciphertext="):
            current_data["ciphertext"] = line.replace("Ciphertext=", '').strip()
            data.append(current_data.copy())
            current_data = {}

cryptanalysis = attempt_8_multiprocessing.CryptanalysisFEAL(data, multiprocessing.Pool(1))
cryptanalysis.linear_cryptanalysis_multiprocessing(num_processes=200)
with open(file='./feal_assigment_1/keys_found.txt', mode='+a') as file:
    for each_file in cryptanalysis.k0_candidates.get():
        print(each_file)
        file.write(each_file)
        file.write('\n')
