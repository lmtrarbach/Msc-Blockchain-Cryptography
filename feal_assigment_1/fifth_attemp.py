import numpy as np

def sBox23_29(K4):
    return (K4 >> 23) & 1 ^ (K4 >> 29) & 1

def sBox31(K1, K3, K4, K5):
    return (K1 & K3 & K4 & K5) & 1

def linear_cryptanalysis(data):
    n = len(data)
    decrypted_keys = set()
    
    for K0 in range(2**32):
        count = [0, 0]
        
        for i in range(n):
            plaintext = int(data[i][0], 2)
            ciphertext = int(data[i][1], 2)
            
            # Calculate the bit 'j' for the first equation (a)
            j = (K0 ^ plaintext) & 1
            count[j] += 1
        
        if count[0] == n or count[1] == n:
            decrypted_keys.add(K0)

    return decrypted_keys

if __name__ == "__main__":
    with open("know.txt", "r") as file:
        data = []
        for line in file:
            if line.startswith("Plaintext=") or line.startswith("Ciphertext="):
                clean_line = line.replace("Plaintext=", '').replace("Ciphertext=", '').strip()
                data.append(clean_line.split())
    
    decrypted_keys = linear_cryptanalysis(data)
    print("Keys found:")
    for key_guess in decrypted_keys:
        print(f'K0: {key_guess:08X}')
