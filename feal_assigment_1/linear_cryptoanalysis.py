import numpy as np

def linear_approximation(plaintext, ciphertext, subkey_bit):
    num_samples = len(plaintext)
    correlation = 0

    for i in range(num_samples):
        plaintext_byte = int(plaintext[i], 16)
        ciphertext_byte = int(ciphertext[i], 16)
        # sbukeys 0 or 1
        for subkey_bit_value in  subkey_bit:

            # Define the hypothesis
            linear_equation = np.bitwise_xor(plaintext_byte, subkey_bit_value) == ciphertext_byte

        # Calculate the correlation between hypothesis and  the actual difference
        correlation += np.sum(linear_equation) / num_samples

    return correlation

# Read data from "know.txt" and create plaintext and ciphertext pairs
data = []
with open("know.txt", "r") as file:
    lines = file.readlines()
    for i in range(0, len(lines), 3):
        plaintext_line = lines[i].strip()
        ciphertext_line = lines[i + 1].strip()
        plaintext = plaintext_line.split("=")[1].strip()
        ciphertext = ciphertext_line.split("=")[1].strip()
        data.append((plaintext, ciphertext))
subkey_bit = [1, 0]

best_correlation = 0
best_approximation = None

for plaintext, ciphertext in data:
    correlation = linear_approximation(plaintext, ciphertext,subkey_bit)
    if correlation > best_correlation:
        best_correlation = correlation
        best_approximation = (plaintext, ciphertext)

print("Best Linear Approximation:")
print("Plaintext:", best_approximation[0])
print("Ciphertext:", best_approximation[1])
print("Correlation:", best_correlation)
