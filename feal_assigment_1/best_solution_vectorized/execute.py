import argparse
import alternative_10_vectorized

# Command line setup
parser = argparse.ArgumentParser(description='Tries to break Feal-4 using Mark Stamp solution')
parser.add_argument('-i', '--input_file', type=str, default='know.txt', help='Input file name')
parser.add_argument('-o', '--output_file', type=str, default='keys_found.txt', help='Output file name')
parser.add_argument('-m', '--margin_bias', type=int, default=5, help='Add a deviation for the keys a counts')
args = parser.parse_args()

# Read data from file
with open(args.input_file, "r") as file:
    data = []
    current_data = {}
    for line in file:
        if line.startswith("Plaintext="):
            current_data["plaintext"] = line.replace("Plaintext=", '').strip()
        elif line.startswith("Ciphertext="):
            current_data["ciphertext"] = line.replace("Ciphertext=", '').strip()
            data.append(current_data.copy())
            current_data = {}

# Create an instance of CryptanalysisFEAL and pass the output file as an argument
cryptanalysis = alternative_10_vectorized.CryptanalysisFEAL(data, args.output_file, args.margin_bias)
cryptanalysis.linear_cryptanalysis_multiprocess()
