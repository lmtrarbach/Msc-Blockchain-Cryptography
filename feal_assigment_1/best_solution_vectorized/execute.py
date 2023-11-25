import argparse
import alternative_10_vectorized
import time
import datetime
import sys
# Command line setup
default_int = (2 ** 31) - 1
parser = argparse.ArgumentParser(description='Tries to break Feal-4 using Mark Stamp solution')
parser.add_argument('-i', '--input_file', type=str, default='know.txt', help='Input file name')
parser.add_argument('-o', '--output_file', type=str, default='keys_found.txt', help='Output file name')
parser.add_argument('-m', '--margin_bias', type=int, default=10, help='Add a deviation for the keys a counts')
#This tries to add Linear Hull in a last hope to get better results 
parser.add_argument('-s', '--statistics', type=bool, default=False, help='Provide statistics for the key')
parser.add_argument('-k', '--key_range', type=int, default=default_int, help='THe key range that wish to run')
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
start_time = time.time()
cryptanalysis = alternative_10_vectorized.CryptanalysisFEAL(data, args.output_file, args.margin_bias, args.statistics, args.key_range)
cryptanalysis.linear_cryptanalysis_multiprocess()
end_time = time.time()
total_time = str(datetime.timedelta(seconds=end_time - start_time))
print(f'Cryptanalysis finished in {total_time}')

with open(cryptanalysis.output_file, mode='a') as file_keys:
    print(cryptanalysis.k0_candidate)
    for each_key in cryptanalysis.k0_candidate:
        print(f'Adding key {each_key} to records ')
        file_keys.write(str(each_key))
        file_keys.write('\n')