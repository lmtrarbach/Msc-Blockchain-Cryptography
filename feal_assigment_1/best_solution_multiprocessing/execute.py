import argparse
import alternative_8_multiprocessing

# Set up command-line
parser = argparse.ArgumentParser(description='Tries to break the Feal-4 encryption using Mark Stamp solution')
parser.add_argument('-p', '--processes_per_core', type=int, default=10, help='Number of process per core')
parser.add_argument('-i', '--input_file', type=str, default='know.txt', help='Input file name')
parser.add_argument('-o', '--output_file', type=str, default='keys_found.txt', help='Output file name')
parser.add_argument('-m', '--margin_bias', type=int, default=5, help='Add a deviation for the keys a counts')
args = parser.parse_args()

# Read data from  file
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

# Instantiate the class  and set parse the data file
cryptanalysis = alternative_8_multiprocessing.CryptanalysisFEAL(data=data, process_per_core=args.processes_per_core,bias_margin=args.margin_bias)
cryptanalysis.linear_cryptanalysis_multiprocessing()

# Loop thought the possible keys and wirte to file
with open(args.output_file, mode='a') as file:
    for each_file in cryptanalysis.k0_candidates:
        print(each_file)
        file.write(each_file)
        file.write('\n')
