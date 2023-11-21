import argparse
import attempt_8_multiprocessing

# Set up command-line
parser = argparse.ArgumentParser(description='Tries to break the Feal-4 encryption using Mark Stamp solution')
parser.add_argument('-n', '--num_processes', type=int, default=200, help='Number of processes to use')
parser.add_argument('-i', '--input_file', type=str, default='know.txt', help='Input file name')
parser.add_argument('-o', '--output_file', type=str, default='keys_found.txt', help='Output file name')
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
cryptanalysis = attempt_8_multiprocessing.CryptanalysisFEAL(data)
cryptanalysis.linear_cryptanalysis_multiprocessing(num_processes=args.num_processes)

# Loop thought the possible keys and wirte to file
with open(args.output_file, mode='a') as file:
    for each_file in cryptanalysis.k0_candidates.get():
        print(each_file)
        file.write(each_file)
        file.write('\n')
