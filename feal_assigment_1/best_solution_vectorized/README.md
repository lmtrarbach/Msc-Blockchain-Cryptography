## Vectorized solution
THis solution was focused in try the use of vectorization of numpy to find the keys in a best performance.

## execute.py

Helper script that imports alternative_8_multiprocessing and execute it. It has helper arguments so we can change  number of process per cpu, or the bias deviation for the a count
It is just a way to use the cython implementation importing the c code.

It will instantiate the class alternative_8_multiprocessing.CryptanalysisFEAL()  parse the data and the arguments that are optional
If you want to provide the arguments just provide:
- '-i' or  '--input-file'the type is str and the default is 'know.txt' to set the input file name and path for the plaintext/ciphertext pairs
- '-o' or '--output-file' the type is str and the default is 'keys_found.txt' it sets the output file name and path
- '-m' or  '--margin-bias' required  type is int and the default is 5 it add a deviation for the a counts

## alternative_10_vectorized.py

Is were all the execution happens it has the following functions:


### function F

Execute the F function required by s31_F on the Mark Stamp  equations
It have two nested functions called G0 and G1.
Both execute the module of a and b  and returns a shift left of 2. G1 adds + 1 to the sum as per FEAL-4.
I've found some documentation to add the bitwise or operation with the shift left two and shift left right


### count_ones_zeros

Will calculate the Mark Stamp equation for a getting the xoring of s_23_29 ,  s_31  and  s_31_f_round

s_31_f_round is were we execute the keys passing the xoring of the L0,R0 and the key as specific bits to F function. This would return as uint32

It will calculate the count of results of a for each key. The diference  hete is tht will leverage the numpy arrays and do it via an vectorization

### workers

Create pool of process to run chunks of the array so it don't load all the array at once for the keys. All this with the objective to improve the performance bootleneck

## Results

This code showed to be best performant that the vectoreized solution. Because can handle better the memory issues.