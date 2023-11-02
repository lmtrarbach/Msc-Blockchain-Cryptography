import numpy as np

# Bit manipulation operations
def left_half(x):
    return np.right_shift(x, 32)

def right_half(x):
    return np.bitwise_and(x, 0xFFFFFFFF)

def combine_bytes(b3, b2, b1, b0):
    return ((b3 << 24) | (b2 << 16) | (b1 << 8) | b0) & 0xFFFFFFFF

def combine_halves(x, y):
    return ((x << 32) | (y & 0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF

# FEAL-4 Rotation
def rot(x):
    return np.bitwise_and(np.left_shift(x, 4) | np.right_shift(x, 4), 0xFF)

# FEAL-4 G-Box
def g_box(a, b, mode):
    return rot((a + b + mode) & 0xFF)

# FEAL-4 round function ('f-box')
def f_box(x):
    x0 = np.right_shift(x, 24) & 0xFF
    x1 = np.right_shift(x, 16) & 0xFF
    x2 = np.right_shift(x, 8) & 0xFF
    x3 = x & 0xFF

    t0 = (x2 ^ x3)
    y1 = g_box(x0 ^ x1, t0, 1)
    y0 = g_box(x0, y1, 0)
    y2 = g_box(y1, t0, 0)
    y3 = g_box(y2, x3, 1)

    return combine_bytes(y3, y2, y1, y0)

# Round key cracking function
def crack_round_key(pairs, output_differential):
    valid_candidates = []
    candidate_key = 0
    while candidate_key < 2**32:
        score = 0
        for i in range(len(pairs)):
            cipher_left = left_half(pairs[i][0][1]) ^ left_half(pairs[i][1][1])
            cipher_right = right_half(pairs[i][0][1]) ^ right_half(pairs[i][1][1])

            y = cipher_right
            z = (cipher_left ^ output_differential)

            candidate_right = right_half(pairs[i][0][1])
            candidate_left = left_half(pairs[i][0][1])
            candidate_right2 = right_half(pairs[i][1][1])
            candidate_left2 = left_half(pairs[i][1][1])

            y0 = candidate_right
            y1 = candidate_right2

            candidate_input0 = y0 ^ candidate_key
            candidate_input1 = y1 ^ candidate_key
            candidate_output0 = f_box(candidate_input0)
            candidate_output1 = f_box(candidate_input1)
            candidate_differential = (candidate_output0 ^ candidate_output1)

            if candidate_differential == z:
                score += 1
            else:
                break

        if score == len(pairs):
            valid_candidates.append(candidate_key)

        candidate_key += 1

    return valid_candidates

# Undo last FEAL-4 round
def undo_last_round(pairs, round_key):
    for i in range(len(pairs)):
        cipher_left0 = left_half(pairs[i][0][1])
        cipher_right0 = right_half(pairs[i][0][1])

        cipher_left1 = left_half(pairs[i][1][1])
        cipher_right1 = right_half(pairs[i][1][1])

        cipher_left0 = cipher_right0
        cipher_left1 = cipher_right1
        cipher_right0 = f_box(cipher_left0 ^ round_key) ^ np.right_shift(pairs[i][0][1], 32)
        cipher_right1 = f_box(cipher_left1 ^ round_key) ^ np.right_shift(pairs[i][1][1], 32)

        pairs[i][0][1] = combine_halves(cipher_left0, cipher_right0)
        pairs[i][1][1] = combine_halves(cipher_left1, cipher_right1)

    return pairs

# Undo final operation of a Feistel round (cipherLeft ^ R4R)
def undo_final_operation(pairs):
    for i in range(len(pairs)):
        cipher_left0 = left_half(pairs[i][0][1])
        cipher_right0 = right_half(pairs[i][0][1]) ^ cipher_left0

        cipher_left1 = left_half(pairs[i][1][1])
        cipher_right1 = right_half(pairs[i][1][1]) ^ cipher_left1

        pairs[i][0][1] = combine_halves(cipher_left0, cipher_right0)
        pairs[i][1][1] = combine_halves(cipher_left1, cipher_right1)

    return pairs

# Backtracking approach to cracking rounds 2 to 4 (subkeys 2, 3, and 4)
def phase1(current_round, subkeys, output_differential, chosen_pairs):
    valid_candidates = []
    candidate_key = 0

    if current_round == 0:
        return [subkeys[::-1]]
    else:
        pairs = undo_final_operation(chosen_pairs[current_round])
        for j in range(0, (3 - current_round)):
            pairs = undo_last_round(pairs, subkeys[j])

        candidate_schedules = crack_round_key(pairs, output_differential)

        if len(candidate_schedules) == 0:
            return []
        else:
            for candidate_key in candidate_schedules:
                valid_candidates += phase1(current_round - 1, subkeys + [candidate_key], output_differential, chosen_pairs)

    return valid_candidates

# Crack round 1 and subkeys 1, 5, and 6
def phase2(candidate_schedules, chosen_pairs):
    valid_schedules = []
    for subkeys in candidate_schedules:
        pairs = undo_last_round(chosen_pairs[1], subkeys[0])
        k0_guess = 0

        while k0_guess < 2**32:
            k4_guess = None
            k5_guess = None

            for j in range(len(pairs)):
                plain_left0 = left_half(pairs[j][0][0])
                plain_right0 = right_half(pairs[j][0][0])

                cipher_left0 = left_half(pairs[j][0][1])
                cipher_right0 = right_half(pairs[j][0][1])

                y = (f_box(cipher_right0 ^ k0_guess) ^ cipher_left0)

                if k4_guess is None:
                    k4_guess = (y ^ plain_left0)
                    k5_guess = (y ^ cipher_right0 ^ plain_right0)
                else:
                    if (y ^ plain_left0 != k4_guess) or (y ^ cipher_right0 ^ plain_right0 != k5_guess):
                        k4_guess = None
                        k5_guess = None
                        break

            if k4_guess is not None and k5_guess is not None:
                subkeys.insert(0, k0_guess)
                subkeys.insert(4, k4_guess)
                subkeys.insert(5, k5_guess)
                break

            k0_guess += 1

        if len(subkeys) == 6:
            return [subkeys]

    return valid_schedules

# Combine backtracking routines into single complete differential cryptanalysis routine
def differential_cryptanalysis(output_differential, chosen_pairs):
    subkeys = []

    candidate_schedules = phase1(3, subkeys, output_differential, chosen_pairs)

    if len(candidate_schedules) == 0:
        return []
    else:
        return phase2(candidate_schedules, chosen_pairs)

if __name__ == "__main__":
    # Your code execution logic here
    pass
