# gist: this prog finds the normalized keys corresponds to a given base key. Initially it finds the equivalent keys
# corresponding to the base key then after this it finds out the normalized keys correspionding to the equivalent keys.
# --------------------------------------------------------------------------------------------------------

from default import *
from itertools import product

import random, secrets

def inv_sbox(msg):
    # inv sbox table for default layer
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    cip = [0 for i in range(32)]
    # replacing nibble values of state with sbox values
    for nibble_idx, nibble in enumerate(msg):
        cip[nibble_idx] = inv_sbox_table[nibble]

    if (print_details == "true"):
        print('after inv sbox:\t', cip)
    
    return cip 



def inv_perm(msg):
    # permutation table of gift
    inv_perm_table = [  0, 5, 10, 15, 16, 21, 26, 31, 32, 37, 42, 47, 48, 53, 58, 63, 64, 69, 74, 79, 80, 
                        85, 90, 95, 96, 101, 106, 111, 112, 117, 122, 127, 12, 1, 6, 11, 28, 17, 22, 27, 
                        44, 33, 38, 43, 60, 49, 54, 59, 76, 65, 70, 75, 92, 81, 86, 91, 108, 97, 102, 107,
                        124, 113, 118, 123, 8, 13, 2, 7, 24, 29, 18, 23, 40, 45, 34, 39, 56, 61, 50, 55, 72, 
                        77, 66, 71, 88, 93, 82, 87, 104, 109, 98, 103, 120, 125, 114, 119, 4, 9, 14, 3, 20, 
                        25, 30, 19, 36, 41, 46, 35, 52, 57, 62, 51, 68, 73, 78, 67, 84, 89, 94, 83, 100, 105, 110, 99, 116, 121, 126, 115]

    # storing the state values into bits
    state_bits = [0 for i in range(128)]
    for nibble in range(32):
        for bit in range(4):
            state_bits[4 * nibble + bit] = (msg[nibble] >> bit) & 0x1

    # permute the bits
    perm_bits = [0 for i in range(128)]
    for bit in range(128):
        perm_bits[inv_perm_table[bit]] = state_bits[bit]

    # making cip from permute bits
    cip = [0 for i in range(32)]
    for nibble in range(32):
        cip[nibble] = 0;
        for bit in range(4):
            cip[nibble] ^= perm_bits[4 * nibble + bit] << bit;

    return cip


# key schedule function
def key_schedule(key):
    # initialize 4 round key list
    round_key = [[] for i in range(4)]
    round_key[0] = key.copy()

    # defining rc for key schedule
    rc = [0 for i in range(32)]
    rc[31] = 8

    for idx in range(3):
        # taking the previous round key into next round
        round_key[idx+1] = round_key[idx].copy()

        # applying round function, without add round key and modified rc
        round_key[idx+1] = sbox(round_key[idx+1], 'default')
        round_key[idx+1] = perm(round_key[idx+1])

        round_key[idx+1] = [p^q for p, q in zip(round_key[idx+1], rc)].copy()

    return round_key


def normalize_key_schedule(key_schedule):
    # defining linear structures
    linear_structures = [(0, 0), (6, 0xa), (9, 0xf), (0xf, 5)]
    linear_structures1 = [(0, 0), (0xa, 6), (0xf, 9), (5, 0xf)]

    in_mask = 0xc 
    in_value = 0 

    key_schedule = [[y for y in x] for x in key_schedule]
    
    # print('key_schedule: ', key_schedule)
    
    # print('key_schedule[3] ', key_schedule[3])
    # print('inv_perm of key_schedule[3] ', inv_perm(key_schedule[3]))
    for round_idx, round_key in reversed(list(enumerate(key_schedule))):
    
        if(round_idx > 0): 
            # print('round index: ', round_idx)
            #if(round_idx == 3):
            round_key = inv_perm(round_key)
            # print('round_key: ', round_idx, round_key)
            next_key_delta = [0 for _ in range(32)]

            for nibble_idx, nibble in enumerate(round_key):

                for delta_in, delta_out in linear_structures1:
                    if (nibble ^ delta_in) & in_mask == in_value:
                        round_key[nibble_idx] ^= delta_in
                        next_key_delta[nibble_idx] ^= delta_out
                        break
                else:
                    raise RuntimeError("invalid in_mask or in_value")
    
            # print('after normalization round_key: ', round_idx, round_key)
            #if(round_idx == 3):
            round_key = perm(round_key)
            for i in range(32):
                key_schedule[round_idx][i] = round_key[i]
            #next_key_delta = inv_perm(next_key_delta)
            #key_schedule[round_idx - 1] = inv_perm(key_schedule[round_idx - 1])
            for nibble_idx, delta in enumerate(next_key_delta):
                key_schedule[round_idx - 1][nibble_idx] ^= delta
    
    return key_schedule


def normalize_key_schedule1(key_schedule):
    # defining linear structures
    linear_structures = [(0, 0), (6, 0xa), (9, 0xf), (0xf, 5)]
    linear_structures1 = [(0, 0), (0xa, 6), (0xf, 9), (5, 0xf)]

    in_mask = 0xc
    in_value = 0

    key_schedule = [[y for y in x] for x in key_schedule]


    # print('key_schedule: ', key_schedule)

    # print('key_schedule[3] ', key_schedule[3])
    # print('inv_perm of key_schedule[3] ', inv_perm(key_schedule[3]))
    for round_idx, round_key in reversed(list(enumerate(key_schedule))):

        if(round_idx > 0):
            # print('round index: ', round_idx)
            #if(round_idx == 3):
            round_key = inv_perm(round_key)
            # print('round_key: ', round_idx, round_key)
            next_key_delta = [0 for _ in range(32)]

            for nibble_idx, nibble in enumerate(round_key):

                for delta_in, delta_out in linear_structures1:
                    if ( (nibble ^ delta_in) >= 4 ) and ( (nibble ^ delta_in) <= 7 ):
                        round_key[nibble_idx] ^= delta_in
                        next_key_delta[nibble_idx] ^= delta_out
                        break
                else:
                    raise RuntimeError("invalid in_mask or in_value")

            # print('after normalization round_key: ', round_idx, round_key)
            #if(round_idx == 3):
            round_key = perm(round_key)
            for i in range(32):
                key_schedule[round_idx][i] = round_key[i]
            #next_key_delta = inv_perm(next_key_delta)
            #key_schedule[round_idx - 1] = inv_perm(key_schedule[round_idx - 1])
            for nibble_idx, delta in enumerate(next_key_delta):
                key_schedule[round_idx - 1][nibble_idx] ^= delta


    return key_schedule


def normalize_key_schedule2(key_schedule):
    # defining linear structures
    linear_structures = [(0, 0), (6, 0xa), (9, 0xf), (0xf, 5)]
    linear_structures1 = [(0, 0), (0xa, 6), (0xf, 9), (5, 0xf)]

    in_mask = 0xc
    in_value = 0

    key_schedule = [[y for y in x] for x in key_schedule]


    # print('key_schedule: ', key_schedule)

    # print('key_schedule[3] ', key_schedule[3])
    # print('inv_perm of key_schedule[3] ', inv_perm(key_schedule[3]))
    for round_idx, round_key in reversed(list(enumerate(key_schedule))):

        if(round_idx > 0):
            # print('round index: ', round_idx)
            #if(round_idx == 3):
            round_key = inv_perm(round_key)
            # print('round_key: ', round_idx, round_key)
            next_key_delta = [0 for _ in range(32)]

            for nibble_idx, nibble in enumerate(round_key):

                for delta_in, delta_out in linear_structures1:
                    if ( (nibble ^ delta_in) >= 8 ) and ( (nibble ^ delta_in) <= 11 ):
                        round_key[nibble_idx] ^= delta_in
                        next_key_delta[nibble_idx] ^= delta_out
                        break
                else:
                    raise RuntimeError("invalid in_mask or in_value")

            # print('after normalization round_key: ', round_idx, round_key)
            #if(round_idx == 3):
            round_key = perm(round_key)
            for i in range(32):
               key_schedule[round_idx][i] = round_key[i]
            #next_key_delta = inv_perm(next_key_delta)
            #key_schedule[round_idx - 1] = inv_perm(key_schedule[round_idx - 1])
            for nibble_idx, delta in enumerate(next_key_delta):
                key_schedule[round_idx - 1][nibble_idx] ^= delta

    return key_schedule



def normalize_key_schedule3(key_schedule):
    # defining linear structures
    linear_structures = [(0, 0), (6, 0xa), (9, 0xf), (0xf, 5)]
    linear_structures1 = [(0, 0), (0xa, 6), (0xf, 9), (5, 0xf)]

    in_mask = 0xc
    in_value = 0

    key_schedule = [[y for y in x] for x in key_schedule]


    # print('key_schedule: ', key_schedule)

    # print('key_schedule[3] ', key_schedule[3])
    # print('inv_perm of key_schedule[3] ', inv_perm(key_schedule[3]))
    for round_idx, round_key in reversed(list(enumerate(key_schedule))):

        if(round_idx > 0):
            # print('round index: ', round_idx)
            #if(round_idx == 3):
            round_key = inv_perm(round_key)
            # print('round_key: ', round_idx, round_key)
            next_key_delta = [0 for _ in range(32)]

            for nibble_idx, nibble in enumerate(round_key):

                for delta_in, delta_out in linear_structures1:
                    if ( (nibble ^ delta_in) >= 12 ) and ( (nibble ^ delta_in) <= 15 ):
                        round_key[nibble_idx] ^= delta_in
                        next_key_delta[nibble_idx] ^= delta_out
                        break
                else:
                    raise RuntimeError("invalid in_mask or in_value")

            # print('after normalization round_key: ', round_idx, round_key)
            #if(round_idx == 3):
            round_key = perm(round_key)
            for i in range(32):
                key_schedule[round_idx][i] = round_key[i]
            #next_key_delta = inv_perm(next_key_delta)
            #key_schedule[round_idx - 1] = inv_perm(key_schedule[round_idx - 1])
            for nibble_idx, delta in enumerate(next_key_delta):
                key_schedule[round_idx - 1][nibble_idx] ^= delta

    return key_schedule



def main():
    # taking a base key of 128 bits
    base_key = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10]
    round_key = key_schedule(base_key)

    nrml_key = normalize_key_schedule(round_key).copy()
    nrml_key1 = normalize_key_schedule1(round_key).copy()
    nrml_key2 = normalize_key_schedule2(round_key).copy()
    nrml_key3 = normalize_key_schedule3(round_key).copy()

    print('key schedule:')
    for i in round_key:
        print(i)

    print('\n\nnormalized key schedule:')
    for j in nrml_key:
        print(j)

    print('\n\nnormalized key schedule1:')
    for j in nrml_key1:
        print(j)

    print('\n\nnormalized key schedule2:')
    for j in nrml_key2:
        print(j)

    print('\n\nnormalized key schedule3:')
    for j in nrml_key3:
        print(j)


if __name__ == '__main__':
    main()
