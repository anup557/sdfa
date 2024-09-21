# gist: this prog finds the equivalent key space for each of the nibbles by giving two faults
# at each nibble in 4 rounds. Then this matches the reduced equivalent key space with the
# normalized key schedule.
# --------------------------------------------------------------------------------------------------------

from default import *
from finding_trail import *
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


# ----------------------------------------------------------------------
# finding normalized key schedule
# ----------------------------------------------------------------------
def normalize_key_schedule(key_schedule):
    # defining linear structures
    linear_structures = [(0, 0), (6, 0xa), (9, 0xf), (0xf, 5)]
    linear_structures1 = [(0, 0), (0xa, 6), (0xf, 9), (5, 0xf)]

    in_mask = 0xc 
    in_value = 0 

    key_schedule = [[y for y in x] for x in key_schedule]
    
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


# round nr should be given in the input of this function
def attack_dec(known_keys, starting_keyset):
    # sbox and inv sbox of default layer
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]
    
    # fault values in each nibble idx
    fault_deltas = [1, 2]

    # initializing key space for the last layer it has all the possible values for the whole 32 nibbles
    keyspace = [list(starting_keyset) for _ in range(32)]

    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            # a and b are the cip and the faulty cip, at each time last key is appended in the known key set, for this 
            # its incrementing, and from there it gets in which round it has to give the fault 
            a, b = get_delta_dec(known_keys, len(known_keys) + 1, nibble_idx, delta_in)

            # intializing the new keylist to store the updated keyspace
            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if inv_sbox_table[a ^ k_guess] ^ inv_sbox_table[b ^ k_guess] == delta_in:
                    new_keyset.append(k_guess)
            keyspace[nibble_idx] = new_keyset
    
    return keyspace


def get_delta_dec(known_keys, round_nr: int, idx: int, delta: int):
    msg = [secrets.randbelow(16) for _ in range(32)]

    # calculating the fault round
    fault_round = 80 - round_nr

    # initializing state list to store all the state vals
    state_list = [[] for i in range(80)]
    state_list = oracle(msg, round_key, base_key, state_list)
    cip = state_list[79].copy()

    fault_state_list = [[] for i in range(80)]
    fault_state_list = fault_oracle(msg, round_key, base_key, fault_state_list, fault_round, idx, delta)
    fcip = fault_state_list[79].copy()

    for key in known_keys:
        # applying one round operation
        # applying inv permutation
        cip = inv_perm(cip)
        fcip = inv_perm(fcip)

        # adding round key
        cip = [aa^kk for aa, kk in zip(cip, key)]
        fcip = [aa^kk for aa, kk in zip(fcip, key)]

        # applying inv sbox
        cip = inv_sbox(cip)
        fcip = inv_sbox(fcip)

    # storing the output diff of the original and the faulty cip
    a = inv_perm(cip)[idx]
    b = inv_perm(fcip)[idx]

    return a, b


# checks whether each nibble in the key space has single key or not if not then it raises an error
def single_key(keyspace):
    key = []
    for nibble in keyspace:
        if len(nibble) != 1:
            raise RuntimeError(f"expected a single key, got {len(nibble)}")
        key.append(nibble[0])
    return key 


def main():
    msg = [secrets.randbelow(16) for _ in range(32)]

    # taking a base key of 128 bits
    global base_key
    base_key = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10]

    # extracting the round keys from the base key
    global round_key
    round_key = key_schedule(base_key)

    # generating normalized key
    nk = normalize_key_schedule(round_key)

    # initializing the empty key list
    keys = []

    # recovering equivalent key space
    k3 = single_key(attack_dec(keys, range(4)))
    keys.append(k3)
    assert k3 == inv_perm(nk[3])
    print('assertation pass for k3.')

    k2 = single_key(attack_dec(keys, range(4)))
    keys.append(k2)
    assert k2 == inv_perm(nk[2])
    print('assertation pass for k2.')

    k1 = single_key(attack_dec(keys, range(4)))
    keys.append(k1)
    assert k1 == inv_perm(nk[1])
    print('assertation pass for k1.')

    k0 = attack_dec(keys, range(16))
    assert all(inv_perm(nk[0])[nibble_idx] in k0[nibble_idx] for nibble_idx in range(32))
    print('assertation pass for k0.')


if __name__ == '__main__':
    main()
