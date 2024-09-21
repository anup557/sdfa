# gist: this prog finds the normalized keys corresponds to a given base key in rotating key schedule for 3 rounds. 
# Initially it finds the equivalent keys corresponding to the base key then after this it finds out 
# the normalized keys correspionding to the equivalent keys.
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


# ----------------------------------------------------------------------
# returns the intermediate state values of the cip and the fcip after applying 
# the normalised key schedule
# ----------------------------------------------------------------------
def rotating_key_schedule_finding_trail(cip, fcip, nks):
    diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
    # print('\n\n\nat last round:\t', diff)

    # -------------------------------------------------------
    # last layer
    # -------------------------------------------------------
    dec_cip = inv_perm(cip)
    dec_fcip = inv_perm(fcip)

    layer_key = nks[3].copy()
    dec_cip = [dec_cip^layer_key for dec_cip, layer_key in zip(dec_cip, layer_key)]
    dec_fcip = [dec_fcip^layer_key for dec_fcip, layer_key in zip(dec_fcip, layer_key)]

    # -------------------------------------------------------
    # 2nd last layer
    # -------------------------------------------------------
    dec_cip = inv_sbox(dec_cip)
    dec_fcip = inv_sbox(dec_fcip)

    diff = [dec_cip^dec_fcip for dec_cip, dec_fcip in zip(dec_cip, dec_fcip)]
    # print('2nd last round:\t', diff)

    dec_cip = inv_perm(dec_cip)
    dec_fcip = inv_perm(dec_fcip)

    layer_key = nks[2].copy()
    dec_cip = [dec_cip^layer_key for dec_cip, layer_key in zip(dec_cip, layer_key)]
    dec_fcip = [dec_fcip^layer_key for dec_fcip, layer_key in zip(dec_fcip, layer_key)]

    # -------------------------------------------------------
    # 3rd last layer
    # -------------------------------------------------------
    dec_cip = inv_sbox(dec_cip)
    dec_fcip = inv_sbox(dec_fcip)

    diff = [dec_cip^dec_fcip for dec_cip, dec_fcip in zip(dec_cip, dec_fcip)]
    # print('3rd last round:\t', diff)

    dec_cip = inv_perm(dec_cip)
    dec_fcip = inv_perm(dec_fcip)

    layer_key = nks[1].copy()
    dec_cip = [dec_cip^layer_key for dec_cip, layer_key in zip(dec_cip, layer_key)]
    dec_fcip = [dec_fcip^layer_key for dec_fcip, layer_key in zip(dec_fcip, layer_key)]

    dec_cip = inv_sbox(dec_cip)
    dec_fcip = inv_sbox(dec_fcip)

    dec_cip1 = inv_perm(dec_cip)
    dec_fcip1 = inv_perm(dec_fcip)

    diff = [dec_cip1^dec_fcip1 for dec_cip1, dec_fcip1 in zip(dec_cip1, dec_fcip1)]
    # print('4th last round:\t', diff)


    layer_key = nks[0].copy()
    dec_cip1 = [dec_cip1^layer_key for dec_cip1, layer_key in zip(dec_cip1, layer_key)]
    dec_fcip1 = [dec_fcip1^layer_key for dec_fcip1, layer_key in zip(dec_fcip1, layer_key)]

    dec_cip1 = inv_sbox(dec_cip1)
    dec_fcip1 = inv_sbox(dec_fcip1)

    diff = [dec_cip1^dec_fcip1 for dec_cip1, dec_fcip1 in zip(dec_cip1, dec_fcip1)]
    # print('4th last round:\t', diff)

    return [dec_cip, dec_fcip]


# key recovery attack on round 2
def attack_r2(trail_list, r1_keyspace, k3, cip_fcip_list):
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # taking the product space of the corresponding key nibbles
    r2_keyspace = [list(product(*[r1_keyspace[(i + 8 * j)%32] for j in range(4)])) for i in range(8)]

    # # giving the group idx for 2nd round
    quotient_idx_list = [i for i in range(8)]

    # update r2 keyspace is to store the keys that passes the 2nd round differences
    update_r2_keyspace = [[] for i in range(8)]

    ele_list = []
    key_list = [[] for i in range(16)]

    # making the nibble idx list at round 2 from groups of that round
    for group_idx in quotient_idx_list:
        # making the nibble list of the quotient group from the corresponding group idx
        nibble_idx_list = []
        for bit in range(4):
            nibble_idx_list.append(4*group_idx + bit)

        for nibble_idx in nibble_idx_list:
            cip_fcip_count = 0
            for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):
                if (trail_list[cip_fcip_idx][2][0][nibble_idx] != 0):
                    cip_fcip_count = cip_fcip_count + 1
                    cip = cip_fcip[0]
                    fcip = cip_fcip[1]

                    count = 0
                    for key_idx, key4 in enumerate(r2_keyspace[group_idx]):
                        if(r2_keyspace[group_idx][key_idx] == 9999):
                            continue

                        # forming the last round key from the group idx
                        last_key = [0 for i in range(32)]

                        for j in range(4):
                            last_key[group_idx + 8*j] = key4[j]

                        dec_cip = inv_perm(cip)
                        dec_fcip = inv_perm(fcip)
                        dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                        dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                        dec_cip = inv_perm(inv_sbox(dec_cip))
                        dec_fcip = inv_perm(inv_sbox(dec_fcip))

                        in_diff = inv_sbox_table[dec_cip[nibble_idx]^k3[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^k3[nibble_idx]]

                        # checking whether the input diff is same as the diff in trail or not
                        if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
                            count = count+1

                        else:
                            # removing the key tuple if it does not satisfy the diff
                            r2_keyspace[group_idx][key_idx] = 9999


        # next is for printing purpose
        for key4 in r2_keyspace[group_idx]:
            if (key4 == 9999):
                continue
            update_r2_keyspace[group_idx].append(key4)

    # print('r2 keyspace:')
    # for idx, i in enumerate(update_r2_keyspace):
    #     print('\nfor ' + str(idx) + 'grp: ', i)
    #     print('len: ', len(update_r2_keyspace[idx]))

    return update_r2_keyspace


# 3rd round attack on default cipher
def attack_r3(trail_list, r2_keyspace, k0, k1, k2, k3, cip_fcip_list):    
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # making the nibble list from the corresponding group idx
    nibble_idx_list = [[i for i in range(16)], [i for i in range(16, 32)]]

    r3_keyspace = [[], []] 

    # in the third last group there are only 2 groups, 0 and 1 
    for group_idx_last in [0, 1]: 
        # producting the key space of 3rd last round
        dummy_r3 = list(product(*[r2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))
        # print('initial len:', len(dummy_r3))

        for nibble_idx in nibble_idx_list[group_idx_last]:
            # for each cip and faulty cip text pair
            print('\nfor nibble idx:', nibble_idx)
            for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):

               # if the diff appears in the nibble idx, then do the following 
                if (trail_list[cip_fcip_idx][1][0][nibble_idx] != 0): 
                    # extract cip and faulty cip
                    cip = cip_fcip[0]
                    fcip = cip_fcip[1]

                    # initializing the count for each key of r3_keyspace
                    count = 0 
                    rej_count = 0 

                    # # append in this list only when a key is accepted
                    # accept_key_list = []

                    for key_idx, key in enumerate(dummy_r3):
                        if(key == 9999):
                            continue

                        # forming the last round key from the group idx
                        last_key = [0 for i in range(32)]
                        for group_idx_mid in range(4):
                            for key_0 in range(4):
                                last_key[group_idx_last + 2*group_idx_mid + 8*key_0] = key[group_idx_mid][key_0]

                        # last layer
                        dec_cip = inv_perm(cip)
                        dec_fcip = inv_perm(fcip)

                        dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                        dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                        # 2nd last layer
                        dec_cip = inv_perm(inv_sbox(dec_cip))
                        dec_fcip = inv_perm(inv_sbox(dec_fcip))

                        dec_cip = [dec_cip^k3 for dec_cip, k3 in zip(dec_cip, k3)]
                        dec_fcip = [dec_fcip^k3 for dec_fcip, k3 in zip(dec_fcip, k3)]

                        # 3rd last layer
                        dec_cip = inv_perm(inv_sbox(dec_cip))
                        dec_fcip = inv_perm(inv_sbox(dec_fcip))

                        in_diff = inv_sbox_table[dec_cip[nibble_idx]^k2[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^k2[nibble_idx]]

                        # checking whether the input diff is same as the diff in trail or not
                        if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                            count = count+1
                        else:
                            # removing the key tuple if it does not satisfy the diff
                            dummy_r3[key_idx] = 9999
                            rej_count = rej_count+1

                    print('count: ', count)

        for key in dummy_r3:
            if(key != 9999):
                r3_keyspace[group_idx_last].append(key)


    # for printing purpose
    for group_idx in range(2):
        print('\nfor the r3keyspace ' + str(group_idx) + ': ')
        for i in r3_keyspace[group_idx]:
            if (i == 9999):
                continue
            print(i, end = ', ')

    return r3_keyspace


def finding_trail_4_round(cip_diff, delta, idx, trail_list):
    # ddt table for default
    ddt = [[0], [3, 9], [7, 13], [14, 4], [13, 7], [4, 14], [10], [9, 3], [12, 6], [15], [1, 11], [8, 2], [11, 1], [2, 8], [6, 12], [5]]
    inv_ddt = [[0], [10, 12], [13, 11], [1, 7], [5, 3], [15], [14, 8], [2, 4], [11, 13], [7, 1], [6], [12, 10], [8, 14], [4, 2], [3, 5], [9]]


    # depending upon the input diff at idx, the output diff at idx pos of the following list at 4th last round can occur 
    scnd_last_input_diff = [[1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0],
                            [1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0],
                            [1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0],
                            [1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0],
                            [2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0],
                            [2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0],
                            [2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0],
                            [2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0],
                            [4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0],
                            [4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0],
                            [4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0],
                            [4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0],
                            [8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0],
                            [8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0],
                            [8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0],
                            [8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0],
                            [0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8],
                            [0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8],
                            [0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8],
                            [0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8],
                            [0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1],
                            [0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1],
                            [0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1],
                            [0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1],
                            [0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2],
                            [0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2],
                            [0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2],
                            [0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2],
                            [0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4],
                            [0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4],
                            [0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4],
                            [0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4]]


    # taking the output difference of the last layer
    fourth_layer_output = inv_perm(cip_diff)

    # calculating the all possible product input difference of the last layer
    all_poss_fourth_layer_input = [list(product(inv_ddt[fourth_layer_output[0 + i]], inv_ddt[fourth_layer_output[8 + i]], inv_ddt[fourth_layer_output[16 + i]], inv_ddt[fourth_layer_output[24 + i]])) for i in range(8)]

    # initializing input diff of the fourth last round
    fourth_layer_input = [0 for _ in range(32)]


    # finding the original input diff from the product ones
    for qr in range(8):
        update_list = []
        for in_diff_4 in all_poss_fourth_layer_input[qr]:
            # making the input diff list of the last layer
            in_diff = [0 for i in range(32)]
            for i in range(4):
                in_diff[qr + 8*i] = in_diff_4[i]

            # if the faults are given after idx 16 then in the last round the pattern is different than prev
            if (idx < 16):
                # checking whether the input diff is 0 or not at the odd nibbles, as the diff should occur in the even nibbles only
                if ((inv_perm(in_diff)[1 + 4*qr] == 0) and (inv_perm(in_diff)[3 + 4*qr] == 0)):
                    if ((inv_perm(in_diff)[0 + 4*qr] == 0) and (inv_ddt[inv_perm(in_diff)[2 + 4*qr]] == 0)):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((inv_perm(in_diff)[0 + 4*qr] == 0) and (scnd_last_input_diff[idx][2 + 4*qr] in inv_ddt[inv_perm(in_diff)[2 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((inv_perm(in_diff)[2 + 4*qr] == 0) and (scnd_last_input_diff[idx][2 + 4*qr] in inv_ddt[inv_perm(in_diff)[0 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((scnd_last_input_diff[idx][2 + 4*qr] in inv_ddt[inv_perm(in_diff)[0 + 4*qr]]) and (scnd_last_input_diff[idx][2 + 4*qr] in inv_ddt[inv_perm(in_diff)[2 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

            else:
                # checking whether the input diff is 0 or not at the odd nibbles, as the diff should occur in the even nibbles only
                if ((inv_perm(in_diff)[4*qr] == 0) and (inv_perm(in_diff)[2 + 4*qr] == 0)):
                    if ((inv_perm(in_diff)[1 + 4*qr] == 0) and (inv_ddt[inv_perm(in_diff)[3 + 4*qr]] == 0)):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((inv_perm(in_diff)[1 + 4*qr] == 0) and (scnd_last_input_diff[idx][3 + 4*qr] in inv_ddt[inv_perm(in_diff)[3 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((inv_perm(in_diff)[3 + 4*qr] == 0) and (scnd_last_input_diff[idx][3 + 4*qr] in inv_ddt[inv_perm(in_diff)[1 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((scnd_last_input_diff[idx][3 + 4*qr] in inv_ddt[inv_perm(in_diff)[1 + 4*qr]]) and (scnd_last_input_diff[idx][3 + 4*qr] in inv_ddt[inv_perm(in_diff)[3 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]


    # for the third last and upper rounds
    third_layer_output = inv_perm(fourth_layer_input)

    frst_layer_input = [0 for i in range(32)]
    frst_layer_input[idx] = delta
    top_layer = [0 for i in range(32)]
    # finding active sboxes in the second layer
    top_layer[idx] = 0xf
    scnd_layer_active_sbox = find_active_sbox(perm(top_layer))

    # taking third layer possible input from ddt
    third_layer_possible_input = []
    for i in third_layer_output :
        third_layer_possible_input.append(inv_ddt[i])


    # print('third layer possible output:', third_layer_possible_input)
    third_layer_input = [0 for _ in range(32)]
    for pos, i in enumerate(third_layer_possible_input):
        if i != [0]:
            diff_list = [0 for _ in range(32)]
            for diff in i:
                diff_list[pos] = diff

                if (list_subset( find_active_sbox(inv_perm(diff_list)), scnd_layer_active_sbox) == 1):
                    third_layer_input[pos] = diff


    # for middle layer
    mid_layer_possible_input = []
    for i in inv_perm(third_layer_input):
        mid_layer_possible_input.append(inv_ddt[i])

    frst_layer_active_sbox = find_active_sbox(top_layer)
    mid_layer_input = [0 for _ in range(32)]
    for pos, i in enumerate(mid_layer_possible_input):
        if i != [0]:
            diff_list = [0 for _ in range(32)]
            for diff in i:
                diff_list[pos] = diff

                if (list_subset( find_active_sbox(inv_perm(diff_list)), frst_layer_active_sbox) == 1):
                    mid_layer_input[pos] = diff


    # storing the trails of 4 layers in trail_list
    dummy_trail_list = []
    dummy_trail_list.append([frst_layer_input, inv_perm(mid_layer_input)])
    dummy_trail_list.append([mid_layer_input, inv_perm(third_layer_input)])
    dummy_trail_list.append([third_layer_input, third_layer_output])
    dummy_trail_list.append([fourth_layer_input, fourth_layer_output])

    trail_list = dummy_trail_list.copy()

    return trail_list


def make_k0(nk0):
    k0_eq_list = []

    for i in nk0:
        if i in [0, 5, 10, 15]:
            k0_eq_list.append(0)

        elif i in [1, 4, 11, 14]:
            k0_eq_list.append(1)

        elif i in [2, 7, 8, 13]:
            k0_eq_list.append(2)
        else:
            k0_eq_list.append(3)

    return k0_eq_list


def make_eq_k0(k0):
    k0_eq_list = []

    for i in k0:
        if (i == 0):
            k0_eq_list.append([0, 5, 10, 15])

        elif (i == 1):
            k0_eq_list.append([1, 4, 11, 14])

        elif (i == 2):
            k0_eq_list.append([2, 7, 8, 13])

        else:
            k0_eq_list.append([3, 6, 9, 12])

    return k0_eq_list


def main():
    msg = [secrets.randbelow(16) for _ in range(32)]

    # taking a base key of 128 bits
    base_key = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10]

    # extracting the round keys from the base key
    round_key = key_schedule(base_key)

    # finding the normalized keys from the round key
    nk = normalize_key_schedule(round_key).copy()
    # nk1 = normalize_key_schedule1(round_key).copy()
    # nk2 = normalize_key_schedule2(round_key).copy()
    # nk3 = normalize_key_schedule3(round_key).copy()

    # storing the inv perm of equivalent round keys
    for key_idx, i in enumerate(nk):
        nk[key_idx] = inv_perm(i).copy()

    nk[0] = make_k0(nk[0]).copy()
    k0 = make_eq_k0(nk[0])

    # --------------------------------------------------------------------------------------
    # oracle related things
    # --------------------------------------------------------------------------------------
    # initializing state list to store all the state vals
    state_list = [[] for i in range(80)]
    state_list = oracle(msg, round_key, base_key, state_list)

    # taking the last outpur as cip
    cip = state_list[79].copy()

    # --------------------------------------------------------------------------------------
    # fault oracle related things
    # --------------------------------------------------------------------------------------
    # defining fault round and fault val
    fault_round = 7 
    fault_round_idx = 80 - fault_round

    # initializing trail list and cip fcip list
    trail_list = []
    cip_fcip_list = []

    # the number of faults in an exp
    no_of_faults = 32

    # giving fault at each nibble
    fix_fault_nibble = [i for i in range(32)]

    for times in range(no_of_faults):
        # choosing fix nibble 
        fault_nibble = fix_fault_nibble[times]

        if times < 32:
            fault_val = 2
        else:
            fault_val = 1

        fault_state_list = [[] for i in range(80)]
        fault_state_list = fault_oracle(msg, round_key, base_key, fault_state_list, fault_round_idx, fault_nibble, fault_val)
        fcip = fault_state_list[79].copy()

        inter_cip_fcip_list = rotating_key_schedule_finding_trail(cip, fcip, nk)

        # storing the intermediate cip and faulty cip
        inter_cip = inter_cip_fcip_list[0].copy()
        inter_fcip = inter_cip_fcip_list[1].copy()

        cip_fcip_list.append(inter_cip_fcip_list)

        # finding the trail after decrypting the 3 rounds by k3, k2, k1
        cip_diff = [inter_cip^inter_fcip for inter_cip, inter_fcip in zip(inter_cip, inter_fcip)]

        # trail_list = finding_trail_2_round(cip_diff, fault_val, fault_nibble, trail_list)
        new_trail_list = finding_trail_4_round(cip_diff, fault_val, fault_nibble, trail_list)
        trail_list.append(new_trail_list)

    # ------------------------------------------------------------------
    # r2 key recovery attack
    # ------------------------------------------------------------------
    r2_keyspace = attack_r2(trail_list, k0, nk[3], cip_fcip_list)

    # ------------------------------------------------------------------
    # r3 key recovery attack
    # ------------------------------------------------------------------
    r3_keyspace = attack_r3(trail_list, r2_keyspace, k0, nk[1], nk[2], nk[3], cip_fcip_list)


if __name__ == '__main__':
    main()
