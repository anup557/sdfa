# gist: this prog finds the equivalent key space for each of the nibbles by two calls. In the first call
# some number of faults are given in some of the fixed nibbles in the 5th last round. Then using the 
# five round trail the equivalent key space of the last and the second last rounds are recovered. In the 
# next call the faults are given in the 7th round. Then by the similar technique the equivalent key space
# of the 3rd and 4th rounds are recovered. Then at last this checks whether the recovered four round key 
# spaces are same as the normalized key space or not.
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
def attack_dec(original_known_keys, starting_keyset, trail_list, cip_fcip_list):
    # sbox and inv sbox of default layer
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]
    
    # initializing key space for the last layer it has all the possible values for the whole 32 nibbles
    keyspace = [list(starting_keyset) for _ in range(32)]

    # coping the known keys into the original known keys
    known_keys = original_known_keys.copy()

    # in the second call number remove the keys for k3 and k2 from the known keys
    if (call_number == 1):
        # as after removing one element the list size reduces to one less, so remove the 0-th element again
        known_keys.remove(known_keys[0])
        known_keys.remove(known_keys[0])

    for nibble_idx in range(32):
        # diff_list contains the cip, faulty cip and the input diff values from the trail list in the corresponding
        # nibble
        diff_list = get_delta_dec(known_keys, len(known_keys) + 1, nibble_idx, trail_list, cip_fcip_list)

        for [a, b, delta_in] in diff_list:
            # intializing the new keylist to store the updated keyspace
            new_keyset = list()

            for k_guess in keyspace[nibble_idx]:
                if inv_sbox_table[a ^ k_guess] ^ inv_sbox_table[b ^ k_guess] == delta_in:
                    new_keyset.append(k_guess)
            keyspace[nibble_idx] = new_keyset
    
    return keyspace


def get_delta_dec(known_keys, round_nr: int, idx: int, trail_list, cip_fcip_list):
    diff_list = find_last_trail_list(trail_list, cip_fcip_list)


    # initializing the last and the second last diff list to store the corresponding diff
    diff_list = []

    for trail_idx, trail in enumerate(trail_list):
        # if there is no difference in that nibble
        if (trail[5-round_nr][0][idx] == 0):
            continue

        # extracting the corresp cip and fcip of the corresp trail
        cip = inv_perm(cip_fcip_list[trail_idx][0])
        fcip = inv_perm(cip_fcip_list[trail_idx][1])

        for key in known_keys:
            # applying one round operation
            # adding round key
            cip = [aa^kk for aa, kk in zip(cip, key)]
            fcip = [aa^kk for aa, kk in zip(fcip, key)]

            # applying inv sbox and inv permutation
            cip = inv_perm(inv_sbox(cip))
            fcip = inv_perm(inv_sbox(fcip))

        a, b, in_diff = cip[idx], fcip[idx], trail[5-round_nr][0][idx]

        # appending the corresponding nibble values of cip, faulty cip and input diff
        diff_list.append([a, b, in_diff])

    return diff_list


# checks whether each nibble in the key space has single key or not if not then it raises an error
def single_key(keyspace):
    key = []
    for nibble in keyspace:
        if len(nibble) != 1:
            raise RuntimeError(f"expected a single key, got {len(nibble)}")
        key.append(nibble[0])
    return key 


def finding_trail_3_round(cip_diff, delta, idx, trail_list):
    # ddt table for default
    ddt = [[0], [3, 9], [7, 13], [14, 4], [13, 7], [4, 14], [10], [9, 3], [12, 6], [15], [1, 11], [8, 2], [11, 1], [2, 8], [6, 12], [5]]
    inv_ddt = [[0], [10, 12], [13, 11], [1, 7], [5, 3], [15], [14, 8], [2, 4], [11, 13], [7, 1], [6], [12, 10], [8, 14], [4, 2], [3, 5], [9]]

    third_layer_output = inv_perm(cip_diff)

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

    third_layer_input = [0 for _ in range(32)]
    for pos, i in enumerate(third_layer_possible_input):
        if i != [0]:
            diff_list = [0 for _ in range(32)]

            flag = 0
            for diff in i:
                diff_list[pos] = diff

                if (list_subset( find_active_sbox(inv_perm(diff_list)), scnd_layer_active_sbox) == 1):
                    third_layer_input[pos] = diff
                    flag = 1
            if(flag == 0):
                return 9999

    # for middle layer
    mid_layer_possible_input = []
    for i in inv_perm(third_layer_input):
        mid_layer_possible_input.append(inv_ddt[i])
    frst_layer_active_sbox = find_active_sbox(top_layer)
    mid_layer_input = [0 for _ in range(32)]
    for pos, i in enumerate(mid_layer_possible_input):
        if i != [0]:
            diff_list = [0 for _ in range(32)]

            flag = 0
            for diff in i:
                diff_list[pos] = diff

                if (list_subset( find_active_sbox(inv_perm(diff_list)), frst_layer_active_sbox) == 1):
                    mid_layer_input[pos] = diff
                    flag = 1

            if(flag == 0):
                return 9999

    dummy_frst_output = inv_perm(mid_layer_input)
    # checking whether the generated first layer output diff is in the possible output diff  
    if (dummy_frst_output[idx] not in ddt[frst_layer_input[idx]]):
        return 9999

    # storing the trails of 3 layers in trail_list
    dummy_trail_list = []
    dummy_trail_list.append([frst_layer_input, inv_perm(mid_layer_input)])
    dummy_trail_list.append([mid_layer_input, inv_perm(third_layer_input)])
    dummy_trail_list.append([third_layer_input, third_layer_output])
    trail_list.append(dummy_trail_list)

    return trail_list






# returns the trail of 5 rounds
def finding_trail_5_round(last_diff, fault_val, fault_nibble, trail_list):
    # inv ddt of sbox of default layer
    inv_ddt = [[0], [10, 12], [13, 11], [1, 7], [5, 3], [15], [14, 8], [2, 4], [11, 13], [7, 1], [6], [12, 10], [8, 14], [4, 2], [3, 5], [9]]

    scnd_last_input_diff = [[[0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5],
                            [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5],
                            [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10],
                            [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10],
                            [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5],
                            [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5],
                            [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10],
                            [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10]],

                            [[0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10],
                            [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10],
                            [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5],
                            [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5],
                            [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10],
                            [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10], [0, 2, 8, 10],
                            [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5],
                            [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5], [0, 1, 4, 5]]]


    # storing last round diff in last diff
    last_layer_output = inv_perm(last_diff)

    inter_diff = [0 for i in range(32)]

    # these are to take the products of the possible trails qr wise in the last two rounds
    dummy_fifth = [[] for i in range(8)]
    dummy_fourth = [[] for i in range(8)]

    # finding group idx depending upon the fault nibble
    group_idx = fault_nibble//16

    for qr in range(8):
        # calculating the all possible product input difference of the last layer
        all_poss_last_layer_input = list(product(inv_ddt[last_layer_output[0+qr]], inv_ddt[last_layer_output[8+qr]], inv_ddt[last_layer_output[16+qr]], inv_ddt[last_layer_output[24+qr]]))

        # taking each possible trail of the second last round and calculate and check the trails for the upper round 
        for trail in all_poss_last_layer_input:
            inter_diff[0+qr] = trail[0]
            inter_diff[8+qr] = trail[1]
            inter_diff[16+qr] = trail[2]
            inter_diff[24+qr] = trail[3]

            inter_diff = inv_perm(inter_diff)
            all_poss_scnd_last_layer_input = list(product(inv_ddt[inter_diff[0 + 4*qr]], inv_ddt[inter_diff[1 + 4*qr]], inv_ddt[inter_diff[2 + 4*qr]], inv_ddt[inter_diff[3 + 4*qr]]))

            # generating all possible trails for the fourth last round
            for scnd_last_trail in all_poss_scnd_last_layer_input:
               if ((scnd_last_trail[0] in scnd_last_input_diff[group_idx][0 + 4*qr]) and (scnd_last_trail[1] in scnd_last_input_diff[group_idx][1 + 4*qr]) and (scnd_last_trail[2] in scnd_last_input_diff[group_idx][2 + 4*qr]) and (scnd_last_trail[3] in scnd_last_input_diff[group_idx][3 + 4*qr])):
                   # updating the corresp nibble idx at the input list of 4th layer
                   dummy_fifth[qr].append(trail)
                   dummy_fourth[qr].append(scnd_last_trail)
                   # print('for qr ' + str(qr) + ' trail:', trail, '    scnd last trail:',scnd_last_trail)

    # taking the trails qr wise for the fifth and the fourth round
    fifth_round_trail_qr = list(product(dummy_fifth[0], dummy_fifth[1], dummy_fifth[2], dummy_fifth[3], dummy_fifth[4], dummy_fifth[5], dummy_fifth[6], dummy_fifth[7]))
    fourth_round_trail_qr = list(product(dummy_fourth[0], dummy_fourth[1], dummy_fourth[2], dummy_fourth[3], dummy_fourth[4], dummy_fourth[5], dummy_fourth[6], dummy_fourth[7]))

    # print('fourth round trail qr:', fourth_round_trail_qr)

    # generating fourth round trail from fourth round trail (qr wise)
    fourth_round_trail = []
    for trail in fourth_round_trail_qr:
        round_trail = [0 for i in range(32)]
        for qr in range(8):
            for nibble in range(4):
                round_trail[4*qr + nibble] = trail[qr][nibble]

        fourth_round_trail.append(round_trail)



    # generating fifth round trail from fifth round trail (qr wise)
    fifth_round_trail = []
    for trail in fifth_round_trail_qr:
        round_trail = [0 for i in range(32)]
        for qr in range(8):
            for nibble in range(4):
                round_trail[qr + 8*nibble] = trail[qr][nibble]

        fifth_round_trail.append(round_trail)


    new_trail_list = []
    # will store the trail of five roudns in full trail list
    full_trail_list = []

    for i in range(len(fourth_round_trail)):
        # calling 3 round trail function
        new_trail_list = finding_trail_3_round(fourth_round_trail[i], fault_val, fault_nibble, new_trail_list)

        # if 3 round trail returns invalid then reject the trails of 4 and 5 rounds
        if (new_trail_list == 9999):
            new_trail_list = []
            continue

        for trail in new_trail_list:
            for in_out_diff in trail:
                full_trail_list.append(in_out_diff)

        # appending the trails of four and fifth round
        full_trail_list.append([fourth_round_trail[i], inv_perm(fifth_round_trail[i])])
        full_trail_list.append([fifth_round_trail[i], inv_perm(last_diff)])

    trail_list.append(full_trail_list)
    return trail_list


def find_eq_scnd_last_key(scnd_last_trail_list):
    # sbox and inv sbox of default layer
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    scnd_last_key_list = [[i for i in range(4)] for j in range(32)]

    for nibble in range(32):
        for [in_diff, out_diff, cip] in scnd_last_trail_list[nibble]:
            for key_idx, key in enumerate(scnd_last_key_list[nibble]):
                # if the key is invalid then continue with the next key
                if (key == 9999):
                    continue

                # computing the input diff from input output diff and cip
                test_in_diff = inv_sbox_table[cip^key] ^ inv_sbox_table[cip^out_diff^key]

                # checking whether the input diff is same as the diff in trail or not
                if(in_diff != test_in_diff):
                    scnd_last_key_list[nibble][key_idx] = 9999


    # initializing the new key list for updation
    new_scnd_last_key_list = [[] for i in range(32)]

    # updating the new key list
    for nibble in range(32):
        for key_idx, key in enumerate(scnd_last_key_list[nibble]):
            if (key != 9999):
                new_scnd_last_key_list[nibble].append(key)

    eq_scnd_last_key = [0 for i in range(32)]
    for nibble in range(32):
        if (len(new_scnd_last_key_list[nibble]) > 1):
            print('scnd_last key space does not reduces to one eqvalent key.')
            exit()

        eq_scnd_last_key[nibble] = new_scnd_last_key_list[nibble][0]

    return eq_scnd_last_key



def find_last_trail_list(trail_list, cip_fcip_list):
    # initializing the last and the second last diff list to store the corresponding diff
    last_trail_list = [[] for _ in range(32)]
    scnd_last_trail_list = [[] for _ in range(32)]

    for trail_idx, trail in enumerate(trail_list):
        # extracting the corresp cip and fcip of the corresp trail
        cip = inv_perm(cip_fcip_list[trail_idx][0])
        fcip = inv_perm(cip_fcip_list[trail_idx][1])

        # -----------------------------------------------------------
        # for the last trail
        # -----------------------------------------------------------
        for in_diff_idx, in_diff in enumerate(trail[4][0]):
            # if the input and output diff is 0 then continue with the next diff
            if (in_diff == 0):
                continue

            # appending the input and the output difference in the last trail list
            in_diff_nibble = trail[4][0][in_diff_idx]
            out_diff_nibble = trail[4][1][in_diff_idx]
            cip_nibble = cip[in_diff_idx]

            last_trail_list[in_diff_idx].append([in_diff_nibble, out_diff_nibble, cip_nibble])

    return last_trail_list



def call_oracle(base_key, round_key, call_number):
    msg = [secrets.randbelow(16) for _ in range(32)]

    # --------------------------------------------------------------------------------------
    # oracle related things
    # --------------------------------------------------------------------------------------
    # initializing state list to store all the state vals
    state_list = [[] for i in range(80)]
    state_list = oracle(msg, round_key, base_key, state_list)

    # --------------------------------------------------------------------------------------
    # fault oracle related things
    # --------------------------------------------------------------------------------------
    # defining fault round and fault val
    # in the first call number, the fault round is 75 in the second one, this is 70
    fault_round = 5
    fault_round_idx = 80 - fault_round - 2*call_number

    # initializing trail list and cip fcip list
    trail_list = [] 
    cip_fcip_list = [] 

    # giving fault at each nibble
    # fix_fault_nibble = [0, 4, 8, 16, 20, 24]
    # fix_fault_nibble = [0, 4, 8, 12, 16, 20, 24, 28]
    # fix_fault_nibble = [4*i for i in range(5)] + [4*i + 1 for i in range(5)]
    fix_fault_nibble = [4*i for i in range(8)] + [4*i + 1 for i in range(8)]

    # the number of faults in an exp
    no_of_faults = len(fix_fault_nibble)

    for times in range(no_of_faults):
        # choosing fix nibble
        fault_nibble = fix_fault_nibble[times]

        # choosing fixed single bit value, here we are taking 4, as for 4 the hw of the output diff is max.
        # The same thing will happen for 2 also
        fault_val = 2

        fault_state_list = [[] for i in range(80)]
        fault_state_list = fault_oracle(msg, round_key, base_key, fault_state_list, fault_round_idx, fault_nibble, fault_val)

        # taking the last output as cip
        cip = state_list[79].copy()
        fcip = fault_state_list[79].copy()

        if (call_number == 1):
            # decrypting last round
            cip = inv_perm(cip)
            fcip = inv_perm(fcip)

            cip = [aa^kk for aa, kk in zip(cip, k3)]
            fcip = [aa^kk for aa, kk in zip(fcip, k3)]

            cip = inv_sbox(cip)
            fcip = inv_sbox(fcip)

            # decrypting second last round
            cip = inv_perm(cip)
            fcip = inv_perm(fcip)

            cip = [aa^kk for aa, kk in zip(cip, k2)]
            fcip = [aa^kk for aa, kk in zip(fcip, k2)]

            cip = inv_sbox(cip)
            fcip = inv_sbox(fcip)

        # finding the trail after decrypting the 3 rounds by k3, k2, k1
        cip_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]

        # appending the cip and faulty cip for the corresponding faults
        cip_fcip_list.append([cip, fcip])

        trail_list = finding_trail_5_round(cip_diff, fault_val, fault_nibble, trail_list)

    return trail_list, cip_fcip_list



def main():
    # taking a base key of 128 bits
    base_key = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10]

    # extracting the round keys from the base key
    round_key = key_schedule(base_key)

    # generating normalized key
    nk = normalize_key_schedule(round_key)

    # initializing the empty key list
    keys = []

    # --------------------------------------------------------
    # in the first call
    # --------------------------------------------------------
    global call_number
    call_number = 0
    trail_list, cip_fcip_list = call_oracle(base_key, round_key, call_number)

    # recovering equivalent key space
    global k3
    k3 = single_key(attack_dec(keys, range(4), trail_list, cip_fcip_list))
    # k3 = attack_dec(keys, range(4), trail_list, cip_fcip_list)
    keys.append(k3)
    assert k3 == inv_perm(nk[3])
    print('assertation pass for k3.')

    global k2
    k2 = single_key(attack_dec(keys, range(4), trail_list, cip_fcip_list))
    keys.append(k2)
    assert k2 == inv_perm(nk[2])
    print('assertation pass for k2.')

    # --------------------------------------------------------
    # in the second call
    # --------------------------------------------------------
    call_number = 1
    trail_list, cip_fcip_list = call_oracle(base_key, round_key, call_number)

    # give the call number as anothrer condition for the round number
    k1 = single_key(attack_dec(keys, range(4), trail_list, cip_fcip_list))
    keys.append(k1)
    assert k1 == inv_perm(nk[1])
    print('assertation pass for k1.')

    k0 = attack_dec(keys, range(16), trail_list, cip_fcip_list)
    assert all(inv_perm(nk[0])[nibble_idx] in k0[nibble_idx] for nibble_idx in range(32))
    print('assertation pass for k0.')


if __name__ == '__main__':
    main()
