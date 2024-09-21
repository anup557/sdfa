# gist: calculate the trails for 3 rounds for baksheesh cipher with random msg, nibble val and nibble idx for 100
# times and each of the time it gives the correct trail. 
# ---------------------------------------------------------------------------------------------------------------


# from simple_fault_oracle import *
from fault_oracle import *
from itertools import product

import random, secrets

def inv_sbox(msg):
    # inv sbox table for baksheesh layer
    inv_sbox_table = [0x1, 0xf, 0xb, 0x0, 0xc, 0x5, 0x2, 0xe, 0x6, 0xa, 0xd, 0x4, 0x8, 0x3, 0x7, 0x9]

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


# returns 1 if list1 is in list2
def list_subset(list1, list2):
    if len(list1) != len(list2):
        return 0

    for pos in range(len(list1)):
        if list1[pos] == 1:
            if list2[pos] != 1:
                return 0
    return 1
    

# takes a list and returns the list with 1 at those places where the nibbles are active
def find_active_sbox(sbox_list):
    for i in range(len(sbox_list)):
        if sbox_list[i] != 0:
            sbox_list[i] = 1
    return sbox_list


def finding_trail_3_round(cip_diff, delta, idx, trail_list):
    # ddt table for default
    ddt = [[0], [3, 6, 11, 14], [3, 5, 11, 13], [5, 6, 13, 14], [3, 5, 8, 14], [5, 6, 8, 11], [8, 11, 13, 14], [3, 6, 8, 13], 
           [15], [1, 4, 9, 12], [2, 4, 10, 12], [1, 2, 9, 10], [1, 7, 10, 12], [4, 7, 9, 10], [1, 2, 4, 7], [2, 7, 9, 12]]

    inv_ddt = [[0], [9, 11, 12, 14], [10, 11, 14, 15], [1, 2, 4, 7], [9, 10, 13, 14], [2, 3, 4, 5], [1, 3, 5, 7], [12, 13, 14, 15], 
               [4, 5, 6, 7], [9, 11, 13, 15], [10, 11, 12, 13], [1, 2, 5, 6], [9, 10, 12, 15], [2, 3, 6, 7], [1, 3, 4, 6], [8]]

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

    dummy_frst_output = inv_perm(mid_layer_input)

    # storing the trails of 3 layers in trail_list
    dummy_trail_list = []
    dummy_trail_list.append([frst_layer_input, inv_perm(mid_layer_input)])
    dummy_trail_list.append([mid_layer_input, inv_perm(third_layer_input)])
    dummy_trail_list.append([third_layer_input, third_layer_output])
    trail_list.append(dummy_trail_list)

    return trail_list


def main():
    NO_OF_ROUNDS = 35

    # msg = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 
    msg = [secrets.randbelow(16) for _ in range(32)]

    # defining key list for default core
    #key = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 
    key = [secrets.randbelow(16) for _ in range(32)]

    # initializing state list to store all the state vals
    state_list = [[] for i in range(NO_OF_ROUNDS)]
    state_list = oracle(msg, key, state_list)

    # defining fault round and fault val
    fault_round = 3
    fault_round_idx = NO_OF_ROUNDS - fault_round

    # choosing nibble randomly
    fault_nibble = secrets.randbelow(32) 

    # choosing random single bit fault from list
    fault_val_list = [1, 2, 4, 8]
    fault_val_idx = secrets.randbelow(4)
    fault_val = fault_val_list[fault_val_idx]  


    fault_state_list = [[] for i in range(NO_OF_ROUNDS)]
    fault_state_list = fault_oracle(msg, key, fault_state_list, fault_round_idx, fault_nibble, fault_val)

    # to store the original last 4 rounds trail
    original_last_3_trail = []

    for round_num in range(fault_round_idx, NO_OF_ROUNDS):
        inter_cip = state_list[round_num].copy()
        inter_fcip = fault_state_list[round_num].copy()

        # calculating the state differences
        state_diff = [inter_cip^inter_fcip for inter_cip, inter_fcip in zip(inter_cip, inter_fcip)]

        # for the following rounds, store the diff trail
        original_last_3_trail.append(state_diff)

    # deriving the trail list part
    # ---------------------------------------------------------------------------------------------------
    cip = state_list[NO_OF_ROUNDS-1].copy()
    fcip = fault_state_list[NO_OF_ROUNDS-1].copy()

    # storing last round diff in last diff
    last_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
    last_layer_output = inv_perm(last_diff)

    trail_list = []
    trail_list = finding_trail_3_round(last_diff, fault_val, fault_nibble, trail_list)

    success = 0

    # if at each round the trail list matches then success
    for i in range(3):
        if (trail_list[0][i][1] == inv_perm(original_last_3_trail[i])):
            success = success + 1
    if (success == 3):
        print('hola.')
        return 1


    # if for any exp the main function returns failure then print msg and fault related things
    print('msg:', msg)
    print('\nfault val:',fault_val, '\t nibble:', fault_nibble)
    return 0



if __name__=='__main__':
    exp_num = 100

    for exp in range(exp_num):
        # if the main cipher returns failure then break
        if (main() == 0):
            break






