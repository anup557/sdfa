# gist: to calculate the trails for 2 rounds for default core with random msg, nibble val and nibble idx for 100
# times and each of the time it gives the correct trail. 
# ---------------------------------------------------------------------------------------------------------------


# from simple_fault_oracle import *
from default import *
from itertools import product

import random, secrets

def inv_sbox(msg):
    # inv sbox table for default core
    inv_sbox_table = [11, 0, 7, 13, 12, 15, 2, 4, 6, 1, 8, 14, 5, 10, 9, 3]

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


def finding_trail_2_round(cip_diff, delta, idx, trail_list):
    # ddt table for default core
    ddt = [[0], [4, 7, 8, 9, 10, 11, 13, 14], [6, 7, 14, 15], [1, 3, 4, 5, 8, 10, 14, 15], 
           [5, 6, 13, 14], [4, 7, 8, 9, 10, 11, 13, 14], [1, 3, 9, 11], [1, 3, 4, 5, 8, 10, 14, 15], 
           [3, 7, 11, 15], [2, 3, 4, 6, 8, 9, 13, 15], [1, 9, 12], [1, 2, 4, 5, 6, 7, 8, 11], 
           [2, 5, 10, 13], [2, 3, 4, 6, 8, 9, 13, 15], [2, 10, 12], [1, 2, 4, 5, 6, 7, 8, 11]]

    inv_ddt = [[0], [3, 6, 7, 10, 11, 15], [9, 11, 12, 13, 14, 15], [3, 6, 7, 8, 9, 13], 
               [1, 3, 5, 7, 9, 11, 13, 15], [3, 4, 7, 11, 12, 15], [2, 4, 9, 11, 13, 15], [1, 2, 5, 8, 11, 15], 
               [1, 3, 5, 7, 9, 11, 13, 15], [1, 5, 6, 9, 10, 13], [1, 3, 5, 7, 12, 14], [1, 5, 6, 8, 11, 15], 
               [10, 14], [1, 4, 5, 9, 12, 13], [1, 2, 3, 4, 5, 7], [2, 3, 7, 8, 9, 13]]

    scnd_layer_output = inv_perm(cip_diff)

    frst_layer_input = [0 for i in range(32)]
    frst_layer_input[idx] = delta

    top_layer = [0 for i in range(32)]
    # finding active sboxes in the second layer
    top_layer[idx] = 0xf 
    scnd_layer_active_sbox = find_active_sbox(top_layer)

    # taking third layer possible input from ddt
    scnd_layer_possible_input = []
    for i in scnd_layer_output :
        scnd_layer_possible_input.append(inv_ddt[i])

    scnd_layer_input = [0 for _ in range(32)]
    for pos, i in enumerate(scnd_layer_possible_input):
        if i != [0]:
            diff_list = [0 for _ in range(32)]

            for diff in i:
                diff_list[pos] = diff

                if (list_subset( find_active_sbox(inv_perm(diff_list)), scnd_layer_active_sbox) == 1): 
                    scnd_layer_input[pos] = diff


    # storing the trails of 2 layers in trail_list
    dummy_trail_list = []
    dummy_trail_list.append([frst_layer_input, inv_perm(scnd_layer_input)])
    dummy_trail_list.append([scnd_layer_input, scnd_layer_output])
    trail_list.append(dummy_trail_list)

    return trail_list


def main():
    # for default core, total number of rounds is 52
    no_of_rounds = 52

    # msg = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 
    msg = [secrets.randbelow(16) for _ in range(32)]

    # defining original key list for default layer
    key_layer = [[12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10], 
                 [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10], 
                 [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10], 
                 [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10]]

    # defining key list for default core
    key_core = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 

    # initializing state list to store all the state vals
    state_list = [[] for i in range(no_of_rounds)]
    state_list = oracle(msg, key_layer, key_core, state_list)

    # defining fault round and fault val
    fault_round = 2
    fault_round_idx = no_of_rounds - fault_round

    # choosing nibble randomly
    fault_nibble = secrets.randbelow(32) 

    # choosing random single bit fault from list
    fault_val_list = [1, 2, 4, 8]
    fault_val_idx = secrets.randbelow(4)
    fault_val = fault_val_list[fault_val_idx]  


    fault_state_list = [[] for i in range(no_of_rounds)]
    fault_state_list = fault_oracle(msg, key_layer, key_core, fault_state_list, fault_round_idx, fault_nibble, fault_val)
    # print('\n\n')

    # to store the original last 2 rounds trail for default core
    original_last_2_trail = []

    for round_num in range(no_of_rounds):
        inter_cip = state_list[round_num].copy()
        inter_fcip = fault_state_list[round_num].copy()

        # calculating the state differences
        state_diff = [inter_cip^inter_fcip for inter_cip, inter_fcip in zip(inter_cip, inter_fcip)]

        # for the following rounds, store the diff trail
        if(round_num in range(fault_round_idx, no_of_rounds)):
            original_last_2_trail.append(state_diff)

    # deriving the trail list part
    # ---------------------------------------------------------------------------------------------------
    cip = state_list[no_of_rounds-1].copy()
    fcip = fault_state_list[no_of_rounds-1].copy()

    # storing last round diff in last diff
    last_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
    last_layer_output = inv_perm(last_diff)


    trail_list = []
    trail_list = finding_trail_2_round(last_diff, fault_val, fault_nibble, trail_list)

    success = 0
    # if at each round the trail list matches then success
    for i in range(fault_round):
        if (trail_list[0][i][1] == inv_perm(original_last_2_trail[i])):
            success = success + 1
    if (success == fault_round):
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






