# gist: calculate the trails for 5 rounds witn random msg, nibble val and nibble idx of default cipher 
# for the simple key schedule for 100 times and each of the time it gives the correct trail. 
# ------------------------------------------------------------------------------------------------

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



def main():
    # msg = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 
    msg = [secrets.randbelow(16) for _ in range(32)]

    no_of_rounds = 80

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
    fault_round = 5 
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

    # to store the original last 4 rounds trail
    original_last_5_trail = []

    for round_num in range(no_of_rounds):
        inter_cip = state_list[round_num].copy()
        inter_fcip = fault_state_list[round_num].copy()

        # calculating the state differences
        state_diff = [inter_cip^inter_fcip for inter_cip, inter_fcip in zip(inter_cip, inter_fcip)]

        # for the following rounds, store the diff trail
        if(round_num in range(fault_round_idx, no_of_rounds)):
            original_last_5_trail.append(state_diff)

    # deriving the trail list part
    # ---------------------------------------------------------------------------------------------------
    cip = state_list[no_of_rounds-1].copy()
    fcip = fault_state_list[no_of_rounds-1].copy()

    # storing last round diff in last diff
    last_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
    last_layer_output = inv_perm(last_diff)

    trail_list = []
    trail_list = finding_trail_5_round(last_diff, fault_val, fault_nibble, trail_list)

    success = 0

    # if at each round the trail list matches then success
    for i in range(fault_round):
        if (trail_list[0][i][1] == inv_perm(original_last_5_trail[i])):
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






