# gist: calculate the trails for 4 rounds witn random msg, nibble val and nibble idx for 100 times and each of the time
# it gives the correct trail. Keep the file in "/home/anup/Desktop/github/dfa_on_default/oracle" folder to execute.


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


# this is for the 4th last rounds
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

    trail_list.append(dummy_trail_list)

    return trail_list

