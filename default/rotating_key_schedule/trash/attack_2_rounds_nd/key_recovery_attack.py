# not done yet




# program desc:
# -----------------------------------------------------------------------------------------------------
# This is key recovery attack for rotating key schedule according to our work for 4 rounds. In this prog 
# initially we give faults at round 21 (for 7 rounds). Then reduce the keyspace of k3, k2, k1 in equivalent
# keyspaces then use the trail of 4 rounds to recover the keyspace of k0. At first decrypt the rounds 27,
# 26, 25 by k3, k2, k1 resp and then use our attack procedure  to reduce the keyspace of k0. By this
# procedure after giving 
# 10 faults reduced size: 2.1 
# 11 faults reduced size: 0.95, 


#!/usr/bin/env python3
from sage.all import GF, matrix, block_matrix, vector
from sage.crypto.sboxes import SBox
from sage.crypto.boolean_function import BooleanFunction


import sys
import math
from IPython import embed

sys.path.append("./build")

from math import *
from util import *
from default_cipher import *
import random, secrets


s_base = SBox([0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5])
si_base = s_base.inverse()

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
    fourth_layer_output = inv_permute_bits(cip_diff)

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
                if ((inv_permute_bits(in_diff)[1 + 4*qr] == 0) and (inv_permute_bits(in_diff)[3 + 4*qr] == 0)):
                    if ((inv_permute_bits(in_diff)[0 + 4*qr] == 0) and (inv_ddt[inv_permute_bits(in_diff)[2 + 4*qr]] == 0)):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((inv_permute_bits(in_diff)[0 + 4*qr] == 0) and (scnd_last_input_diff[idx][2 + 4*qr] in inv_ddt[inv_permute_bits(in_diff)[2 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((inv_permute_bits(in_diff)[2 + 4*qr] == 0) and (scnd_last_input_diff[idx][2 + 4*qr] in inv_ddt[inv_permute_bits(in_diff)[0 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((scnd_last_input_diff[idx][2 + 4*qr] in inv_ddt[inv_permute_bits(in_diff)[0 + 4*qr]]) and (scnd_last_input_diff[idx][2 + 4*qr] in inv_ddt[inv_permute_bits(in_diff)[2 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

            else:
                # checking whether the input diff is 0 or not at the odd nibbles, as the diff should occur in the even nibbles only
                if ((inv_permute_bits(in_diff)[4*qr] == 0) and (inv_permute_bits(in_diff)[2 + 4*qr] == 0)):
                    if ((inv_permute_bits(in_diff)[1 + 4*qr] == 0) and (inv_ddt[inv_permute_bits(in_diff)[3 + 4*qr]] == 0)):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((inv_permute_bits(in_diff)[1 + 4*qr] == 0) and (scnd_last_input_diff[idx][3 + 4*qr] in inv_ddt[inv_permute_bits(in_diff)[3 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((inv_permute_bits(in_diff)[3 + 4*qr] == 0) and (scnd_last_input_diff[idx][3 + 4*qr] in inv_ddt[inv_permute_bits(in_diff)[1 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]

                    if ((scnd_last_input_diff[idx][3 + 4*qr] in inv_ddt[inv_permute_bits(in_diff)[1 + 4*qr]]) and (scnd_last_input_diff[idx][3 + 4*qr] in inv_ddt[inv_permute_bits(in_diff)[3 + 4*qr]])):
                        # updating the corresp nibble idx at the input list of 4th layer
                        for i in range(4):
                            fourth_layer_input[qr + 8*i] = in_diff[qr + 8*i]


    # for the third last and upper rounds
    third_layer_output = inv_permute_bits(fourth_layer_input)

    frst_layer_input = [0 for i in range(32)]
    frst_layer_input[idx] = delta
    top_layer = [0 for i in range(32)]
    # finding active sboxes in the second layer
    top_layer[idx] = 0xf
    scnd_layer_active_sbox = find_active_sbox(permute_bits(top_layer))

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

                if (list_subset( find_active_sbox(inv_permute_bits(diff_list)), scnd_layer_active_sbox) == 1):
                    third_layer_input[pos] = diff


    # for middle layer
    mid_layer_possible_input = []
    for i in inv_permute_bits(third_layer_input):
        mid_layer_possible_input.append(inv_ddt[i])

    frst_layer_active_sbox = find_active_sbox(top_layer)
    mid_layer_input = [0 for _ in range(32)]
    for pos, i in enumerate(mid_layer_possible_input):
        if i != [0]:
            diff_list = [0 for _ in range(32)]
            for diff in i:
                diff_list[pos] = diff

                if (list_subset( find_active_sbox(inv_permute_bits(diff_list)), frst_layer_active_sbox) == 1):
                    mid_layer_input[pos] = diff


    # storing the trails of 4 layers in trail_list
    dummy_trail_list = []
    dummy_trail_list.append([frst_layer_input, inv_permute_bits(mid_layer_input)])
    dummy_trail_list.append([mid_layer_input, inv_permute_bits(third_layer_input)])
    dummy_trail_list.append([third_layer_input, third_layer_output])
    dummy_trail_list.append([fourth_layer_input, fourth_layer_output])

    trail_list = dummy_trail_list.copy()

    return trail_list


def find_last_layer_diff_list(trail_list): 
    diff_list = [[] for _ in range(32)]

    for trail in trail_list:
        frst_layer_input = trail[0][0]
        frst_layer_output = trail[0][1]

        mid_layer_input = trail[1][0]
        mid_layer_output = trail[1][1]

        third_layer_input = trail[2][0]
        third_layer_output = trail[2][1]

        for i in range(32):
            if third_layer_input[i] != 0:
                dummy_list = [third_layer_input[i], third_layer_output[i]]
                if dummy_list not in diff_list[i]:
                    diff_list[i].append(dummy_list)

    return diff_list


# key recovery attack on round 2
def attack_r2(trail_list, r1_keyspace, k3, cip_fcip_list):    
    si = si_base    
    s = si.inverse()    

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
            
                        dec_cip = inv_permute_bits(cip)
                        dec_fcip = inv_permute_bits(fcip)
                        dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                        dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
            
                        dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                        dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))
            
                        in_diff = si(dec_cip[nibble_idx]^k3[nibble_idx]) ^ si(dec_fcip[nibble_idx]^k3[nibble_idx])

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

    return update_r2_keyspace


# 4th round attack on default cipher
def attack_r4(trail_list, r3_keyspace, k0, k1, k2, k3, cip_fcip_list):    
    si = si_base    
    s = si.inverse()    

    # making the nibble list from the corresponding group idx
    nibble_idx_list = [i for i in range(32)]

    r4_keyspace = []

    # producting the key space of 3rd last round
    dummy_r4 = list(product(r3_keyspace[0], r3_keyspace[1]))

    for nibble_idx in nibble_idx_list:
        # for each cip and faulty cip text pair
        # print('\nfor nibble idx:', nibble_idx)
        for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):

           # if the diff appears in the nibble idx, then do the following 
            if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
                # extract cip and faulty cip
                cip = cip_fcip[0]
                fcip = cip_fcip[1]

                # initializing the count for each key of r4_keyspace
                count = 0
                rej_count = 0

                # # append in this list only when a key is accepted
                # accept_key_list = []

                for key_idx, key in enumerate(dummy_r4):
                    if(key == 9999):
                        continue

                    # forming the last round key from the group idx
                    last_key = [0 for i in range(32)]

                    for group_idx_last in range(2):
                        for group_idx_mid in range(4):
                            for key_0 in range(4):
                                last_key[group_idx_last + 2*group_idx_mid + 8*key_0] = key[group_idx_last][group_idx_mid][key_0]

                    # last layer
                    dec_cip = inv_permute_bits(cip)
                    dec_fcip = inv_permute_bits(fcip)

                    dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                    dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                    # 2nd last layer
                    dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                    dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

                    dec_cip = [dec_cip^k3 for dec_cip, k3 in zip(dec_cip, k3)]
                    dec_fcip = [dec_fcip^k3 for dec_fcip, k3 in zip(dec_fcip, k3)]

                    # 3rd last layer
                    dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                    dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

                    dec_cip = [dec_cip^k2 for dec_cip, k2 in zip(dec_cip, k2)]
                    dec_fcip = [dec_fcip^k2 for dec_fcip, k2 in zip(dec_fcip, k2)]

                    # 4th last layer
                    dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                    dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

                    in_diff = si(dec_cip[nibble_idx]^k1[nibble_idx]) ^ si(dec_fcip[nibble_idx]^k1[nibble_idx])

                    # checking whether the input diff is same as the diff in trail or not
                    if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                        count = count+1
                    else:
                        # removing the key tuple if it does not satisfy the diff
                        dummy_r4[key_idx] = 9999
                        rej_count = rej_count+1

                # print('count: ', count)



    for key in dummy_r4:
        if (key == 9999):
            continue

        # initiallizing last key for k0
        last_key = [0 for i in range(32)]

        # making last key from key in r4
        for group_idx_last in range(2):
            for group_idx_mid in range(4):
                for key_0 in range(4):
                    last_key[group_idx_last + 2*group_idx_mid + 8*key_0] = key[group_idx_last][group_idx_mid][key_0]

        r4_keyspace.append(last_key)

    return r4_keyspace


# 3rd round attack on default cipher
def attack_r3(trail_list, r2_keyspace, k0, k1, k2, k3, cip_fcip_list):    
    si = si_base    
    s = si.inverse()    

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
            # print('\nfor nibble idx:', nibble_idx)
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
                        dec_cip = inv_permute_bits(cip)
                        dec_fcip = inv_permute_bits(fcip)

                        dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                        dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                        # 2nd last layer
                        dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                        dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

                        dec_cip = [dec_cip^k3 for dec_cip, k3 in zip(dec_cip, k3)]
                        dec_fcip = [dec_fcip^k3 for dec_fcip, k3 in zip(dec_fcip, k3)]

                        # 3rd last layer
                        dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                        dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

                        in_diff = si(dec_cip[nibble_idx]^k2[nibble_idx]) ^ si(dec_fcip[nibble_idx]^k2[nibble_idx])

                        # checking whether the input diff is same as the diff in trail or not
                        if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                            count = count+1
                        else:
                            # removing the key tuple if it does not satisfy the diff
                            dummy_r3[key_idx] = 9999
                            rej_count = rej_count+1

                    # print('count: ', count)



        for key in dummy_r3:
            # if ((group_idx_last == 0) and (key == (13, 14, 2, 9), (6, 10, 11, 14), (12, 8, 11, 14), (5, 13, 5, 14))):
            #     print('\n\noriginal key is here for left half.')

            # if ((group_idx_last == 1) and (key == ((2, 2, 11, 2), (15, 0, 2, 12), (3, 5, 1, 15), (10, 15, 6, 15)))):
            #     print('\n\noriginal key is here for right half.')

            if(key != 9999):
                r3_keyspace[group_idx_last].append(key)


    return r3_keyspace

    # # for printing purpose
    # for group_idx in range(2):
    #     print('\nfor the r3keyspace ' + str(group_idx) + ': ')
    #     for i in r3_keyspace[group_idx]:
    #         if (i == 9999):
    #             continue
    #         print(i, end = ', ')


def get_delta_enc(known_keys, round_nr: int, idx: int, delta: int):
    pt = [i for i in range(32)]
    set_fault(2, -1, idx, delta)
    a = c.encrypt(pt)
    
    set_fault(2, round_nr, idx, delta)
    b = c.encrypt(pt)

    set_fault(-1, -1, 0, 0)

    a = inv_permute_bits(a)
    b = inv_permute_bits(b)


    for key in known_keys:
        a = [aa ^ kk for aa, kk in zip(a, key)]
        b = [bb ^ kk for bb, kk in zip(b, key)]

        a = inv_permute_bits(inv_sub_cells(a))
        b = inv_permute_bits(inv_sub_cells(b))

    return a, b, [aa^bb for aa,bb in zip(a,b)]


def get_keyset(a, b, delta_in, sbox):
    keys = set()
    sbox_inv = sbox.inverse()

    for k_guess in range(16):
        if sbox_inv(a ^ k_guess) ^ sbox_inv(b ^ k_guess) == delta_in:
            keys.add(k_guess)

    return keys


def attack_enc(known_keys, starting_keyset):
    s = s_base
    si = si_base

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]

    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            a, b, delta = get_delta_enc(known_keys, 28-(len(known_keys) + 1), nibble_idx, delta_in)
            a, b = a[nibble_idx], b[nibble_idx]
            
            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if si(a ^ k_guess) ^ si(b ^ k_guess) == delta_in:
                    new_keyset.append(k_guess)
            keyspace[nibble_idx] = new_keyset
    
    return keyspace
    
    
def attack_enc1(known_keys, starting_keyset):
    s = s_base
    si = si_base

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]

    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            a, b, delta = get_delta_enc(known_keys, 28-(len(known_keys) + 1), nibble_idx, delta_in)
            a, b = a[nibble_idx], b[nibble_idx]
            
            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if si(a ^ k_guess) ^ si(b ^ k_guess) == delta_in:
                    new_keyset.append(k_guess)
            keyspace[nibble_idx] = new_keyset
    
    return keyspace
    
    
def attack_enc2(known_keys, starting_keyset):
    s = s_base
    si = si_base

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]

    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            a, b, delta = get_delta_enc(known_keys, 28-(len(known_keys) + 1), nibble_idx, delta_in)
            a, b = a[nibble_idx], b[nibble_idx]
            
            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if si(a ^ k_guess) ^ si(b ^ k_guess) == delta_in:
                    new_keyset.append(k_guess)
            keyspace[nibble_idx] = new_keyset
    
    return keyspace
    
    
def attack_enc3(known_keys, starting_keyset):
    s = s_base
    si = si_base

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]

    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            a, b, delta = get_delta_enc(known_keys, 28-(len(known_keys) + 1), nibble_idx, delta_in)
            a, b = a[nibble_idx], b[nibble_idx]
            
            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if si(a ^ k_guess) ^ si(b ^ k_guess) == delta_in:
                    new_keyset.append(k_guess)
            keyspace[nibble_idx] = new_keyset

    return keyspace


def single_key(keyspace):
    key = []
    # print('keyspace: ', keyspace)
    for nibble in keyspace:
        if len(nibble) != 1:
            raise RuntimeError(f"expected a single key, got {len(nibble)}")
        key.append(nibble[0])
        
    #key = permute_bits(key)
    return key


# returns the cip and fcip list of 4th last round where k0 is xored and here we have to reduce the key space of k0
def rotating_key_schedule_finding_trail(cip, fcip, nks):
    diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
    # print('\n\n\nat last round:\t', diff)

    # last layer
    dec_cip = inv_permute_bits(cip)
    dec_fcip = inv_permute_bits(fcip)

    layer_key = nks[3].copy()
    dec_cip = [dec_cip^layer_key for dec_cip, layer_key in zip(dec_cip, layer_key)]
    dec_fcip = [dec_fcip^layer_key for dec_fcip, layer_key in zip(dec_fcip, layer_key)]

    # 2nd last layer
    dec_cip = inv_sub_cells(dec_cip)
    dec_fcip = inv_sub_cells(dec_fcip)

    diff = [dec_cip^dec_fcip for dec_cip, dec_fcip in zip(dec_cip, dec_fcip)]
    # print('2nd last round:\t', diff)

    dec_cip = inv_permute_bits(dec_cip)
    dec_fcip = inv_permute_bits(dec_fcip)

    layer_key = nks[2].copy()
    dec_cip = [dec_cip^layer_key for dec_cip, layer_key in zip(dec_cip, layer_key)]
    dec_fcip = [dec_fcip^layer_key for dec_fcip, layer_key in zip(dec_fcip, layer_key)]

    # 3rd last layer
    dec_cip = inv_sub_cells(dec_cip)
    dec_fcip = inv_sub_cells(dec_fcip)

    diff = [dec_cip^dec_fcip for dec_cip, dec_fcip in zip(dec_cip, dec_fcip)]
    # print('3rd last round:\t', diff)

    dec_cip = inv_permute_bits(dec_cip)
    dec_fcip = inv_permute_bits(dec_fcip)

    layer_key = nks[1].copy()
    dec_cip = [dec_cip^layer_key for dec_cip, layer_key in zip(dec_cip, layer_key)]
    dec_fcip = [dec_fcip^layer_key for dec_fcip, layer_key in zip(dec_fcip, layer_key)]

    dec_cip = inv_sub_cells(dec_cip)
    dec_fcip = inv_sub_cells(dec_fcip)

    dec_cip1 = inv_permute_bits(dec_cip)
    dec_fcip1 = inv_permute_bits(dec_fcip)

    diff = [dec_cip1^dec_fcip1 for dec_cip1, dec_fcip1 in zip(dec_cip1, dec_fcip1)]
    # print('4th last round:\t', diff)


    layer_key = nks[0].copy()
    dec_cip1 = [dec_cip1^layer_key for dec_cip1, layer_key in zip(dec_cip1, layer_key)]
    dec_fcip1 = [dec_fcip1^layer_key for dec_fcip1, layer_key in zip(dec_fcip1, layer_key)]

    dec_cip1 = inv_sub_cells(dec_cip1)
    dec_fcip1 = inv_sub_cells(dec_fcip1)

    diff = [dec_cip1^dec_fcip1 for dec_cip1, dec_fcip1 in zip(dec_cip1, dec_fcip1)]
    # print('4th last round:\t', diff)

    return [dec_cip, dec_fcip]


def main(number_of_faults ):
    global c, base_key, key_schedule, nks 

    num_unique_keys = 4 
    num_faulted_keys = num_unique_keys + 3 

    # giving random pt and base key
    base_key = [random.randint(0,15) for _ in range(32)]
    pt = [random.randint(0,15) for _ in range(32)]

    # # giving fix key
    # base_key = [i for i in range(32)]
    # pt = [i for i in range(32)]

    # its calling the default cipher whose input vars are default keys, number of keys and round per update
    c = DefaultCipher(base_key, num_unique_keys, 4)

    # in key schedule the 0th key is the base key
    key_schedule = c.key_schedule

    # storing normalized key in nks
    nks = normalize_key_schedule(key_schedule)
    nks1 = normalize_key_schedule1(key_schedule)
    nks2 = normalize_key_schedule2(key_schedule)
    nks3 = normalize_key_schedule3(key_schedule)


    # checking whether ki's are same with nks or not
    keys = []

    k3 = single_key(attack_enc(keys, range(4)))
    assert k3 == inv_permute_bits(nks[3])
    keys.append(k3)

    k2 = single_key(attack_enc(keys, range(4)))
    assert k2 == inv_permute_bits(nks[2])
    keys.append(k2)

    k1 = single_key(attack_enc(keys, range(4)))
    assert k1 == inv_permute_bits(nks[1])
    keys.append(k1)
    
    k0 = attack_enc(keys, range(16))
    assert all(inv_permute_bits(nks[0])[nibble_idx] in k0[nibble_idx] for nibble_idx in range(32))
    

    # making k3 eq list from k3
    k0_eq_list = []
    for nibble in range(32):
        k0_eq_list.append(k0[nibble][0])

    # generating nks list for rotating key schedule
    nks_list = []

    # here k3 is the key of the last round
    nks_list.append(k0_eq_list)
    nks_list.append(k1)
    nks_list.append(k2)
    nks_list.append(k3)

    # generating original ciphertext
    set_fault(-1, -1, 0, 0)
    cip = c.encrypt(pt)

    # 21 round is for 7 rounds 
    round_nr = 21 

    trail_list = [] 
    new_trail_list = [] 

    cip_fcip_list = [] 

    # giving fault to generate the fault diff in the last round
    # fault_list = [1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8]

    fault_list = [0 for i in range(32)]

    for i in range(number_of_faults):
        # if a fault is already there in the nibble then choose another nibble
        fault_nibble = secrets.randbelow(32) 

        while (fault_list[fault_nibble] != 0):
            # choosing nibble randomly
            fault_nibble = secrets.randbelow(32) 

        # choosing random single bit fault from list
        fault_val_list = [1, 2, 4, 8]
        fault_val_idx = secrets.randbelow(4)
        fault_val = fault_val_list[fault_val_idx]  

        fault_list[fault_nibble] = fault_val


    # sfa_bit_list stores the nibble values in the inner state
    sfa_bit_list = [] 

    # inter cip is to store the intermediate value of the cip after 4th last round
    inter_cip = []

    # depending upon the fault list storing the full trail list in trail_list
    for fault_idx, fault in enumerate(fault_list):
        idx = fault_idx

        set_fault(2, round_nr, idx, fault)
        fcip = c.encrypt(pt)

        # sfa_state() prints the inter state value at the time of fault
        sfa_bit_list.append(sfa_state())

        set_fault(-1, -1, 0, 0)

        # storing the intermediater values of the cip and fcip
        inter_cip_fcip_list = rotating_key_schedule_finding_trail(cip, fcip, nks_list)
        # print('inter cip fcip:', inter_cip_fcip_list)
        cip_fcip_list.append(inter_cip_fcip_list)

        inter_cip = inter_cip_fcip_list[0].copy()
        inter_fcip = inter_cip_fcip_list[1].copy()

        # finding the trail after decrypting the 3 rounds by k3, k2, k1
        cip_diff = [inter_cip^inter_fcip for inter_cip, inter_fcip in zip(inter_cip, inter_fcip)]

        new_trail_list = finding_trail_4_round(cip_diff, fault, idx, trail_list)
        trail_list.append(new_trail_list)


    # # printing the trails for round 22, 23, 24
    # for idx, i in enumerate(trail_list):
    #     print('trail list for ' + str(idx) + ': ', i)
    #     print('\n\n')

    # print('\n\n\n\n')
    # print('*'*100)
    # print('\n\n\n\n')

    # # printing the original key schedule
    # print('key schedule: ')
    # for key in key_schedule:
    #     print(key)

    # # printing the base key and the nibbles corresponding to the qr groups 
    # print('\nbase key:', base_key)

    # reducing the key space of k0 by doing 2 round attack
    r2_keyspace = attack_r2(trail_list, k0, k3, cip_fcip_list)

    nks_0_key = inv_permute_bits(nks[0])
    # for qr in range(8):
    #     qr_key = (nks_0_key[0 + qr], nks_0_key[8 + qr], nks_0_key[16 + qr], nks_0_key[24 + qr])

    #     if (qr_key in r2_keyspace[qr]):
    #         print('key is there for ' + str(qr))

    # for idx, key in enumerate(r2_keyspace):
    #     print('for group idx ' + str(idx) + ': ', key)
    #     print('group idx len for ' + str(idx) + ': ', len(key))
    #     print()

    # reducing the key space of k0 further by doing 3 round attack
    r3_keyspace = attack_r3(trail_list, r2_keyspace, k0, k1, k2, k3, cip_fcip_list)


    # print('\n\nfor 4th round attack:')
    r4_keyspace = attack_r4(trail_list, r3_keyspace, k0, k1, k2, k3, cip_fcip_list)

    # storing the reduced keyspace size after r4 attack
    reduced_keyspace_size = math.log2(len(r4_keyspace))

    if (nks_0_key in r4_keyspace):
        print('hola. keyspace size: ', reduced_keyspace_size)


    return [1, reduced_keyspace_size]


    # if the experiment gets fail
    print('fault list:', fault_list)
    print('msg:', pt)
    print('base key:', base_key)
    print('\n')
    return 0





    # if for any exp the main function returns failure then print msg and fault related things
    print('msg:', msg)
    print('\nfault val:',fault_val, '\t nibble:', fault_nibble)
    return 0



if __name__=='__main__':
    exp_num = 10
    
    # giving at each exp the amount of total number of faults
    number_of_faults = 12

    reduced_keyspace_size = 0
    print('For 4th round attack (using rotating key schedule):')
    print('*'*100)
    print('number of faults:', number_of_faults, end = '\n\n') 

    for exp in range(exp_num):
        # if the main cipher returns failure then break
        return_val = main(number_of_faults) 

        if (return_val == 0): 
            break

        reduced_keyspace_size = reduced_keyspace_size + return_val[1] 

    # printing avg size
    print('\navg reduced keyspace size: ', reduced_keyspace_size/exp_num)








