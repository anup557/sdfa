# This is key recovery attack according to our work. In this prog we have used trail to find out the reduced keyspace. checking for whether second layer group 0 sboxes have all 2 bit reduction individually but in the last layer 0,8,16,24 has the combined key space strictly > 2^8. This is doing dfa. This is for rotating key also.
# Here we check whether the cips becomes same after changing the key schedule by rotating key schedule


#!/usr/bin/env python3
from sage.all import GF, matrix, block_matrix, vector
from sage.crypto.sboxes import SBox
from sage.crypto.boolean_function import BooleanFunction


import sys
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


def finding_dt(a, b, delta: int, idx, trail_list):
    # ddt table for default
    ddt = [[0], [3, 9], [7, 13], [14, 4], [13, 7], [4, 14], [10], [9, 3], [12, 6], [15], [1, 11], [8, 2], [11, 1], [2, 8], [6, 12], [5]]
    inv_ddt = [[0], [10, 12], [13, 11], [1, 7], [5, 3], [15], [14, 8], [2, 4], [11, 13], [7, 1], [6], [12, 10], [8, 14], [4, 2], [3, 5], [9]]

# [7, 1]

    # half_0 = [0, 2, 8, 10, 16, 18, 24, 26]
    # half_1 = [4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31]

    cip_diff = [aa^bb for aa,bb in zip(a,b)]

    third_layer_output = inv_permute_bits(cip_diff)

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


    third_layer_input = [0 for _ in range(32)]
    for pos, i in enumerate(third_layer_possible_input):
        if i != [0]:
            diff_list = [0 for _ in range(32)]
            for diff in i:
                diff_list[pos] = diff

                if (list_subset( find_active_sbox(inv_permute_bits(diff_list)), scnd_layer_active_sbox) == 1):
                    third_layer_input[pos] = diff

    # print(third_layer_input)


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

    # # printing stuffs
    # print(frst_layer_input)
    # print(inv_permute_bits(mid_layer_input))
    # print('\n')
    
    # # initializing difference list for 3 rounds
    # print(mid_layer_input)
    # print(inv_permute_bits(third_layer_input))
    # print('\n')

    # print(third_layer_input)
    # print(third_layer_output)

    # storing the trails of 3 layers in trail_list
    dummy_trail_list = []
    dummy_trail_list.append([frst_layer_input, inv_permute_bits(mid_layer_input)])
    dummy_trail_list.append([mid_layer_input, inv_permute_bits(third_layer_input)])
    dummy_trail_list.append([third_layer_input, third_layer_output])
    trail_list.append(dummy_trail_list)

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

            # # comment the rest of the for loop from this if mid and frst layer's in out diff is not needed
            # if mid_layer_input[i] != 0:
            #     dummy_list = [mid_layer_input[i], mid_layer_output[i]]
            #     if dummy_list not in diff_list[i]:
            #         diff_list[i].append(dummy_list)

            # if frst_layer_input[i] != 0:
            #     dummy_list = [frst_layer_input[i], frst_layer_output[i]]
            #     if dummy_list not in diff_list[i]:
            #         diff_list[i].append(dummy_list)

    return diff_list



# depending upon the diff list in last layer only this function reduce the key space of the nibbles
def attack_r1(trail_list, r1_keyspace, cip):    
    
    si = si_base    
    s = si.inverse()    

    # print("trail list: ", trail_list)

    last_layer_diff_list = [] 
    last_layer_diff_list = find_last_layer_diff_list(trail_list) 

    # print("last layer diff list: ", last_layer_diff_list)

    cip = inv_permute_bits(cip)

    for idx in range(32):    
        for in_out_diff in last_layer_diff_list[idx]:
            if len(in_out_diff) == 0:
                continue
            dummy_keysp = []
            for key_r1 in r1_keyspace[idx]:
                if  (((si(cip[idx] ^ key_r1) ^ si(cip[idx] ^ in_out_diff[1] ^ key_r1)) == in_out_diff[0])):    
                    dummy_keysp.append(key_r1)
            r1_keyspace[idx] = dummy_keysp

    return r1_keyspace    
    

# key recovery attack on round 2
def attack_r2(trail_list, r1_keyspace, cip_fcip_list):    
    si = si_base    
    s = si.inverse()    

    # taking the product space of the corresponding key nibbles
    r2_keyspace = [list(product(*[r1_keyspace[(i + 8 * j)%32] for j in range(4)])) for i in range(8)]

    # # giving the group idx for 2nd round
    # quotient_idx_list = [i for i in range(8)]
    quotient_idx_list = [0]


    ele_list = []
    key_list = [[] for i in range(16)]

    # checkihng the rotating one for nibble idx 0 only
    group_idx = 0

    # for no nibbles in [0, 1, 2, 3] the original key remains
    nibble_idx_list = [0]
    nibble_idx = 0

    print('\n\nkey nibbles that satisfies the nibble in the second last layer:')

    for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):
        if (trail_list[cip_fcip_idx][1][0][nibble_idx] != 0):
            cip = cip_fcip[0]
            fcip = cip_fcip[1]
    
            count = 0
            # # taking one key from the r1keysapce
            # key4 = ((r1_keyspace[0][0], r1_keyspace[8][0], r1_keyspace[16][0], r1_keyspace[24][0]))
            key4 = (12, 12, 10, 14)
            print('key4: ', key4)

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

            for key_nibble_idx in range(16):
                in_diff = si(dec_cip[nibble_idx]^key_nibble_idx) ^ si(dec_fcip[nibble_idx]^key_nibble_idx)

                # checking whether the input diff is same as the diff in trail or not
                if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                    print(key_nibble_idx, end = ', ')

            print('\n')
            # checking that for one cip fcip diff only
            # break
 

    return r2_keyspace



# # key recovery attack on round 2
# def attack_r2(trail_list, r1_keyspace, cip_fcip_list):    
#     si = si_base    
#     s = si.inverse()    

#     # taking the product space of the corresponding key nibbles
#     r2_keyspace = [list(product(*[r1_keyspace[(i + 8 * j)%32] for j in range(4)])) for i in range(8)]

#     # # giving the group idx for 2nd round
#     # quotient_idx_list = [i for i in range(8)]
#     quotient_idx_list = [0]


#     ele_list = []
#     key_list = [[] for i in range(16)]

#     # checkihng the rotating one for nibble idx 0 only
#     group_idx = 0

#     # for no nibbles in [0, 1, 2, 3] the original key remains
#     nibble_idx = 0
#     print('\n\nkey nibbles that satisfies the nibble in the second last layer:')

#     for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):
#         if (trail_list[cip_fcip_idx][1][0][nibble_idx] != 0):
#             cip = cip_fcip[0]
#             fcip = cip_fcip[1]
    
#             count = 0
#             for key_idx, key4 in enumerate(r2_keyspace[group_idx]):
#                 if(r2_keyspace[group_idx][key_idx] == 9999):
#                     continue

#                 # forming the last round key from the group idx
#                 last_key = [0 for i in range(32)]

#                 for j in range(4):
#                     last_key[group_idx + 8*j] = key4[j]

#                 dec_cip = inv_permute_bits(cip)
#                 dec_fcip = inv_permute_bits(fcip)
#                 dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
#                 dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

#                 dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
#                 dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

#                 key_nibble_idx_list = []
#                 for key_nibble_idx in range(16):
#                     in_diff = si(dec_cip[nibble_idx]^key_nibble_idx) ^ si(dec_fcip[nibble_idx]^key_nibble_idx)

#                     # checking whether the input diff is same as the diff in trail or not
#                     if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
#                         key_nibble_idx_list.append(key_nibble_idx)

#                 # if original nibble idx for the nibble 1 is not there then change the product nibble to 9999
#                 if (4 not in key_nibble_idx_list):
#                     r2_keyspace[group_idx][key_idx] = 9999

#     # next is for printing purpose
#     print("\n\nfor group ", str(group_idx), ": ")
#     count = 0
#     for key4 in r2_keyspace[group_idx]:
#         if (key4 == 9999):
#             continue
#         print(key4, end = ',  ') 
#         count = count + 1

#     print('\n\ncount of the satisfied key space: ', count)


#     return r2_keyspace




# # key recovery attack on round 2
# def attack_r2(trail_list, r1_keyspace, cip_fcip_list):    
#     si = si_base    
#     s = si.inverse()    

#     # taking the product space of the corresponding key nibbles
#     r2_keyspace = [list(product(*[r1_keyspace[(i + 8 * j)%32] for j in range(4)])) for i in range(8)]

#     # # giving the group idx for 2nd round
#     # quotient_idx_list = [i for i in range(8)]
#     quotient_idx_list = [0]


#     ele_list = []
#     key_list = [[] for i in range(16)]

#     # making the nibble idx list at round 2 from groups of that round
#     for group_idx in quotient_idx_list:
#         # making the nibble list of the quotient group from the corresponding group idx
#         nibble_idx_list = []
#         for bit in range(4):
#             nibble_idx_list.append(4*group_idx + bit)

#         for nibble_idx in nibble_idx_list:
#             cip_fcip_count = 0
#             for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):
#                 if (trail_list[cip_fcip_idx][1][0][nibble_idx] != 0):
#                     cip_fcip_count = cip_fcip_count + 1
#                     cip = cip_fcip[0]
#                     fcip = cip_fcip[1]
            
#                     count = 0
#                     for key_idx, key4 in enumerate(r2_keyspace[group_idx]):
#                         if(r2_keyspace[group_idx][key_idx] == 9999):
#                             continue
            
#                         # forming the last round key from the group idx
#                         last_key = [0 for i in range(32)]
            
#                         for j in range(4):
#                             last_key[group_idx + 8*j] = key4[j]
            
#                         dec_cip = inv_permute_bits(cip)
#                         dec_fcip = inv_permute_bits(fcip)
#                         dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
#                         dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
            
#                         dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
#                         dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))
            
#                         # checking for which the original key combo appears
#                         if (nibble_idx == 2):
#                             key_list[dec_cip[nibble_idx]].append(key4)

#                         # appending the eles to count the number of distinct eles in the list
#                         if (nibble_idx == 2):
#                             ele_list.append(dec_cip[nibble_idx])

#                         # if (nibble_idx == 2):
#                             # in_diff = si(dec_cip[nibble_idx]^r1_keyspace[nibble_idx][1]) ^ si(dec_fcip[nibble_idx]^r1_keyspace[nibble_idx][1])
#                         # else:
#                             # in_diff = si(dec_cip[nibble_idx]^r1_keyspace[nibble_idx][0]) ^ si(dec_fcip[nibble_idx]^r1_keyspace[nibble_idx][0])
         
#                         in_diff = si(dec_cip[nibble_idx]^r1_keyspace[nibble_idx][0]) ^ si(dec_fcip[nibble_idx]^r1_keyspace[nibble_idx][0])

#                         # print('original key: ', si(dec_cip[nibble_idx]^2) ^ si(dec_fcip[nibble_idx]^2))

#                         # checking whether the input diff is same as the diff in trail or not
#                         if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
#                             count = count+1

#                         else:
#                             # removing the key tuple if it does not satisfy the diff
#                             r2_keyspace[group_idx].remove(key4)
         
#             print('number of cip fcip pair: ', cip_fcip_count)
#         print('len of group ', group_idx, ': ', len(r2_keyspace[group_idx]))
         
#         # # next is for printing purpose
#         # print("\n\nfor group ", str(group_idx), ": ")
#         # for key4 in r2_keyspace[group_idx]:
#         #     print(key4, end = ',  ') 


#     print('ele list: ', ele_list)
#     print('len ele list: ', len(ele_list))
#     for i in range(15):
#         print('\nkey list that satisfies ' , i, ': ', key_list[i])

#     print('\n\nfor the count of the list:')
#     ele_set = set(ele_list)
#     for i in ele_set:
#         print('count for ele ', i, ': ', ele_list.count(i))
#     # # checking the distinct vals for group idx 2
#     # list1 = []
#     # for key4 in r2_keyspace[2]:
#     #     list1.append(key4[0])
#     # print('distinct vals: ', set(list1))



#     return r2_keyspace


# 3rd round attack on default cipher
def attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list):    
    si = si_base    
    s = si.inverse()    

    # # making the nibble list from the corresponding group idx
    # nibble_idx_list = [[i for i in range(16)], [i for i in range(16, 32)]]
    nibble_idx_list = [[0, 1, 2, 3, 8, 9, 10, 11], [20, 21, 22, 23, 28, 29, 30, 31]]

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
                if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
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

                        # forming the mid round key from the group idx
                        mid_key = [0 for i in range(32)]


                        # making the mid key for the nibble idxs
                        # reduce the keyspace at first for these nibbles then do this for other nibbles
                        if(nibble_idx in [0, 1, 2, 3, 8, 9, 10, 11, 20, 21, 22, 23, 28, 29, 30, 31]):
                            # if the nibbles are in the upper nibble idx then storing the mid key as the last key
                            for i in range(32):
                                mid_key[i] = last_key[i]
                        else:
                            # if the nibbles are from the following nibble idx then the last key will be from the right half but the mid key depends upon the left
                            if (nibble_idx in [4, 5, 6, 7, 12, 13, 14, 15]):
                                key4 = (r2_keyspace[1][0], r2_keyspace[3][0], r2_keyspace[5][0], r2_keyspace[7][0])

                                for group_idx_mid in range(4):
                                    for key_0 in range(4):
                                        mid_key[1 + 2*group_idx_mid + 8*key_0] = key4[group_idx_mid][key_0]
                            # similarly if the nibbles are from the following nibble idx then the last key will be from the left half but the mid key depends upon the right
                            else:
                                key4 = (r2_keyspace[0][0], r2_keyspace[2][0], r2_keyspace[4][0], r2_keyspace[6][0])
                                for group_idx_mid in range(4):
                                    for key_0 in range(4):
                                        mid_key[0 + 2*group_idx_mid + 8*key_0] = key4[group_idx_mid][key_0]

                        # last layer
                        dec_cip = inv_permute_bits(cip)
                        dec_fcip = inv_permute_bits(fcip)

                        dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                        dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                        # 2nd last layer
                        dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                        dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

                        dec_cip = [dec_cip^mid_key for dec_cip, mid_key in zip(dec_cip, mid_key)]
                        dec_fcip = [dec_fcip^mid_key for dec_fcip, mid_key in zip(dec_fcip, mid_key)]

                        # 3rd last layer
                        dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                        dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

                        in_diff = si(dec_cip[nibble_idx]^r2_keyspace[nibble_idx%8][0][nibble_idx//8]) ^ si(dec_fcip[nibble_idx]^r2_keyspace[nibble_idx%8][0][nibble_idx//8])

                        # checking whether the input diff is same as the diff in trail or not
                        if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                            # if ((group_idx_last == 0) and (key == ((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8)))):
                            #     print('\n\noriginal key is here for left half.')

                            # if ((group_idx_last == 1) and (key == ((13, 15, 12, 8), (6, 11, 8, 7), (13, 6, 11, 13), (5, 14, 6, 0)))):
                            #     print('\n\noriginal key is here for right half.')

                            # accept_key_list.append(key)
                            count = count+1
                        else:
                            # removing the key tuple if it does not satisfy the diff
                            dummy_r3[key_idx] = 9999
                            rej_count = rej_count+1

                    # dummy_r3 = set(dummy_r3).intersection(set(accept_key_list))
                    # dummy_r3 = list(dummy_r3)

                    # print('len: ', len(dummy_r3))
                    # print('count: ', count)
                    # print('reject count: ', rej_count)

            # if (((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8)) in dummy_r3):
            #     print('for nibble idx ', nibble_idx, ' key nibble of group 2 is here.')



        for key in dummy_r3:
            if(key != 9999):
                r3_keyspace[group_idx_last].append(key)


    # # for printing purpose
    # print('\nprinting here for the key.')
    # for i in r3_keyspace[0]:
    #     if (i == ((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8))):
    #         print('\n\noriginal key is here for left half.')

    # for i in r3_keyspace[1]:
    #     if (i == ((13, 15, 12, 8), (6, 11, 8, 7), (13, 6, 11, 13), (5, 14, 6, 0))):
    #         print('\n\noriginal key is here for right half.')
    # print('\n\n')





    update_r3_keyspace = [[], []]
    nibble_idx_list = [[4, 5, 6, 7, 12, 13, 14, 15], [16, 17, 18, 19, 24, 25, 26, 27]]

    # in the third last group there are only 2 groups, 0 and 1 
    for group_idx_last in [0, 1]:
        # producting the key space of 3rd last round
        dummy_r3 = []
        for i in r3_keyspace[group_idx_last]:
            dummy_r3.append(i)

        for nibble_idx in nibble_idx_list[group_idx_last]:
            # for each cip and faulty cip text pair
            print('\nfor nibble idx:', nibble_idx)
            for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):

               # if the diff appears in the nibble idx, then do the following 
                if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
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

                        # forming the mid round key from the group idx
                        mid_key = [0 for i in range(32)]


                        # making the mid key for the nibble idxs
                        # reduce the keyspace at first for these nibbles then do this for other nibbles
                        if(nibble_idx in [0, 1, 2, 3, 8, 9, 10, 11, 20, 21, 22, 23, 28, 29, 30, 31]):
                            # if the nibbles are in the upper nibble idx then storing the mid key as the last key
                            for i in range(32):
                                mid_key[i] = last_key[i]
                        else:
                            # if the nibbles are from the following nibble idx then the last key will be from the right half but the mid key depends upon the left
                            if (nibble_idx in [4, 5, 6, 7, 12, 13, 14, 15]):
                                key4 = r3_keyspace[(group_idx_last+1)%2][0]

                                for group_idx_mid in range(4):
                                    for key_0 in range(4):
                                        mid_key[1 + 2*group_idx_mid + 8*key_0] = key4[group_idx_mid][key_0]
                            # similarly if the nibbles are from the following nibble idx then the last key will be from the left half but the mid key depends upon the right
                            else:
                                key4 = r3_keyspace[(group_idx_last+1)%2][0]
                                for group_idx_mid in range(4):
                                    for key_0 in range(4):
                                        mid_key[0 + 2*group_idx_mid + 8*key_0] = key4[group_idx_mid][key_0]

                        # last layer
                        dec_cip = inv_permute_bits(cip)
                        dec_fcip = inv_permute_bits(fcip)

                        dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                        dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                        # 2nd last layer
                        dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                        dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

                        dec_cip = [dec_cip^mid_key for dec_cip, mid_key in zip(dec_cip, mid_key)]
                        dec_fcip = [dec_fcip^mid_key for dec_fcip, mid_key in zip(dec_fcip, mid_key)]

                        # 3rd last layer
                        dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                        dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

                        in_diff = si(dec_cip[nibble_idx]^r2_keyspace[nibble_idx%8][0][nibble_idx//8]) ^ si(dec_fcip[nibble_idx]^r2_keyspace[nibble_idx%8][0][nibble_idx//8])

                        # checking whether the input diff is same as the diff in trail or not
                        if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                            # if ((group_idx_last == 0) and (key == ((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8)))):
                            #     print('\n\noriginal key is here for left half.')

                            # if ((group_idx_last == 1) and (key == ((13, 15, 12, 8), (6, 11, 8, 7), (13, 6, 11, 13), (5, 14, 6, 0)))):
                            #     print('\n\noriginal key is here for right half.')

                            # accept_key_list.append(key)
                            count = count+1
                        else:
                            # removing the key tuple if it does not satisfy the diff
                            dummy_r3[key_idx] = 9999
                            rej_count = rej_count+1

                    # dummy_r3 = set(dummy_r3).intersection(set(accept_key_list))
                    # dummy_r3 = list(dummy_r3)

#                     print('len: ', len(dummy_r3))
#                     print('count: ', count)
#                     print('reject count: ', rej_count)

            # if (((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8)) in dummy_r3):
            #     print('for nibble idx ', nibble_idx, ' key nibble of group 2 is here.')



        for key in dummy_r3:
            if(key != 9999):
                update_r3_keyspace[group_idx_last].append(key)



    # for printing purpose
    print('\n\nkeys for the left half:')
    for i in update_r3_keyspace[0]:
        print(i)
    print('keys for the right half:')
    for i in update_r3_keyspace[1]:
        print(i)

    print('\n\n')

    return update_r3_keyspace



################################################################################



def get_delta_enc(known_keys, round_nr: int, idx: int, delta: int):
    #ct = [random.randint(0,15) for _ in range(32)]
    pt = [i for i in range(32)]
    set_fault(2, -1, idx, delta)
    
    #print('non-faulty encryption')
    a = c.encrypt(pt)
    
    set_fault(2, round_nr, idx, delta)
    
    #print('faulty encryption')
    b = c.encrypt(pt)

    set_fault(-1, -1, 0, 0)

    a = inv_permute_bits(a)
    b = inv_permute_bits(b)


    for key in known_keys:
    
        '''known_keys[0][0] = 1
        known_keys[0][8] = 9
        known_keys[0][16] = 2
        known_keys[0][24] = 3'''
        
        a = [aa ^ kk for aa, kk in zip(a, key)]
        b = [bb ^ kk for bb, kk in zip(b, key)]

        a = inv_permute_bits(inv_sub_cells(a))
        b = inv_permute_bits(inv_sub_cells(b))

    return a, b, [aa^bb for aa,bb in zip(a,b)]

# def get_delta_enc(round_nr: int, idx: int, delta: int):
#     set_fault(2, -1, idx, delta)
#     pt = [random.randint(0,15) for _ in range(32)]
#     a = c.encrypt(pt)
#     set_fault(2, round_nr, idx, delta)
#     b = c.encrypt(pt)

#     set_fault(-1, -1, 0, 0)

#     a = inv_permute_bits(a)
#     b = inv_permute_bits(b)

#     return a, b, [aa^bb for aa,bb in zip(a,b)]

def get_keyset(a, b, delta_in, sbox):
    keys = set()
    sbox_inv = sbox.inverse()

    for k_guess in range(16):
        # print(si(a ^ k_guess) ^ si(b ^ k_guess), "==", delta_in)
        if sbox_inv(a ^ k_guess) ^ sbox_inv(b ^ k_guess) == delta_in:
            keys.add(k_guess)

    return keys


def attack_enc(known_keys, starting_keyset):
    s = s_base
    si = si_base

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]
    print('..................keyspace: ', keyspace)
    print('len of known keys: ', len(known_keys))
    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            a, b, delta = get_delta_enc(known_keys, 28-(len(known_keys) + 1), nibble_idx, delta_in)
            
            #print('a, b, delta_in: ', permute_bits(a), permute_bits(b), delta)
            
            a, b = a[nibble_idx], b[nibble_idx]
            
            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if si(a ^ k_guess) ^ si(b ^ k_guess) == delta_in:
                    new_keyset.append(k_guess)
                    #print('for delta_in: ', delta_in, 'nibble_idx: ', nibble_idx, 'k_guess: ', k_guess)
            keyspace[nibble_idx] = new_keyset
            #print('nibble_idx, new_keyset: ', nibble_idx, new_keyset)
    #keyspace = inv_permute_bits(keyspace)     
    
    print('------------------------keyspace: ', keyspace)
    return keyspace
    
    
def attack_enc1(known_keys, starting_keyset):
    s = s_base
    si = si_base

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]
    print('..................keyspace: ', keyspace)
    print('len of known keys: ', len(known_keys))
    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            a, b, delta = get_delta_enc(known_keys, 28-(len(known_keys) + 1), nibble_idx, delta_in)
            
            #print('a, b, delta_in: ', permute_bits(a), permute_bits(b), delta)
            
            a, b = a[nibble_idx], b[nibble_idx]
            
            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if si(a ^ k_guess) ^ si(b ^ k_guess) == delta_in:
                    new_keyset.append(k_guess)
                    #print('for delta_in: ', delta_in, 'nibble_idx: ', nibble_idx, 'k_guess: ', k_guess)
            keyspace[nibble_idx] = new_keyset
            #print('nibble_idx, new_keyset: ', nibble_idx, new_keyset)
    #keyspace = inv_permute_bits(keyspace)     
    
    print('------------------------keyspace: ', keyspace)
    return keyspace
    
    
def attack_enc2(known_keys, starting_keyset):
    s = s_base
    si = si_base

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]
    print('..................keyspace: ', keyspace)
    print('len of known keys: ', len(known_keys))
    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            a, b, delta = get_delta_enc(known_keys, 28-(len(known_keys) + 1), nibble_idx, delta_in)
            
            #print('a, b, delta_in: ', permute_bits(a), permute_bits(b), delta)
            
            a, b = a[nibble_idx], b[nibble_idx]
            
            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if si(a ^ k_guess) ^ si(b ^ k_guess) == delta_in:
                    new_keyset.append(k_guess)
                    #print('for delta_in: ', delta_in, 'nibble_idx: ', nibble_idx, 'k_guess: ', k_guess)
            keyspace[nibble_idx] = new_keyset
            #print('nibble_idx, new_keyset: ', nibble_idx, new_keyset)
    #keyspace = inv_permute_bits(keyspace)     
    
    print('------------------------keyspace: ', keyspace)
    return keyspace
    
    
def attack_enc3(known_keys, starting_keyset):
    s = s_base
    si = si_base

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]
    print('..................keyspace: ', keyspace)
    print('len of known keys: ', len(known_keys))
    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            a, b, delta = get_delta_enc(known_keys, 28-(len(known_keys) + 1), nibble_idx, delta_in)
            
            #print('a, b, delta_in: ', permute_bits(a), permute_bits(b), delta)
            
            a, b = a[nibble_idx], b[nibble_idx]
            
            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if si(a ^ k_guess) ^ si(b ^ k_guess) == delta_in:
                    new_keyset.append(k_guess)
                    #print('for delta_in: ', delta_in, 'nibble_idx: ', nibble_idx, 'k_guess: ', k_guess)
            keyspace[nibble_idx] = new_keyset
            #print('nibble_idx, new_keyset: ', nibble_idx, new_keyset)
    #keyspace = inv_permute_bits(keyspace)     
    
    print('------------------------keyspace: ', keyspace)
    return keyspace



def single_key(keyspace):
    key = []
    print('keyspace: ', keyspace)
    for nibble in keyspace:
        if len(nibble) != 1:
            raise RuntimeError(f"expected a single key, got {len(nibble)}")
        key.append(nibble[0])
        
    #key = permute_bits(key)
    return key










#######################################################################################










def main():
    global c, base_key, key_schedule, nks 

    num_unique_keys = 4 
    num_faulted_keys = num_unique_keys + 3 

    # # taking a base key of 128 bits
    # base_key = [secrets.randbelow(16) for _ in range(32)]

    #pt = [10, 13, 13, 15, 9, 2, 6, 9, 14, 9, 4, 1, 10, 5, 11, 7, 10, 1, 12, 12, 7, 2, 10, 15, 3, 1, 11, 2, 8, 1, 1, 4]
    base_key = [1, 10, 5, 15, 0, 1, 11, 3, 5, 14, 15, 5, 13, 14, 14, 10, 6, 0, 3, 6, 1, 15, 4, 13, 15, 5, 9, 1, 12, 6, 5, 4]
    #base_key = [2 for _ in range(32)]
    
    #base_key = [random.randint(0,15) for _ in range(32)]
    pt = [random.randint(0,15) for _ in range(32)]

    # its calling the default cipher whose input vars are default keys, number of keys and round per update
    c = DefaultCipher(base_key, num_unique_keys, 4)

    # in key schedule the 0th key is the base key
    key_schedule = c.key_schedule

    print('key schedule: ')
    for key in key_schedule:
        print(key)

    key_schedule = c.key_schedule

    nks = normalize_key_schedule(key_schedule)
    nks1 = normalize_key_schedule1(key_schedule)
    nks2 = normalize_key_schedule2(key_schedule)
    nks3 = normalize_key_schedule3(key_schedule)
    
    nks4 = normalize_key_schedule4(key_schedule)

    #pt = [i for i in range(32)]
    a = c.encrypt(pt)
    print('with original key cip:', a)
    print('\n\n\n\n')
    
    
    print('\n\nbase key:')
    #for key in base_key:
    print(base_key)
    
    
    print('\n\nkey schedule:')
    for key in key_schedule:
        print(list(map(hex,key)))
        
    
    print('\nnormalised key schedule0:')
    for key in nks:
        #print(key)
        print(list(map(hex,key)))
        
    print('\nnormalised key schedule1:')
    for key in nks1:
        #print(key)
        print(list(map(hex,key)))
        
    print('\nnormalised key schedule2:')
    for key in nks2:
        print(key)
        
        
    print('\nnormalised key schedule3:')
    for key in nks3:
        print(key)
        
        
    print('\nnormalised key schedule4:')
    for key in nks4:
        #print(key)
        print(list(map(hex,key)))
    
    
    
        
    
        
    print('\n\nkey schedule (inv_per):')
    for key in key_schedule:
        print(inv_permute_bits(key))

    print('\nnormalised key schedule0 (inv_per):')
    for key in nks:
        print(inv_permute_bits(key))
        
    print('\nnormalised key schedule1 (inv_per):')
    for key in nks1:
        print(inv_permute_bits(key))
        
    print('\nnormalised key schedule2 (inv_per):')
    for key in nks2:
        print(inv_permute_bits(key))
        
        
    print('\nnormalised key schedule3 (inv_per):')
    for key in nks3:
        print(inv_permute_bits(key))
        
        
    print('\nnormalised key schedule4 (inv_per):')
    for key in nks4:
        print(inv_permute_bits(key))


    c.key_schedule = [nks[0], nks[1], nks[2], nks[3]]
    b = c.encrypt(pt)
    
    
    c.key_schedule = [nks1[0], nks1[1], nks1[2], nks1[3]]
    b1 = c.encrypt(pt)
    
    
    c.key_schedule = [nks2[0], nks2[1], nks2[2], nks2[3]]
    b2 = c.encrypt(pt)
    
    
    c.key_schedule = [nks3[0], nks3[1], nks3[2], nks3[3]]
    b3 = c.encrypt(pt)
    
    
    c.key_schedule = [nks4[0], nks4[1], nks4[2], nks4[3]]
    b4 = c.encrypt(pt)

    # key_schedule1 = c.key_schedule
    # print('\n\nnew key schedule:')
    # for key in key_schedule1:
    #     print(key)

    print('\ncip:', a)
    print('\ncip0:', b)
    print('\ncip1:', b1)
    print('\ncip2:', b2)
    print('\ncip3:', b3)
    print('\ncip4:', b4)
    return



    keys = []
    keys1 = []
    keys2 = []
    keys3 = []
    # print('\nk0:', attack_dec(keys, range(4)))

    k0 = single_key(attack_enc(keys, range(4)))
    k0_1 = single_key(attack_enc1(keys1, range(4,8)))
    k0_2 = single_key(attack_enc2(keys2, range(8,12)))
    k0_3 = single_key(attack_enc3(keys3, range(12,16)))
    '''print('\nk0:', k0)
    print('\nnks:', nks[3], '\n', nks[2], '\n', nks[1], '\n', nks[0])'''

    assert k0 == inv_permute_bits(nks[3])
    print('assertation pass of k0 with nks[3].')
    exit
    
    assert k0_1 == inv_permute_bits(nks1[3])
    print('assertation pass of k0_1 with nks1[3].')
    exit 
    
    assert k0_2 == inv_permute_bits(nks2[3])
    print('assertation pass of k0_2 with nks2[3].')
    exit 
    
    assert k0_3 == inv_permute_bits(nks3[3])
    print('assertation pass of k0_3 with nks3[3].')
    exit  



    keys.append(k0)
    keys1.append(k0_1)
    keys2.append(k0_2)
    keys3.append(k0_3)
    #print('\nk0:', k0)
    # print('nk0:', nks[0])

    k1 = single_key(attack_enc(keys, range(4)))
    k1_1 = single_key(attack_enc1(keys1, range(4,8)))
    k1_2 = single_key(attack_enc(keys2, range(8,12)))
    k1_3 = single_key(attack_enc1(keys3, range(12,16)))
    
    '''print('\nk1:', k1)
    print('\nnks:', nks[3], '\n', nks[2], '\n', nks[1], '\n', nks[0])'''
    
    assert k1 == inv_permute_bits(nks[2])
    print('assertation pass k1 with nks[2].')
    exit
    
    assert k1_1 == inv_permute_bits(nks1[2])
    print('assertation pass k1_1 with nks1[2].')
    exit
    
    assert k1_2 == inv_permute_bits(nks2[2])
    print('assertation pass k1_2 with nks2[2].')
    exit
    
    assert k1_3 == inv_permute_bits(nks3[2])
    print('assertation pass k1_3 with nks3[2].')
    exit
    
    
    keys.append(k1)
    keys1.append(k1_1)
    keys2.append(k1_2)
    keys3.append(k1_3)
    #print('\nk0:', k0)
    # print('nk0:', nks[0])

    k2 = single_key(attack_enc(keys, range(4)))
    k2_1 = single_key(attack_enc1(keys1, range(4,8)))
    k2_2 = single_key(attack_enc(keys2, range(8,12)))
    k2_3 = single_key(attack_enc1(keys3, range(12,16)))
    
    '''print('\nk1:', k1)
    print('\nnks:', nks[3], '\n', nks[2], '\n', nks[1], '\n', nks[0])'''
    
    assert k2 == inv_permute_bits(nks[1])
    print('assertation pass k2 with nks[1].')
    exit
    
    assert k2_1 == inv_permute_bits(nks1[1])
    print('assertation pass k2_1 with nks1[1].')
    exit
    
    assert k2_2 == inv_permute_bits(nks2[1])
    print('assertation pass k2_2 with nks2[1].')
    exit
    
    assert k2_3 == inv_permute_bits(nks3[1])
    print('assertation pass k2_3 with nks3[1].')
    exit
    
    keys.append(k2)
    
    #k3 = single_key(attack_enc(keys, range(4)))
    k3 = attack_enc(keys, range(16))
    
    
    
        
    print('\n\nk3: ', k3)
    print('k2: ', k2)
    print('k1: ', k1)
    print('k0: ', k0)
    
    print('\nnormalised key schedule0:')
    for key in nks:
        print(inv_permute_bits(key))
        
    assert all(inv_permute_bits(nks[0])[nibble_idx] in k3[nibble_idx] for nibble_idx in range(32))
    
    #return
    
    #k3_1 = single_key(attack_enc1(keys1, range(4,8)))
    #k3_2 = single_key(attack_enc(keys2, range(8,12)))
    #k3_3 = single_key(attack_enc1(keys3, range(12,16)))
    
    '''print('\nk1:', k1)
    print('\nnks:', nks[3], '\n', nks[2], '\n', nks[1], '\n', nks[0])'''
    
    #assert k3 == inv_permute_bits(nks[0])
    #print('assertation pass k2 with nks[1].')
    #exit
    
    
    c.key_schedule = [nks[0], permute_bits(k2), permute_bits(k1), permute_bits(k0)]
    b = c.encrypt(pt)
    
    
    #c.key_schedule = [nks1[0], nks1[1], nks1[2], nks1[3]]
    #b1 = c.encrypt(pt)
    
    
    #c.key_schedule = [nks2[0], nks2[1], nks2[2], nks2[3]]
    #b2 = c.encrypt(pt)
    
    
    #c.key_schedule = [nks3[0], nks3[1], nks3[2], nks3[3]]
    #b3 = c.encrypt(pt)

    # key_schedule1 = c.key_schedule
    # print('\n\nnew key schedule:')
    # for key in key_schedule1:
    #     print(key)

    print('\ncip:', a)
    print('\ncip0:', b)
    #print('\ncip1:', b1)
    #print('\ncip2:', b2)
    #print('\ncip3:', b3)
    





    # set_fault(2, -1, 0, 0)
    # a = c.encrypt(ct)
    # set_fault(2, round_nr, bit_idx // 4, 1 << (bit_idx % 4)) 
    # b = c.encrypt(ct)

    # set_fault(-1, -1, 0, 0)






    # storing the actual cipher text in a
    '''set_fault(-1, -1, 0, 0)
    cip = c.encrypt(pt)

    # 25 round is for 3 rounds 
    round_nr = 25 

    trail_list = []
    cip_fcip_list = []

    # giving fault to generate the fault diff in the last round
    fault_list = [1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8]
    # fault_list = [1]

    # sfa_bit_list stores the nibble values in the inner state
    sfa_bit_list = []

    # depending upon the fault list storing the full trail list in trail_list
    for fault_idx, fault in enumerate(fault_list):
        # for the first half only and storing the faulty ciphertext in b
        # idx = random.randint(0,7)
        # if (fault_idx == 0):
        #     idx = 16
        # else:
        #     idx = fault_idx

        # if (fault_idx in ):
        #     idx = 16
        # else:
        #     idx = fault_idx

        idx = fault_idx

        set_fault(2, round_nr, idx, fault)
        fcip = c.encrypt(pt)

        # sfa_state() prints the inter state value at the time of fault
        sfa_bit_list.append(sfa_state())

        set_fault(-1, -1, 0, 0)

        cip_fcip_list.append([cip, fcip])
        trail_list = finding_dt(cip, fcip, fault, idx, trail_list)

    # for idx, i in enumerate(trail_list): 
    #     print('\n')
    #     print("trail list ", idx, ': ', i)

    # keyspace = [set(range(16)) for _ in range(32)]    
    r1_keyspace = [[i for i in range(16)] for _ in range(32)]    
    r1_keyspace = attack_r1(trail_list, r1_keyspace, cip)

    print('\n\noriginal key:')
    print(inv_permute_bits(key_schedule[3]))

    print('\n')
    for idx, i in enumerate(r1_keyspace):
        print('for nibble ', str(idx), ': ', i)
    print('\n\n')

    r2_keyspace = attack_r2(trail_list, r1_keyspace, cip_fcip_list)
    print('\n\n')

    # r3_keyspace = [[], []]
    # r3_keyspace = attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list)'''





    # # checking whether the original key is there  
    # original_key = inv_permute_bits(key)
    # qr_key = [0 for i in range(8)]

    # for qr in range(8):
    #     qr_key[qr] = ((original_key[qr + 0], original_key[qr + 8], original_key[qr + 16], original_key[qr + 24]))

    # left_half_key = ((qr_key[0], qr_key[2], qr_key[4], qr_key[6]))
    # right_half_key = ((qr_key[1], qr_key[3], qr_key[5], qr_key[7]))

    # for qr in range(8):
    #     if (qr_key[qr] in r2_keyspace[qr]):
    #         print('key is there for qr idx ', qr)


    # print('left half key:', left_half_key)
    # print('right half key:', right_half_key)
    # print('\n\n')

    # if (left_half_key in r3_keyspace[0]):
    #     print('eeeeeeee, left half key is in there.')

    # if (right_half_key in r3_keyspace[1]):
    #     print('eeeeeeee, right half key is in there.')








    # printing original key
    print('\n\noriginal key:')
    print('\n\n')
    for i in range(4):
        print(inv_permute_bits(key_schedule[i]))

        # # original round key
        # print(key_schedule[i])

    # print('\n\n', [[inv_permute_bits(key)[qr + 8*i] for i in range(4)] for qr in range(8)])


if __name__ == '__main__':
    main()
