# This is key recovery attack according to our work. In this prog we have used trail to find out the reduced keyspace. checking for whether second layer group 0 sboxes have all 2 bit reduction individually but in the last layer 0,8,16,24 has the combined key space strictly > 2^8. This is doing dfa.


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
    

# if the ele is in the list then return 1
def list_search(list1, list_ele):
    for i in list1:
        if (i == list_ele):
            return 1
    return 0

# key recovery attack on round 2
def attack_r2(trail_list, r1_keyspace, cip_fcip_list):    
    si = si_base    
    s = si.inverse()    

    # taking the product space of the corresponding key nibbles
    r2_keyspace = [list(product(*[r1_keyspace[(i + 8 * j)%32] for j in range(4)])) for i in range(8)]

    # giving the group idx for 2nd round
    quotient_idx_list = [i for i in range(8)]


    # making the nibble idx list at round 2 from groups of that round
    for group_idx in quotient_idx_list:
        # making the nibble list of the quotient group from the corresponding group idx
        nibble_idx_list = []
        for bit in range(4):
            nibble_idx_list.append(4*group_idx + bit)

        for nibble_idx in nibble_idx_list:
            for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):
                if (trail_list[cip_fcip_idx][1][0][nibble_idx] != 0):
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
                        # print('input diff: ', )
            
                        if (nibble_idx == 0):
                            dummy_list = []
                            for i in range(4):
                                if (list_search(r1_keyspace[nibble_idx], i) == 1):
                                    dummy_list.append(i)

                            for i in dummy_list:
                                in_diff = si(dec_cip[nibble_idx]^i) ^ si(dec_fcip[nibble_idx]^i)
         
                                # checking whether the input diff is same as the diff in trail or not
                                if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                    count = count+1
                                    break

                                else:
                                    # removing the key tuple if it does not satisfy the diff
                                    if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
                                        r2_keyspace[group_idx].remove(key4)

                        elif (nibble_idx == 10):
                            dummy_list = []
                            for i in range(4):
                                if (list_search(r1_keyspace[nibble_idx], i) == 1):
                                    dummy_list.append(i)

                            for i in dummy_list:
                                in_diff = si(dec_cip[nibble_idx]^i) ^ si(dec_fcip[nibble_idx]^i)
         
                                # checking whether the input diff is same as the diff in trail or not
                                if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                    count = count+1
                                    break

                                else:
                                    if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
                                        # removing the key tuple if it does not satisfy the diff
                                        r2_keyspace[group_idx].remove(key4)

                        elif (nibble_idx == 21):
                            dummy_list = []
                            for i in range(4):
                                if (list_search(r1_keyspace[nibble_idx], i) == 1):
                                    dummy_list.append(i)

                            for i in dummy_list:
                                in_diff = si(dec_cip[nibble_idx]^i) ^ si(dec_fcip[nibble_idx]^i)
         
                                # checking whether the input diff is same as the diff in trail or not
                                if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                    count = count+1
                                    break

                                else:
                                    # removing the key tuple if it does not satisfy the diff
                                    if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
                                        r2_keyspace[group_idx].remove(key4)

                        elif (nibble_idx == 31):
                            dummy_list = []
                            for i in range(4):
                                if (list_search(r1_keyspace[nibble_idx], i) == 1):
                                    dummy_list.append(i)

                            for i in dummy_list:
                                in_diff = si(dec_cip[nibble_idx]^i) ^ si(dec_fcip[nibble_idx]^i)
         
                                # checking whether the input diff is same as the diff in trail or not
                                if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                    count = count+1
                                    break

                                else:
                                    # removing the key tuple if it does not satisfy the diff
                                    if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
                                        r2_keyspace[group_idx].remove(key4)
                        else:
                            dummy_list = []
                            for i in range(4):
                                if (list_search(r1_keyspace[nibble_idx], i) == 1):
                                    dummy_list.append(i)

                            # print('dummy list:', dummy_list)
                            for i in dummy_list:
                                in_diff = si(dec_cip[nibble_idx]^i) ^ si(dec_fcip[nibble_idx]^i)
         
                                # checking whether the input diff is same as the diff in trail or not
                                if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                    count = count+1
                                    # when the conditon satisfies for the first class representator then it will not check for the other one
                                    break
                                else:
                                    # if the key4 is there but it doesnot satisfies the in diff condition and it becomes the last class repesentator then remove 
                                    if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
                                        r2_keyspace[group_idx].remove(key4)
         
        # print('\n\nlen of group ', group_idx, ': ', len(r2_keyspace[group_idx]))
         
        # # next is for printing purpose
        # print("for group ", str(group_idx), ": ")
        # for key4 in r2_keyspace[group_idx]:
        #     print(key4, end = ',  ') 

    return r2_keyspace


# # key recovery attack on round 2
# def attack_r2(trail_list, r1_keyspace, cip_fcip_list):    
#     si = si_base    
#     s = si.inverse()    

#     # taking the product space of the corresponding key nibbles
#     r2_keyspace = [list(product(*[r1_keyspace[(i + 8 * j)%32] for j in range(4)])) for i in range(8)]

#     # giving the group idx for 2nd round
#     quotient_idx_list = [i for i in range(8)]


#     # to store the reject dummy list class representators
#     r1_rej_dummy_list = [[] for i in range(32)]

#     # making the nibble idx list at round 2 from groups of that round
#     for group_idx in quotient_idx_list:
#         # making the nibble list of the quotient group from the corresponding group idx
#         nibble_idx_list = []
#         for bit in range(4):
#             nibble_idx_list.append(4*group_idx + bit)

#         for nibble_idx in nibble_idx_list:
#             for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):
#                 if (trail_list[cip_fcip_idx][1][0][nibble_idx] != 0):
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
#                         # print('input diff: ', )
            
#                         if (nibble_idx == 0):
#                             # making dummy list to store the class representators
#                             dummy_list = []
#                             for i in range(4):
#                                 if (list_search(r1_keyspace[nibble_idx], i) == 1):
#                                     dummy_list.append(i)

#                             count1 = 0
#                             for i in dummy_list:
#                                 in_diff = si(dec_cip[nibble_idx]^i) ^ si(dec_fcip[nibble_idx]^i)
         
#                                 # checking whether the input diff is same as the diff in trail or not
#                                 if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
#                                     count = count+1
#                                     count1 = count1 + 1

#                                 else:
#                                     if (len(dummy_list) > 1):
#                                         r1_rej_dummy_list[nibble_idx].append(i)

#                                     # # removing the key tuple if it does not satisfy the diff
#                                     # if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
#                                     #     r2_keyspace[group_idx].remove(key4)

#                             if (count1 == 0):
#                                 r2_keyspace[group_idx].remove(key4)
                                
#                         elif (nibble_idx == 10):
#                             dummy_list = []
#                             for i in range(4):
#                                 if (list_search(r1_keyspace[nibble_idx], i) == 1):
#                                     dummy_list.append(i)

#                             count1 = 0
#                             for i in dummy_list:
#                                 in_diff = si(dec_cip[nibble_idx]^i) ^ si(dec_fcip[nibble_idx]^i)
         
#                                 # checking whether the input diff is same as the diff in trail or not
#                                 if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
#                                     count = count+1
#                                     count1 = count1 + 1

#                                 else:
#                                     if (len(dummy_list) > 1):
#                                         r1_rej_dummy_list[nibble_idx].append(i)

#                                     # if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
#                                     #     # removing the key tuple if it does not satisfy the diff
#                                     #     r2_keyspace[group_idx].remove(key4)

#                             if (count1 == 0):
#                                 r2_keyspace[group_idx].remove(key4)
                                
#                         elif (nibble_idx == 21):
#                             dummy_list = []
#                             for i in range(4):
#                                 if (list_search(r1_keyspace[nibble_idx], i) == 1):
#                                     dummy_list.append(i)

#                             count1 = 0
#                             for i in dummy_list:
#                                 in_diff = si(dec_cip[nibble_idx]^i) ^ si(dec_fcip[nibble_idx]^i)
         
#                                 # checking whether the input diff is same as the diff in trail or not
#                                 if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
#                                     count = count+1
#                                     count1 = count1 + 1

#                                 else:
#                                     if (len(dummy_list) > 1):
#                                         r1_rej_dummy_list[nibble_idx].append(i)

#                                     # # removing the key tuple if it does not satisfy the diff
#                                     # if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
#                                     #     r2_keyspace[group_idx].remove(key4)

#                             if (count1 == 0):
#                                 r2_keyspace[group_idx].remove(key4)
                                
#                         elif (nibble_idx == 31):
#                             dummy_list = []
#                             for i in range(4):
#                                 if (list_search(r1_keyspace[nibble_idx], i) == 1):
#                                     dummy_list.append(i)

#                             count1 = 0
#                             for i in dummy_list:
#                                 in_diff = si(dec_cip[nibble_idx]^i) ^ si(dec_fcip[nibble_idx]^i)
         
#                                 # checking whether the input diff is same as the diff in trail or not
#                                 if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
#                                     count = count+1
#                                     count1 = count1 + 1

#                                 else:
#                                     if (len(dummy_list) > 1):
#                                         r1_rej_dummy_list[nibble_idx].append(i)

#                                     # # removing the key tuple if it does not satisfy the diff
#                                     # if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
#                                     #     r2_keyspace[group_idx].remove(key4)

#                             if (count1 == 0):
#                                 r2_keyspace[group_idx].remove(key4)
                                
#                         else:
#                             dummy_list = []
#                             for i in range(4):
#                                 if (list_search(r1_keyspace[nibble_idx], i) == 1):
#                                     dummy_list.append(i)

#                             count1 = 0
#                             # print('dummy list:', dummy_list)
#                             for i in dummy_list:
#                                 in_diff = si(dec_cip[nibble_idx]^i) ^ si(dec_fcip[nibble_idx]^i)
         
#                                 # checking whether the input diff is same as the diff in trail or not
#                                 if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
#                                     count = count+1
#                                     count1 = count1 + 1
#                                     # when the conditon satisfies for the first class representator then it will not check for the other one
#                                 else:
#                                     if (len(dummy_list) > 1):
#                                         r1_rej_dummy_list.append(i)

#                                     # # if the key4 is there but it doesnot satisfies the in diff condition and it becomes the last class repesentator then remove 
#                                     # if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
#                                     #     r2_keyspace[group_idx].remove(key4)
#                             if (count1 == 0):
#                                 r2_keyspace[group_idx].remove(key4)
                                
         
#         # print('\n\nlen of group ', group_idx, ': ', len(r2_keyspace[group_idx]))
         
#         # # next is for printing purpose
#         # print("for group ", str(group_idx), ": ")
#         # for key4 in r2_keyspace[group_idx]:
#         #     print(key4, end = ',  ') 


#     # # storing the equivalance classes in the list
#     # eq_cls_list = [[0, 5, 0xa, 0xf], [1, 4, 0xb, 0xe], [2, 7, 8, 0xd], [3, 6, 9, 0xc]]

#     for nibble_idx in range(32):
#         print('for nibble ', nibble_idx, ': ', set(r1_rej_dummy_list[nibble_idx]))
#     #     # for cls in (r1_rej_dummy_list[nibble_idx]):
#     #     #     for ele in eq_cls_list[cls]: 
#     #     #         if (ele in r1_keyspace[nibble_idx]):
#     #     #             r1_keyspace[nibble_idx].remove(ele)

                    
#     # # printing r1 keyspace
#     # print('\n')
#     # for idx, i in enumerate(r1_keyspace):
#     #     print('for nibble ', str(idx), ': ', i)


#     return r2_keyspace


# 3rd round attack on default cipher
def attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list):    
    si = si_base    
    s = si.inverse()    

    # making the nibble list from the corresponding group idx
    # nibble_idx_list = [[i for i in range(16)], [i for i in range(16, 32)]]
    nibble_idx_list = [[0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7, 12, 13, 14, 15], [20, 21, 22, 23, 28, 29, 30, 31, 16, 17, 18, 19, 24, 25, 26, 27]]

    r3_keyspace = [[], []]

    # r1 dummy list is to store the cls representatives of r1 keyspace
    r1_dummy_list = [[] for i in range(32)]
    for nibble_idx in range(32):
        for i in range(4):
            if (i in r1_keyspace[nibble_idx]):
                r1_dummy_list[nibble_idx].append(i)

    # # in the third last group there are only 2 groups, 0 and 1 
    # for group_idx_last in [0, 1]:
    for group_idx_last in [0]:
        # producting the key space of 3rd last round
        dummy_r3 = list(product(*[r2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))

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

                    # if (nibble_idx == 5):
                    #     print('dummy r3: ', dummy_r3)
                    # print('')
                    for key_idx, key in enumerate(dummy_r3):
                        if(key == 9999):
                            continue

                        # forming the last round key from the group idx
                        last_key = [0 for i in range(32)]
                        for group_idx_mid in range(4):
                            for key_0 in range(4):
                                last_key[group_idx_last + 2*group_idx_mid + 8*key_0] = key[group_idx_mid][key_0]

                        # eq key is the product of the equivalence class keys
                        #eq_key_list = list(product(*[r1_dummy_list[i] for i in range(32)]))


                        # reduce the keyspace at first for these nibbles then do this for other nibbles
                        if(nibble_idx in [0, 1, 2, 3, 8, 9, 10, 11, 20, 21, 22, 23, 28, 29, 30, 31]):
                            # last layer
                            dec_cip = inv_permute_bits(cip)
                            dec_fcip = inv_permute_bits(fcip)

                            dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                            dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                            # 2nd last layer
                            dec_cip = inv_sub_cells(dec_cip)
                            dec_fcip = inv_sub_cells(dec_fcip)
                            
                            dec_cip = inv_permute_bits(dec_cip)
                            dec_fcip = inv_permute_bits(dec_fcip)

                            dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                            dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                            # 3rd last layer
                            dec_cip = inv_sub_cells(dec_cip)
                            dec_fcip = inv_sub_cells(dec_fcip)
                            
                            dec_cip = inv_permute_bits(dec_cip)
                            dec_fcip = inv_permute_bits(dec_fcip)
                                
                            if(group_idx_last == 0):
                                if ((nibble_idx%2) == 0):
                                    in_diff = si(dec_cip[nibble_idx]^last_key[nibble_idx]) ^ si(dec_fcip[nibble_idx]^last_key[nibble_idx])


                                    # for printing purpose
                                    if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                        if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                            print('left key is there.')
                                        if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                            print('right key is there.')
                                        count = count + 1

                                    if(in_diff != trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                        dummy_r3[key_idx] = 9999

                                else:
                                    for dummy_ele in r1_dummy_list[nibble_idx]:
                                        in_diff = si(dec_cip[nibble_idx]^dummy_ele) ^ si(dec_fcip[nibble_idx]^dummy_ele)
                                    
                                        # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                        if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                            if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                print('left key is there.')
                                            if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                print('right key is there.')

                                            count = count + 1
                                            break

                                        # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
                                        if (dummy_ele == r1_dummy_list[nibble_idx][len(r1_dummy_list[nibble_idx]) - 1]):
                                            # rej_count = rej_count + 1
                                            dummy_r3[key_idx] = 9999
                                            
                            # for nibbles 20, 21, 22, 23, 28, 29, 30, 31
                            else:
                                # for nibbles 21, 23, 29, 31
                                if ((nibble_idx%2) == 1):
                                    in_diff = si(dec_cip[nibble_idx]^last_key[nibble_idx]) ^ si(dec_fcip[nibble_idx]^last_key[nibble_idx])


                                    # for printing purpose
                                    if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                        if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                            print('left key is there.')
                                        if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                            print('right key is there.')
                                        count = count + 1

                                    if(in_diff != trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                        dummy_r3[key_idx] = 9999

                                # for nibbles 20, 22, 28, 30
                                else:
                                    for dummy_ele in r1_dummy_list[nibble_idx]:
                                        in_diff = si(dec_cip[nibble_idx]^dummy_ele) ^ si(dec_fcip[nibble_idx]^dummy_ele)
                                    
                                        # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                        if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                            if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                print('left key is there.')
                                            if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                print('right key is there.')

                                            count = count + 1
                                            break

                                        # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
                                        if (dummy_ele == r1_dummy_list[nibble_idx][len(r1_dummy_list[nibble_idx]) - 1]):
                                            # rej_count = rej_count + 1
                                            dummy_r3[key_idx] = 9999


                        # for nibble 4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 26, 27
                        if(nibble_idx in [4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 26, 27]):
                            eq_key_list = []
                            if(len(r2_keyspace[nibble_idx//4]) > 16):
                                eq_key_list = r2_keyspace[nibble_idx//4].copy()
                            else:
                                eq_key_list.append(r2_keyspace[nibble_idx//4][0])

                            #check here
                            '''eq_key_list = []
                            dummy_eq_key_list = [[] for i in range(4)]
                            if(len(r2_keyspace[nibble_idx//4]) > 16):
                                #eq_key = r2_keyspace[nibble_idx//4][0].copy()

                                nibble_check_list = [nibble_idx//4 + 8*i for i in range(4)]

                                for pos, nibble_check_idx in enumerate(nibble_check_list):
                                    if (len(r1_keyspace[nibble_idx//4]) > 4):
                                        dummy_eq_key_list[pos].append(r2_keyspace[nibble_idx//4][0][nibble_check_idx])
                                    else:
                                        dummy_eq_key_list[pos].append(r2_keyspace[nibble_idx//4][0][nibble_check_idx])

                            # dummy key list product

                            #if(len(r2_keyspace[nibble_idx//4]) > 16):
                                #eq_key_list = list(product(*[r2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))
                            else:
                                dummy_eq_key_list.append(r2_keyspace[nibble_idx//4][0])
                                
                            eq_key_list = list(product(*[dummy_eq_key_list[i] for i in range(4)]))'''

                            for eq_key in eq_key_list:
                                # last layer
                                dec_cip = inv_permute_bits(cip)
                                dec_fcip = inv_permute_bits(fcip)

                                dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                                dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                                
                                dec_cip = inv_sub_cells(dec_cip)
                                dec_fcip = inv_sub_cells(dec_fcip)
                                
                                # 2nd last layer
                                dec_cip = inv_permute_bits(dec_cip)
                                dec_fcip = inv_permute_bits(dec_fcip)
                                
                                # making mid key from the 0th ele of r2 keyspace
                                mid_key = [0 for i in range(32)]
                                for qr in range(8):
                                    for i in range(4):
                                        mid_key[qr + 8*i] = r2_keyspace[qr][0][i]
                                 
                                for i in range(4):
                                    mid_key[nibble_idx//4+8*i] = eq_key[i]
                                    
                                dec_cip = [dec_cip^mid_key for dec_cip, mid_key in zip(dec_cip, mid_key)]
                                dec_fcip = [dec_fcip^mid_key for dec_fcip, mid_key in zip(dec_fcip, mid_key)]

                                
                                # 3rd last layer
                                dec_cip = inv_sub_cells(dec_cip)
                                dec_fcip = inv_sub_cells(dec_fcip)
                                    
                                dec_cip = inv_permute_bits(dec_cip)
                                dec_fcip = inv_permute_bits(dec_fcip)


                                flag1 = 1
                                # for the left half nibbles 4, 5, 6, 7, 12, 13, 14, 15, 16,17,18,19,24,25,26,27 
                                if (group_idx_last == 0):
                                    # for nibbles 4, 6, 12, 14
                                    # flag1 = 0
                                    if ((nibble_idx%2) == 0):
                                        in_diff = si(dec_cip[nibble_idx]^last_key[nibble_idx]) ^ si(dec_fcip[nibble_idx]^last_key[nibble_idx])

                                        # for printing purpose
                                        if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                            if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                print('left key is there.')
                                            if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                print('right key is there.')
                                            count = count + 1
                                            flag1 = 0
                                            break
                                            
                                    # for nibbles 5, 7, 13, 15
                                    else:
                                        # flag1 is used to break the for loop in r1 dummy list
                                        flag1 = 1

                                        for dummy_ele in r1_dummy_list[nibble_idx]:
                                            in_diff = si(dec_cip[nibble_idx]^dummy_ele) ^ si(dec_fcip[nibble_idx]^dummy_ele)
                                        
                                            # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                            if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                                if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                    print('left key is there.')
                                                if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                    print('right key is there.')

                                                count = count + 1
                                                flag1 = 0
                                                break

                                        if(flag1 == 0):
                                            break

                                else:
                                    # for nibbles 17, 19, 25, 27
                                    if ((nibble_idx%2) == 1):
                                        in_diff = si(dec_cip[nibble_idx]^last_key[nibble_idx]) ^ si(dec_fcip[nibble_idx]^last_key[nibble_idx])

                                        # for printing purpose
                                        if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                            if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                print('left key is there.')
                                            if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                print('right key is there.')

                                            count = count + 1
                                            flag1 = 0
                                            break
                                            
                                    else:
                                        # for nibbles 16,18,24,26
                                        for dummy_ele in r1_dummy_list[nibble_idx]:
                                            in_diff = si(dec_cip[nibble_idx]^dummy_ele) ^ si(dec_fcip[nibble_idx]^dummy_ele)
                                        
                                            # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                            if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                                if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                    print('left key is there.')
                                                if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                    print('right key is there.')

                                                count = count + 1
                                                flag1 = 0
                                                break

                                        if(flag1 == 0):
                                            break

                                if (eq_key == eq_key_list[len(eq_key_list) - 1]):
                                    dummy_r3[key_idx] = 9999
                                    
                                    
                    print('count: ', count)
                    print('rej count: ', rej_count)

            # dummy1 = []
            # for key in dummy_r3:
            #     if(key == 9999):
            #         continue
            #     if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
            #         print('left key is there in dummy r3.')
            #     dummy1.append(key)
            # print('dummy1 len: ', len(dummy1))
            # print('distinct ele in dummy1 len: ', len(set(dummy1)))

            # if (nibble_idx == 11):
            #     print('keyspace at nibble 12: ', dummy1)





        for key in dummy_r3:
            if(key != 9999):
                r3_keyspace[group_idx_last].append(key)


        # print('len r3 keyspace ', group_idx_last, ': ', len(r3_keyspace[group_idx_last]))

        # print('r3 keyspace ', group_idx_last, ': ')
        # for i in r3_keyspace[group_idx_last]:
        #     print(i, end = ', ')

    print('\n\n')
    return r3_keyspace


    # # for printing purpose
    # print('\nprinting here for the key.')
    # for i in r3_keyspace[0]:
    #     if (i == ((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8))):
    #         print('\n\noriginal key is here for left half.')

    # for i in r3_keyspace[1]:
    #     if (i == ((13, 15, 12, 8), (6, 11, 8, 7), (13, 6, 11, 13), (5, 14, 6, 0))):
    #         print('\n\noriginal key is here for right half.')
    # print('\n\n')











#                             # checking whether the input diff is same as the diff in trail or not
#                             if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                 # if ((group_idx_last == 0) and (key == ((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8)))):
#                                 #     print('\n\noriginal key is here for left half.')

#                                 # if ((group_idx_last == 1) and (key == ((13, 15, 12, 8), (6, 11, 8, 7), (13, 6, 11, 13), (5, 14, 6, 0)))):
#                                 #     print('\n\noriginal key is here for right half.')

#                                 # accept_key_list.append(key)
#                                 count = count+1
#                             else:
#                                 # removing the key tuple if it does not satisfy the diff
#                                 dummy_r3[key_idx] = 9999
#                                 rej_count = rej_count+1

#                         else:
#                             for i in range(32):
#                                 mid_key[i] = eq_key[i]
                            




#                             # if the nibbles are from the following nibble idx then the last key will be from the right half but the mid key depends upon the left
#                             # print('\n\nr1 dummy list:', r1_dummy_list)

#                             if (nibble_idx in [4, 5, 6, 7, 12, 13, 14, 15]):
#                                 key4 = (r2_keyspace[1][0], r2_keyspace[3][0], r2_keyspace[5][0], r2_keyspace[7][0])

#                                 for group_idx_mid in range(4):
#                                     for key_0 in range(4):
#                                         mid_key[1 + 2*group_idx_mid + 8*key_0] = key4[group_idx_mid][key_0]
#                             # similarly if the nibbles are from the following nibble idx then the last key will be from the left half but the mid key depends upon the right
#                             else:
#                                 key4 = (r2_keyspace[0][0], r2_keyspace[2][0], r2_keyspace[4][0], r2_keyspace[6][0])
#                                 for group_idx_mid in range(4):
#                                     for key_0 in range(4):
#                                         mid_key[0 + 2*group_idx_mid + 8*key_0] = key4[group_idx_mid][key_0]

#                         # last layer
#                         dec_cip = inv_permute_bits(cip)
#                         dec_fcip = inv_permute_bits(fcip)

#                         dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
#                         dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

#                         # 2nd last layer
#                         dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
#                         dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

#                         dec_cip = [dec_cip^mid_key for dec_cip, mid_key in zip(dec_cip, mid_key)]
#                         dec_fcip = [dec_fcip^mid_key for dec_fcip, mid_key in zip(dec_fcip, mid_key)]

#                         # 3rd last layer
#                         dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
#                         dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))


#                         in_diff = si(dec_cip[nibble_idx]^r2_keyspace[nibble_idx%8][0][nibble_idx//8]) ^ si(dec_fcip[nibble_idx]^r2_keyspace[nibble_idx%8][0][nibble_idx//8])

#                         # checking whether the input diff is same as the diff in trail or not
#                         if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                             # if ((group_idx_last == 0) and (key == ((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8)))):
#                             #     print('\n\noriginal key is here for left half.')

#                             # if ((group_idx_last == 1) and (key == ((13, 15, 12, 8), (6, 11, 8, 7), (13, 6, 11, 13), (5, 14, 6, 0)))):
#                             #     print('\n\noriginal key is here for right half.')

#                             # accept_key_list.append(key)
#                             count = count+1
#                         else:
#                             # removing the key tuple if it does not satisfy the diff
#                             dummy_r3[key_idx] = 9999
#                             rej_count = rej_count+1

#                     # dummy_r3 = set(dummy_r3).intersection(set(accept_key_list))
#                     # dummy_r3 = list(dummy_r3)

#                     # print('len: ', len(dummy_r3))
#                     # print('count: ', count)
#                     # print('reject count: ', rej_count)

#             # if (((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8)) in dummy_r3):
#             #     print('for nibble idx ', nibble_idx, ' key nibble of group 2 is here.')



#         for key in dummy_r3:
#             if(key != 9999):
#                 r3_keyspace[group_idx_last].append(key)


#     # # for printing purpose
#     # print('\nprinting here for the key.')
#     # for i in r3_keyspace[0]:
#     #     if (i == ((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8))):
#     #         print('\n\noriginal key is here for left half.')

#     # for i in r3_keyspace[1]:
#     #     if (i == ((13, 15, 12, 8), (6, 11, 8, 7), (13, 6, 11, 13), (5, 14, 6, 0))):
#     #         print('\n\noriginal key is here for right half.')
#     # print('\n\n')





#     update_r3_keyspace = [[], []]
#     nibble_idx_list = [[4, 5, 6, 7, 12, 13, 14, 15], [16, 17, 18, 19, 24, 25, 26, 27]]

#     # in the third last group there are only 2 groups, 0 and 1 
#     for group_idx_last in [0, 1]:
#         # producting the key space of 3rd last round
#         dummy_r3 = []
#         for i in r3_keyspace[group_idx_last]:
#             dummy_r3.append(i)

#         for nibble_idx in nibble_idx_list[group_idx_last]:
#             # for each cip and faulty cip text pair
#             print('\nfor nibble idx:', nibble_idx)
#             for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):

#                # if the diff appears in the nibble idx, then do the following 
#                 if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
#                     # extract cip and faulty cip
#                     cip = cip_fcip[0]
#                     fcip = cip_fcip[1]

#                     # initializing the count for each key of r3_keyspace
#                     count = 0
#                     rej_count = 0

#                     # # append in this list only when a key is accepted
#                     # accept_key_list = []

#                     for key_idx, key in enumerate(dummy_r3):
#                         if(key == 9999):
#                             continue

#                         # forming the last round key from the group idx
#                         last_key = [0 for i in range(32)]
#                         for group_idx_mid in range(4):
#                             for key_0 in range(4):
#                                 last_key[group_idx_last + 2*group_idx_mid + 8*key_0] = key[group_idx_mid][key_0]

#                         # forming the mid round key from the group idx
#                         mid_key = [0 for i in range(32)]


#                         # making the mid key for the nibble idxs
#                         if (nibble_idx in [4, 5, 6, 7, 12, 13, 14, 15]):
#                             for mid_nibble in [1, 9, 17, 25, 3, 11, 19, 27]:
#                                 prod_cls_rep = list(product(*[r1_dummy_list[mid_nibble]]))

#                             print('\n\nprod cls rep: ', prod_cls_rep)


#                             key4 = r3_keyspace[(group_idx_last+1)%2][0]

#                             for group_idx_mid in range(4):
#                                 for key_0 in range(4):
#                                     mid_key[1 + 2*group_idx_mid + 8*key_0] = key4[group_idx_mid][key_0]
#                         # similarly if the nibbles are from the following nibble idx then the last key will be from the left half but the mid key depends upon the right
#                         else:
#                             key4 = r3_keyspace[(group_idx_last+1)%2][0]
#                             for group_idx_mid in range(4):
#                                 for key_0 in range(4):
#                                     mid_key[0 + 2*group_idx_mid + 8*key_0] = key4[group_idx_mid][key_0]

#                         # last layer
#                         dec_cip = inv_permute_bits(cip)
#                         dec_fcip = inv_permute_bits(fcip)

#                         dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
#                         dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

#                         # 2nd last layer
#                         dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
#                         dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

#                         dec_cip = [dec_cip^mid_key for dec_cip, mid_key in zip(dec_cip, mid_key)]
#                         dec_fcip = [dec_fcip^mid_key for dec_fcip, mid_key in zip(dec_fcip, mid_key)]

#                         # 3rd last layer
#                         dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
#                         dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))

#                         in_diff = si(dec_cip[nibble_idx]^r2_keyspace[nibble_idx%8][0][nibble_idx//8]) ^ si(dec_fcip[nibble_idx]^r2_keyspace[nibble_idx%8][0][nibble_idx//8])

#                         # checking whether the input diff is same as the diff in trail or not
#                         if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                             # if ((group_idx_last == 0) and (key == ((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8)))):
#                             #     print('\n\noriginal key is here for left half.')

#                             # if ((group_idx_last == 1) and (key == ((13, 15, 12, 8), (6, 11, 8, 7), (13, 6, 11, 13), (5, 14, 6, 0)))):
#                             #     print('\n\noriginal key is here for right half.')

#                             # accept_key_list.append(key)
#                             count = count+1
#                         else:
#                             # removing the key tuple if it does not satisfy the diff
#                             dummy_r3[key_idx] = 9999
#                             rej_count = rej_count+1

#                     # dummy_r3 = set(dummy_r3).intersection(set(accept_key_list))
#                     # dummy_r3 = list(dummy_r3)

# #                     print('len: ', len(dummy_r3))
# #                     print('count: ', count)
# #                     print('reject count: ', rej_count)

#             # if (((0, 14, 2, 3), (6, 14, 1, 13), (9, 13, 8, 10), (0, 10, 7, 8)) in dummy_r3):
#             #     print('for nibble idx ', nibble_idx, ' key nibble of group 2 is here.')



#         for key in dummy_r3:
#             if(key != 9999):
#                 update_r3_keyspace[group_idx_last].append(key)



#     # for printing purpose
#     print('\n\nkeys for the left half:')
#     for i in update_r3_keyspace[0]:
#         print(i)
#     print('keys for the right half:')
#     for i in update_r3_keyspace[1]:
#         print(i)

#     print('\n\n')

#     return update_r3_keyspace



def main():
    global c, pt, key

    # # for random key and plaintext
    pt = [random.randint(0,15) for _ in range(32)]
    key = [secrets.randbelow(16) for _ in range(32)]

    # # for checking with fixed msg and key
    # pt = [11, 9, 10, 13, 1, 12, 13, 11, 2, 15, 13, 5, 10, 0, 0, 10, 0, 5, 2, 11, 14, 12, 2, 13, 1, 1, 1, 1, 15, 10, 14, 13]
    # key = [4, 1, 14, 11, 8, 6, 5, 0, 4, 5, 15, 12, 6, 0, 11, 14, 10, 8, 14, 6, 9, 11, 11, 8, 7, 13, 11, 14, 0, 15, 4, 9]

    # pt = [10, 13, 13, 15, 9, 2, 6, 9, 14, 9, 4, 1, 10, 5, 11, 7, 10, 1, 12, 12, 7, 2, 10, 15, 3, 1, 11, 2, 8, 1, 1, 4]
    # key = [1, 10, 5, 15, 0, 1, 11, 3, 5, 14, 15, 5, 13, 14, 14, 10, 6, 0, 3, 6, 1, 15, 4, 13, 15, 5, 9, 1, 12, 6, 5, 4]

    # pt = [0, 6, 6, 5, 4, 11, 0, 14, 15, 2, 9, 6, 0, 9, 9, 0, 5, 5, 8, 10, 11, 7, 8, 7, 11, 6, 11, 6, 10, 7, 7, 9]
    # key = [10, 11, 15, 11, 7, 13, 4, 14, 2, 6, 2, 1, 0, 2, 12, 1, 5, 11, 14, 10, 13, 8, 4, 2, 5, 0, 8, 8, 11, 6, 14, 4]

    # pt = [6, 10, 0, 8, 9, 1, 11, 12, 15, 14, 1, 8, 14, 2, 1, 13, 15, 5, 7, 12, 11, 15, 14, 11, 3, 7, 4, 11, 6, 8, 6, 5]
    # key = [11, 7, 8, 6, 14, 12, 10, 0, 3, 1, 8, 6, 14, 15, 6, 6, 14, 0, 8, 7, 12, 8, 8, 0, 2, 11, 15, 11, 7, 1, 14, 8]

    # pt = [13, 0, 9, 8, 0, 2, 5, 8, 3, 12, 8, 11, 12, 6, 0, 4, 7, 7, 7, 9, 8, 8, 13, 1, 12, 14, 4, 14, 14, 10, 2, 12]
    # key = [1, 9, 5, 0, 2, 1, 6, 3, 5, 9, 15, 11, 10, 12, 11, 14, 10, 8, 2, 5, 9, 7, 6, 7, 5, 6, 3, 1, 9, 7, 6, 14]

    #pt = [14, 6, 1, 3, 1, 1, 15, 9, 13, 3, 0, 7, 2, 10, 14, 0, 15, 14, 13, 15, 10, 6, 6, 12, 1, 1, 0, 10, 10, 10, 13, 10]
    #key = [11, 2, 2, 6, 12, 6, 3, 6, 3, 11, 1, 9, 2, 3, 4, 9, 7, 13, 1, 1, 8, 11, 8, 12, 11, 4, 3, 2, 15, 10, 4, 2]




    # print('msg: ', pt)
    # print('key: ', key)
    # print('\n\n')

    # # for fixed plaintext and key
    # pt = [(i+5)%16 for i in range(32)]
    # key = [i%16 for i in range(32)]

    c = DefaultCipher(key)

    # storing the actual cipher text in a
    set_fault(-1, -1, 0, 0)
    cip = c.encrypt(pt)

    # 25 round is for 3 rounds 
    round_nr = 25 

    trail_list = []
    cip_fcip_list = []

    # giving fault to generate the fault diff in the last round
    #fault_list = [1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8]
    fault_list = [1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8]

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

    print('\n')
    for idx, i in enumerate(r1_keyspace):
        print('for nibble ', str(idx), ': ', i)

    r2_keyspace = attack_r2(trail_list, r1_keyspace, cip_fcip_list)



    # checking whether the original key is there in the r2 keyspace or not
    # print('\n\n')
    original_key = inv_permute_bits(key)
    qr_key = [0 for i in range(8)]


    # checksum is for checking whether the key is in the qr group or not
    # print('\n\n')
    r2_check_sum = 0
    for qr in range(8):
        qr_key[qr] = ((original_key[qr + 0], original_key[qr + 8], original_key[qr + 16], original_key[qr + 24]))
        if (qr_key[qr] in r2_keyspace[qr]):
            # print('key is there for ', qr)
            r2_check_sum = r2_check_sum + 1  

    # if (r2_check_sum == 8):
    #     return 1
        
    # print('msg: ', pt)
    # print('key: ', key)
    # print('\n\n')

    # return 0


    r3_keyspace = [[], []]
    r3_keyspace = attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list)


    left_half_key = ((qr_key[0], qr_key[2], qr_key[4], qr_key[6]))
    right_half_key = ((qr_key[1], qr_key[3], qr_key[5], qr_key[7]))

    print('left half key:', left_half_key)
    print('right half key:', right_half_key)

    print('\n\n')
    if (left_half_key in r3_keyspace[0]):
        print('eeeeeeee, left half key is in there.')

    if (right_half_key in r3_keyspace[1]):
        print('eeeeeeee, right half key is in there.')








    # printing original key
    print('\n\noriginal key:')
    
    print(inv_permute_bits(key))
    print('\n\n', [[inv_permute_bits(key)[qr + 8*i] for i in range(4)] for qr in range(8)])


if __name__ == '__main__':
    # for exp in range(100):
    for exp in range(1):
        out = main()
        if (out == 1):
            print('exp ', exp, ' success.')
        else:
            print('exp ', exp, ' fails.')
            break

