# This is key recovery attack according to our work. In this prog we have used trail to find out the reduced keyspace. checking for whether second layer group 0 sboxes have all 2 bit reduction individually but in the last layer 0,8,16,24 has the combined key space strictly > 2^8


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

def get_delta_enc(round_nr: int, idx: int, delta: int):
    set_fault(2, -1, idx, delta)
    a = c.encrypt(pt)
    set_fault(2, round_nr, idx, delta)
    b = c.encrypt(pt)

    set_fault(-1, -1, 0, 0)

    a = inv_permute_bits(a)
    b = inv_permute_bits(b)

    return a, b, [aa^bb for aa,bb in zip(a,b)]

def inv_sbox_round(out):
    inv_ddt = [[0], [10, 12], [13, 11], [1, 7], [5, 3], [15], [14, 8], [2, 4], [11, 13], [7, 1], [6], [12, 10], [8, 14], [4, 2], [3, 5], [9]]

    inp = []
    for nib in out:
        inp.append(inv_ddt[nib])

    return inp

# function checks whether given two lists are equal or not. 
def list_eq(list1, list2):
    if len(list1) != len(list2):
        return 0

    for pos in range(len(list1)):
        if list1[pos] != list2[pos]:
            return 0
    return 1


# returns positionwise intersection of the given two lists
def list_intersection(list1, list2):
    intersection_list = [0 for _ in range(len(list1))]

    if len(list1) != len(list2):
        return intersection_list 

    for pos in range(len(list1)):
        if list1[pos] == list2[pos]:
            intersection_list[pos] = list1[pos]
    return intersection_list


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
def finding_dt(a, b, delta: int, idx, trail_list):
    # ddt table for default
    ddt = [[0], [3, 9], [7, 13], [14, 4], [13, 7], [4, 14], [10], [9, 3], [12, 6], [15], [1, 11], [8, 2], [11, 1], [2, 8], [6, 12], [5]]
    inv_ddt = [[0], [10, 12], [13, 11], [1, 7], [5, 3], [15], [14, 8], [2, 4], [11, 13], [7, 1], [6], [12, 10], [8, 14], [4, 2], [3, 5], [9]]


    # depending upon the input diff at idx, the output diff at idx pos of the following list at 4th last round can occur 
    scnd_last_input_diff = [[1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0], [1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2,     0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0], [1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0], [1, 0, 1,     0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0], [2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0,     1, 0, 1, 0, 1, 0], [2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0], [2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0,     8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0], [2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0], [4, 0, 4, 0, 4, 0,     4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0], [4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2    , 0, 2, 0], [4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0], [4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1    , 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0], [8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0], [8, 0, 8, 0, 8, 0, 8, 0, 1    , 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0], [8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4,     0], [8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0], [0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0,     4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8], [0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8], [0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0,     2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8], [0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8], [0,     2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1], [0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8,     0, 1, 0, 1, 0, 1, 0, 1], [0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1], [0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4,     0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1], [0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2], [0, 4, 0, 4,     0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2], [0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0    , 2, 0, 2, 0, 2], [0, 4, 0, 4, 0, 4, 0, 4, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2], [0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0    , 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4], [0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4], [0, 8, 0, 8, 0, 8, 0    , 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 4, 0, 4], [0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0,     4, 0, 4]] 


    # taking the output difference of the last layer
    cip_diff = [aa^bb for aa,bb in zip(a,b)]

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
    # print('\n')

    # print(fourth_layer_input)
    # print(fourth_layer_output)

    # storing the trails of 4 layers in trail_list
    dummy_trail_list = []
    dummy_trail_list.append([frst_layer_input, inv_permute_bits(mid_layer_input)])
    dummy_trail_list.append([mid_layer_input, inv_permute_bits(third_layer_input)])
    dummy_trail_list.append([third_layer_input, third_layer_output])
    dummy_trail_list.append([fourth_layer_input, fourth_layer_output])
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

        fourth_layer_input = trail[3][0]
        fourth_layer_output = trail[3][1]

        for i in range(32):
            if fourth_layer_input[i] != 0:
                dummy_list = [fourth_layer_input[i], fourth_layer_output[i]]
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


def find_scnd_last_layer_diff_list(trail_list): 
    diff_list = [[] for _ in range(32)]

    for trail in trail_list:
        mid_layer_input = trail[1][0]
        mid_layer_output = trail[1][1]

        for i in range(32):
            # if the mid layer input is non-zero then put it in diff list
            if mid_layer_input[i] != 0:
                dummy_list = [mid_layer_input[i], mid_layer_output[i]]
                if dummy_list not in diff_list[i]:
                    diff_list[i].append(dummy_list)

    return diff_list


def get_delta_dec(round_nr: int, idx: int, delta: int):
    ct = pt
    set_fault(2, -1, idx, delta)
    a = c.decrypt(ct)
    set_fault(2, round_nr, idx, delta)
    b = c.decrypt(ct)

    set_fault(-1, -1, 0, 0)

    a = permute_bits(sub_cells(a))
    b = permute_bits(sub_cells(b))

    return a, b, [aa^bb for aa,bb in zip(a,b)]

def get_keyset(a, b, delta_in, sbox):
    keys = set()
    sbox_inv = sbox.inverse()

    for k_guess in range(16):
        # print(si(a ^ k_guess) ^ si(b ^ k_guess), "==", delta_in)
        if sbox_inv(a ^ k_guess) ^ sbox_inv(b ^ k_guess) == delta_in:
            keys.add(k_guess)

    return keys


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
                if (trail_list[cip_fcip_idx][2][0][nibble_idx] != 0):
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
                                if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
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
                                if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
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
                                if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
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
                                if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
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
                                if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
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
    for group_idx_last in [0,1]:
        # producting the key space of 3rd last round
        dummy_r3 = list(product(*[r2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))

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
                                    if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                        '''if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                            print('left key is there.')
                                        if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                            print('right key is there.')'''
                                        count = count + 1

                                    if(in_diff != trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                        dummy_r3[key_idx] = 9999

                                else:
                                    for dummy_ele in r1_dummy_list[nibble_idx]:
                                        in_diff = si(dec_cip[nibble_idx]^dummy_ele) ^ si(dec_fcip[nibble_idx]^dummy_ele)
                                    
                                        # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                        if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                            '''if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                print('left key is there.')
                                            if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                print('right key is there.')'''

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
                                    if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                        '''if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                            print('left key is there.')
                                        if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                            print('right key is there.')'''
                                        count = count + 1

                                    if(in_diff != trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                        dummy_r3[key_idx] = 9999

                                # for nibbles 20, 22, 28, 30
                                else:
                                    for dummy_ele in r1_dummy_list[nibble_idx]:
                                        in_diff = si(dec_cip[nibble_idx]^dummy_ele) ^ si(dec_fcip[nibble_idx]^dummy_ele)
                                    
                                        # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                        if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                            '''if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                print('left key is there.')
                                            if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                print('right key is there.')'''

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
                                        if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                            '''if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                print('left key is there.')
                                            if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                print('right key is there.')'''
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
                                            if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                                '''if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                    print('left key is there.')
                                                if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                    print('right key is there.')'''

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
                                        if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                            '''if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                print('left key is there.')
                                            if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                print('right key is there.')'''

                                            count = count + 1
                                            flag1 = 0
                                            break
                                            
                                    else:
                                        # for nibbles 16,18,24,26
                                        for dummy_ele in r1_dummy_list[nibble_idx]:
                                            in_diff = si(dec_cip[nibble_idx]^dummy_ele) ^ si(dec_fcip[nibble_idx]^dummy_ele)
                                        
                                            # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                            if(in_diff == trail_list[cip_fcip_idx][1][0][nibble_idx]):
                                                '''if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                                                    print('left key is there.')
                                                if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
                                                    print('right key is there.')'''

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


        print('len r3 keyspace ', group_idx_last, ': ', len(r3_keyspace[group_idx_last]))

        print('r3 keyspace ', group_idx_last, ': ')
        for i in r3_keyspace[group_idx_last]:
            print(i, end = ', ')

    print('\n\n')
    return r3_keyspace


# 4th round attack on default cipher for checking the sfa
def attack_r4(trail_list, r3_keyspace, r2_keyspace, r1_keyspace, cip_fcip_list):    
    si = si_base    
    s = si.inverse()    

    full_r3_keyspace = list(product(*[r3_keyspace[i] for i in range(2)]))

    nibble_idx_list = [i for i in range(32)]


    # see about the nibble idx seems here is the prob.  
    for nibble_idx in nibble_idx_list:
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
                for key_idx, key in enumerate(full_r3_keyspace):
                    if(full_r3_keyspace[key_idx] == 9999):
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
                    
                    dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                    dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                    
                    # 3rd last layer
                    dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                    dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))
                    
                    dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                    dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                    # 4th last layer
                    dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                    dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))
                    
                    dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                    dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]


                    dec_cip = inv_sub_cells(dec_cip)
                    dec_fcip = inv_sub_cells(dec_fcip)
                    in_diff = dec_cip[nibble_idx] ^ dec_fcip[nibble_idx]

                    # checking whether the input diff is same as the diff in trail or not
                    if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                        # if (last_key == [8, 0, 8, 0, 9, 1, 9, 1, 10, 2, 10, 2, 11, 3, 11, 3, 12, 4, 12, 4, 13, 5, 13, 5, 14, 6, 14, 6, 15, 7, 15, 7]):
                        #     print('original key is here.')


                        # taking the count of reduced key space size
                        count = count+1
                    else:
                        # removing the key tuple if it does not satisfy the diff
                        full_r3_keyspace[key_idx] = 9999

                # print('count: ', count)

    print('\n\nultimate keys:')
    for key_idx, key in enumerate(full_r3_keyspace):
        if(full_r3_keyspace[key_idx] != 9999):
            print(key, ', ')

    print('\n\n')
    return full_r3_keyspace




# 3rd round attack on default cipher for checking the sfa
def full_attack_r3(trail_list, r3_keyspace, cip_fcip_list, sfa_bit_list):    
    si = si_base    
    s = si.inverse()    

    full_r3_keyspace = list(product(*[r3_keyspace[i] for i in range(2)]))

    nibble_idx_list = [i for i in range(32)]
    fault_bit_list = [(i%4) for i in range(32)]

    for nibble_idx in nibble_idx_list:
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
                for key_idx, key in enumerate(full_r3_keyspace):
                    if(full_r3_keyspace[key_idx] == 9999):
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
                    
                    dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                    dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                    
                    # 3rd last layer
                    dec_cip = inv_permute_bits(inv_sub_cells(dec_cip))
                    dec_fcip = inv_permute_bits(inv_sub_cells(dec_fcip))
                    
                    dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                    dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                    in_diff = si(dec_cip[nibble_idx])^si(dec_fcip[nibble_idx]);

                    # checking whether the input diff is same as the diff in trail or not
                    if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                        if (((si(dec_cip[nibble_idx]) >> fault_bit_list[nibble_idx])&1) == ((sfa_bit_list[nibble_idx]>>fault_bit_list[nibble_idx])&1)):
                            if (last_key == [8, 0, 8, 0, 9, 1, 9, 1, 10, 2, 10, 2, 11, 3, 11, 3, 12, 4, 12, 4, 13, 5, 13, 5, 14, 6, 14, 6, 15, 7, 15, 7]):
                                print('original key is here.')

                            # if (last_key == [0, 0, 0, 0, 0, 1, 0, 1, 0, 2, 0, 2, 0, 3, 0, 3, 0, 4, 0, 4, 0, 5, 0, 5, 0, 6, 0, 6, 0, 7, 0, 7]):
                            #     print('original key is here.')

                            # if (nibble_idx == 15):
                            #     r3_keyspace[group_idx_last].append(key)

                            # if (nibble_idx == 31):
                            #     r3_keyspace[group_idx_last].append(key)

                            # taking the count of reduced key space size
                            count = count+1

                        else:
                            # removing the key tuple if it does not satisfy the diff
                            full_r3_keyspace[key_idx] = 9999

                print('count: ', count)

    print('\n\nkey space of r3:')
    for key in full_r3_keyspace:
        if (key == 9999):
            continue
        print(key, end = ', ')

    return full_r3_keyspace


def keyset_to_equation(keyset):
    # we have k = (k0, k1, k2, k3)^T
    # and represent the keysete using
    # a * k = b

    anf = keyset_to_anf(keyset)
    a = matrix(GF(2), [0] * 4)
    b = vector(GF(2), [0])

    for term in anf.terms():
        if term.is_one():
            b[0] += 1
        else:
            a[0, term.index()] += 1

    b[0] += 1 # we start with a*k + b == 1 but require a * k == b
    return a, b


def main():
    global c, pt, key

    # key = [0x0, 0x1, 0x8, 0x9, 0xa, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0xf, 0x0, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x2, 0x3, 0x4, 0xb, 0xc, 0xd, 0xe];  
        
    # pt = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0xa, 0xb, 0xc, 0xd, 0xf, 0xe, 0xa, 0xb, 0xc, 0xd, 0xe, 0x9, 0x0, 0x8, 0x5, 0x6, 0x4, 0x2, 0x6, 0x1, 0x7, 0x8]; 

    key = [secrets.randbelow(16) for _ in range(32)]
    # key = [i%16 for i in range(32)]
    pt = [random.randint(0,15) for _ in range(32)]
    # pt = [(i+5)%16 for i in range(32)]
    c = DefaultCipher(key)

    # storing the actual cipher text in a
    set_fault(-1, -1, 0, 0)
    cip = c.encrypt(pt)

    # 24 round is for 4 rounds 
    round_nr = 24 

    trail_list = []
    cip_fcip_list = []

    # giving fault to generate the fault diff in the last round
    fault_list = [1, 2, 4, 8]
    # fault_list = [1, 2, 4, 8, 1, 2, 4, 8]

    # sfa_bit_list stores the nibble values in the inner state
    sfa_bit_list = []

    # this denotes the number of faults uptil that the exp will run
    number_of_faults = 16

    # depending upon the fault list storing the full trail list in trail_list
    for exp in range(number_of_faults):
        # taking the random intex as fault idx
        idx = random.randint(0, 31)
        fault = fault_list[random.randint(0, 3)]

        # # for the special case
        # idx = exp
        # fault = fault_list[exp%4]

        set_fault(2, round_nr, idx, fault)
        fcip = c.encrypt(pt)

        # sfa_state() prints the inter state value at the time of fault
        sfa_bit_list.append(sfa_state())

        set_fault(-1, -1, 0, 0)

        cip_fcip_list.append([cip, fcip])
        trail_list = finding_dt(cip, fcip, fault, idx, trail_list)


    for idx, i in enumerate(trail_list): 
        print('\n')
        print("trail list ", idx, ': ', i)

    # keyspace = [set(range(16)) for _ in range(32)]    
    r1_keyspace = [[i for i in range(16)] for _ in range(32)]    
    r1_keyspace = attack_r1(trail_list, r1_keyspace, cip)

    print('\n')
    for idx, i in enumerate(r1_keyspace):
        print('for nibble ', str(idx), ': ', i)

    print("\n\nr2 keyspace: ")
    r2_keyspace = attack_r2(trail_list, r1_keyspace, cip_fcip_list)
    print('\n\n')

    r3_keyspace = [[], []]
    print('\n\nr3 keyspace: ')
    r3_keyspace = attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list)
    print('\n\n')

    print('\n\nr4 keyspace: ')
    full_r3_keyspace = attack_r4(trail_list, r3_keyspace, r2_keyspace, r1_keyspace, cip_fcip_list)  

    # full_r3_keyspace = full_attack_r3(trail_list, r3_keyspace, cip_fcip_list, sfa_bit_list)


    # # constructing the left half key from the original key
    # left_half_key = [0 for i in range(32)]
    # for i in range(32):
    #     if ((i%2) == 0):
    #         left_half_key[i] = inv_permute_bits(key)[i]

    # # checking whether the left half key is in r3_keyspace[0] or not
    # for key4 in r3_keyspace[0]:
    #     get_key = [0 for i in range(32)]
    #     for group_idx_mid in range(4):
    #         for key_0 in range(4):
    #             get_key[0 + 2*group_idx_mid + 8*key_0] = key4[group_idx_mid][key_0]

    #     if (get_key == left_half_key): 
    #         print('original key is there in for the left half.')


    # # constructing the right half key from the original key
    # right_half_key = [0 for i in range(32)]
    # for i in range(32):
    #     if ((i%2) == 1):
    #         right_half_key[i] = inv_permute_bits(key)[i]

    # # checking whether the right half key is in r3_keyspace[0] or not
    # for key4 in r3_keyspace[1]:
    #     get_key = [0 for i in range(32)]
    #     for group_idx_mid in range(4):
    #         for key_0 in range(4):
    #             get_key[1 + 2*group_idx_mid + 8*key_0] = key4[group_idx_mid][key_0]

    #     if (get_key == right_half_key): 
    #         print('original key is there in for the right half.')



    # if key4 in r3_keyspace[0]:
    #     print('original key is there in for the left half.')
    #     print('len: ', len(r3_keyspace[0]))

    # if ((0, 2, 4, 6), (0, 2, 4, 6), (1, 3, 5, 7), (1, 3, 5, 7)) in r3_keyspace[1]:
    #     print('original key is there in for the right half.')
    #     print('len: ', len(r3_keyspace[1]))


    # dummy_attack_r2(trail_list, cip_fcip_list)

    # print("\n\ntrail list: ")
    # for i in trail_list[0]:
    #     print(i)



    # print("r2 key space:\n")
    # for i in r2_keyspace[0]:
    #     print(i)

    # print("trail list: ", trail_list)
    # print("mid trail list: ", trail_list[0][1])



    # for cip_fcip in cip_fcip_list:
    #     r2_keyspace = attack_r2(trail_list, r1_keyspace, cip_fcip)

    # print("cip fcip list: ", cip_fcip_list)


    # ctr_a = 0
    # ctr_b = 0
    # print("r2 key space: ")
    # for i in r2_keyspace[0]:
    #     print(i)
    #     ctr_a = ctr_a+1
    #     if i!= 9999:
    #         ctr_b = ctr_b+1
    #         # print(i)
    # print("\n\nctr a: ", ctr_a, " ctr b: ", ctr_b)

    # print('\n\n')
    # for idx, i in enumerate(r1_keyspace):
    #     if ((idx%8) != 0):
    #         continue
    #     print(i)
    # print('\n\n')

    # print('\ntrail list:')
    # for i in trail_list:
    #     print(i)

    print('\n\noriginal key:')
    print(inv_permute_bits(key))
    
    key1 = [0 for _ in range(32)]
    key1 = inv_permute_bits(key)
    print("(", key1[0],key1[8],key1[16],key1[24], ")", "(", key1[2],key1[10],key1[18],key1[26], ")", "(", key1[4],key1[12],key1[20],key1[28],")", "(", key1[6],key1[14],key1[22],key1[30],")", "(", key1[1],key1[9],key1[17],key1[25], ")", "(", key1[3],key1[11],key1[19],key1[27],")", "(", key1[5],key1[13],key1[21],key1[29],")", "(", key1[7],key1[15],key1[23],key1[31],")",)

    # for i in range(4):
    #     print('(', inv_permute_bits(key)[i+0], ',', inv_permute_bits(key)[i+8], ',', inv_permute_bits(key)[i+16], ',', inv_permute_bits(key)[i+24], ')', end = ', ')


    # for i in range(32):
    #     if ((i%2) == 1):
    #         print('0', end = ', ')
    #         continue
    #     print(inv_permute_bits(key)[i], end = ', ')

    # print('\n\n')
    # for group_idx in [0, 2, 4, 6]:
    #     print('\nfor group ', group_idx, ': ', end = '')
    #     for nibble in range(4):
    #         print(inv_permute_bits(key)[group_idx + 8*nibble], " ", end = '')
    # print('\n')

    # fwd_a, fwd_b = knowledge("fwd")
    # assert fwd_a * state_to_vec(key) == fwd_b
    
    # bwd_a, bwd_b = knowledge("bwd")
    # assert bwd_a * state_to_vec(key) == bwd_b

    # a = block_matrix(2, 1, [fwd_a, bwd_a])
    # b = vector(GF(2), list(fwd_b) + list(bwd_b))

    # if a * state_to_vec(key) != b:
    #     print("keyspace reduction failed")
    #     return 1

    # print(f"reduced keyspace to {128 - a.rank()} bits")
    # print()

    # # Embedding provides your application with the ability to implement some of the functionality of your application in Python rather than C or C++. This can be used for many purposes.
    # embed()


def knowledge(direction: str):
    if direction == "fwd":
        s = s_base
        fault_deltas = [2, 8]
    elif direction == "bwd":
        s = si_base
        fault_deltas = [2]
    else:
        raise RuntimeError("unknown direction")

    key_subspaces = [[] for _ in range(32)]

    for idx in range(32):
        for delta_in in fault_deltas:

            if direction == "fwd":
                a, b, delta = get_delta_enc(27, idx, delta_in)
            elif direction == "bwd":
                a, b, delta = get_delta_dec(1, idx, delta_in)

            tmp = get_keyset(a[idx], b[idx], delta_in, s)
            key_subspaces[idx].append(tmp)


    a = matrix(GF(2), 64, 128)
    b = vector(GF(2), 64)

    matrix_row = 0
    for nibble_idx in range(32):
        for subspace in key_subspaces[nibble_idx]:
            a_, b_ = keyset_to_equation([(x,) for x in subspace])

            a[matrix_row, nibble_idx*4:(nibble_idx+1)*4] += a_
            b[matrix_row] += b_[0]


            matrix_row += 1

    # print(perm)
    # print("\n\n")
    # print(permutation_to_matrix(perm))
    if direction == "fwd":
        a = a * permutation_to_matrix(perm)

    return a, b


if __name__ == '__main__':
    sys.exit(main() or 0)
    

# 2 distinct difference at last layer 0, 1, 2, 3, 8, 16, 24
# 2 distinct differences at 2nd layer in 0, 1, 2, 3


# for nibble (0, 2, 4, 6): ((8, 10, 12, 14), (8, 10, 12, 14), (9, 11, 13, 15), (9, 11, 13, 15))

