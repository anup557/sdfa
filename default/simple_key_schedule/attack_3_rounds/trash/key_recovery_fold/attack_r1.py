# gist: the file contains the attack portion of the last round
# ------------------------------------------------------------------------------------------------

from finding_trail import *

def find_last_layer_diff_list(trail_list): 
    diff_list = [[] for _ in range(32)]

    for trail in trail_list:
        # extracting last layer input output
        frst_layer_input = trail[0][0]
        frst_layer_output = trail[0][1]

        # extracting mid layer input output
        mid_layer_input = trail[1][0]
        mid_layer_output = trail[1][1]

        # extracting third layer input output
        third_layer_input = trail[2][0]
        third_layer_output = trail[2][1]

        # extracting diff for a nibble
        for i in range(32):
            if third_layer_input[i] != 0:
                dummy_list = [third_layer_input[i], third_layer_output[i]]
                if dummy_list not in diff_list[i]:
                    diff_list[i].append(dummy_list)

    return diff_list


# depending upon the diff list in last layer only this function reduce the key space of the nibbles
def attack_r1(trail_list, r1_keyspace, cip):    
    # sbox table for default layer
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # print("trail list: ", trail_list)

    last_layer_diff_list = [] 
    last_layer_diff_list = find_last_layer_diff_list(trail_list) 

    cip = inv_perm(cip)

    for idx in range(32):    
       for in_out_diff in last_layer_diff_list[idx]:
           if len(in_out_diff) == 0:
               continue
           dummy_keysp = []
           for key_r1 in r1_keyspace[idx]:
               if  ((inv_sbox_table[cip[idx] ^ key_r1] ^ inv_sbox_table[cip[idx] ^ in_out_diff[1] ^ key_r1]) == in_out_diff[0]):    
                   dummy_keysp.append(key_r1)
           r1_keyspace[idx] = dummy_keysp

    return r1_keyspace    

