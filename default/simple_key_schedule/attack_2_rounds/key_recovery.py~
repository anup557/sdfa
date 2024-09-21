# gist: code for the 2 rounds of the default cipher for simple key schedule.
# This is key recovery attack according to our work. In this prog we have used trail to find out the reduced keyspace.

# results:
#     (i) fault val 4 in 32 distinct nibbles      -> reduced keyspace in the average case for each of the qr group is 53
#     (i) fault val [2, 4] in 32 distinct nibbles -> reduced keyspace in the average case for each of the qr group is 20

# original key remains in each of the groups after the reduction also.
# ------------------------------------------------------------------------------------------------------------

# from default import *
from finding_trail import *

from itertools import product
import random, secrets

def find_last_layer_diff_list(trail_list): 
    diff_list = [[] for _ in range(32)]

    for trail in trail_list:
        # extracting last layer input output
        frst_layer_input = trail[0][0]
        frst_layer_output = trail[0][1]

        # extracting mid layer input output
        mid_layer_input = trail[1][0]
        mid_layer_output = trail[1][1]

        # extracting diff for a nibble
        for i in range(32):
            if mid_layer_input[i] != 0:
                dummy_list = [mid_layer_input[i], mid_layer_output[i]]
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


# if the ele is in the list then return 1
def list_search(list1, list_ele):
    for i in list1:
        if (i == list_ele):
            return 1
    return 0


# key recovery attack on round 2
def attack_r2(trail_list, r1_keyspace, cip_fcip_list):    
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

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
                if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
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
     
                        dec_cip = inv_perm(cip)
                        dec_fcip = inv_perm(fcip)
                        dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                        dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                        dec_cip = inv_perm(inv_sbox(dec_cip))
                        dec_fcip = inv_perm(inv_sbox(dec_fcip))
                        # print('input diff: ', )

                        if (nibble_idx == 0):
                            dummy_list = []
                            for i in range(4):
                                if (list_search(r1_keyspace[nibble_idx], i) == 1):
                                    dummy_list.append(i)

                            for i in dummy_list:
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]

                                # checking whether the input diff is same as the diff in trail or not
                                if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
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
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]

                                # checking whether the input diff is same as the diff in trail or not
                                if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
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
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]

                                # checking whether the input diff is same as the diff in trail or not
                                if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
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
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]

                                # checking whether the input diff is same as the diff in trail or not
                                if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
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
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]

                                # checking whether the input diff is same as the diff in trail or not
                                if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                    count = count+1
                                    # when the conditon satisfies for the first class representator then it will not check for the other one
                                    break
                                else:
                                    # if the key4 is there but it doesnot satisfies the in diff condition and it becomes the last class repesentator then remove 
                                    if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
                                        r2_keyspace[group_idx].remove(key4)

    return r2_keyspace


def main():
    # msg = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 
    msg = [secrets.randbelow(16) for _ in range(32)]

    # defining original key list for default layer
    key_layer = [[12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10], 
                 [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10], 
                 [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10], 
                 [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10]]

    # defining key list for default core
    key_core = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 

    # --------------------------------------------------------------------------------------
    # oracle related things
    # --------------------------------------------------------------------------------------
    # initializing state list to store all the state vals
    state_list = [[] for i in range(80)]
    state_list = oracle(msg, key_layer, key_core, state_list)

    # taking the last outpur as cip
    cip = state_list[79].copy()

    # --------------------------------------------------------------------------------------
    # fault oracle related things
    # --------------------------------------------------------------------------------------
    # defining fault round and fault val
    fault_round = 2 
    fault_round_idx = 80 - fault_round

    # initializing trail list and cip fcip list
    trail_list = []
    cip_fcip_list = []

    # the number of faults in an exp
    no_of_faults = 32

    # giving fault at each nibble
    fix_fault_nibble = [i for i in range(32)]
    #fix_fault_nibble = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31] # 64, reduced keyspace = 2^{32} verified!!
    
    #fix_fault_nibble = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29] # 48, reduced keyspace = 2^{39} verified!!
    
    fix_fault_nibble = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 4, 8, 12, 16, 20, 24, 28] # 32, reduced keyspace = 2^{46} verified!!

    # choosing fixed single bit value, here we are taking 4, as for 4 the hw of the output diff is max.
    # The same thing will happen for 2 also
    #fault_val_list = [4]
    #fault_val = 4
    #diff = [1,2,4,8]

    for times in range(no_of_faults):
        #for fault_val in fault_val_list:
        # choosing fix nibble 
        fault_nibble = fix_fault_nibble[times] 

        #val = secrets.randbelow(4)
        #fault_val = diff[val]	
        
        if times < 32:
            fault_val = 2
        else:
            fault_val = 1
		
        fault_state_list = [[] for i in range(80)]
        fault_state_list = fault_oracle(msg, key_layer, key_core, fault_state_list, fault_round_idx, fault_nibble, fault_val)
        fcip = fault_state_list[79].copy()

        cip_fcip_list.append([cip, fcip])

        # taking cip output diff
        cip_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
        trail_list = finding_trail_2_round(cip_diff, fault_val, fault_nibble, trail_list)


    global original_key
    original_key = inv_perm(key_core)
    print('original key:', original_key)

    # -------------------------------------------------------------------------------------
    # r1 attack
    # -------------------------------------------------------------------------------------
    r1_keyspace = [[i for i in range(16)] for _ in range(32)]    
    r1_keyspace = attack_r1(trail_list, r1_keyspace, cip)

    # printing purpose
    print('\n********************************************************************************')
    print('performing attack r1:')
    print('********************************************************************************')
    for i in range(32):
        print('for the ' + str(i) + 'th nibble: \t', r1_keyspace[i])

    # -------------------------------------------------------------------------------------
    # r2 attack
    # -------------------------------------------------------------------------------------
    r2_keyspace = attack_r2(trail_list, r1_keyspace, cip_fcip_list)

    # printing purpose
    print('\n\n********************************************************************************')
    print('performing attack r2:')
    print('********************************************************************************')
    for qr in range(8):
        print('\nlen of the key space for group ' + str(qr) + ': ', len(r2_keyspace[qr]))
        if ((original_key[qr+0], original_key[qr+8], original_key[qr+16], original_key[qr+24]) in r2_keyspace[qr]):
            print('key is there for the qr group ' + str(qr))

    print('\n\nlength of r2 keyspace (for all 8 groups):', len(r2_keyspace[0]), len(r2_keyspace[1]), len(r2_keyspace[2]), len(r2_keyspace[3]), len(r2_keyspace[4]), len(r2_keyspace[5]), len(r2_keyspace[6]), len(r2_keyspace[7]))
    print('\nr2 keyspace done.')


if __name__ == '__main__':
    # for exp in range(100):
    for exp in range(1):
        out = main()
        if (out == 1):
            print('exp ', exp, ' success.')
        else:
            print('exp ', exp, ' fails.')
            break

