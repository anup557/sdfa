# not done yet. In nibble 6, its not there.

# This is key recovery attack according to our work. In this prog we have used trail to find out the reduced keyspace. checking for whether second layer group 0 sboxes have all 2 bit reduction individually but in the last layer 0,8,16,24 has the combined key space strictly > 2^8. This is doing dfa.

# final fix original code

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


# if the ele is in the list then return 1
def list_search(list1, list_ele):
    for i in list1:
        if (i == list_ele):
            return 1
    return 0


# new for rotating key schedule
## key recovery attack on round 2
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
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]

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
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]

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
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]

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
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]

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


# 3rd round attack on default cipher
def attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list):    
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # making the nibble list from the corresponding group idx
    #nibble_idx_list = [[i for i in range(16)], [i for i in range(16, 32)]]
    nibble_idx_list = [[0, 2, 8, 10, 1, 3, 9, 11, 4, 6, 12, 14], []]

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
                if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
                    # extract cip and faulty cip
                    cip = cip_fcip[0]
                    fcip = cip_fcip[1]

                    for key_idx, key in enumerate(dummy_r3):
                        if(key == 9999):
                            continue

                        # forming the last round key from the group idx
                        last_key = [0 for i in range(32)]
                        for group_idx_mid in range(4):
                            for key_0 in range(4):
                                last_key[group_idx_last + 2*group_idx_mid + 8*key_0] = key[group_idx_mid][key_0]

                        # not used anywhere bt will be
                        # # eq key is the product of the equivalence class keys
                        # eq_key_list = list(product(*[r1_dummy_list[i] for i in range(32)]))


                        # reduce the keyspace at first for these nibbles then do this for other nibbles
                        if(nibble_idx in [0, 1, 2, 3, 8, 9, 10, 11, 20, 21, 22, 23, 28, 29, 30, 31]):
                            # last layer
                            dec_cip = inv_perm(cip)
                            dec_fcip = inv_perm(fcip)

                            dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                            dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                            # 2nd last layer
                            dec_cip = inv_sbox(dec_cip)
                            dec_fcip = inv_sbox(dec_fcip)
                           
                            dec_cip = inv_perm(dec_cip)
                            dec_fcip = inv_perm(dec_fcip)

                            # for the qr group 0 and 2
                            if nibble_idx in [0, 1, 2, 3, 8, 9, 10, 11]:
                                dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                                dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                                # 3rd last layer
                                dec_cip = inv_sbox(dec_cip)
                                dec_fcip = inv_sbox(dec_fcip)
                               
                                dec_cip = inv_perm(dec_cip)
                                dec_fcip = inv_perm(dec_fcip)
                                   
                                # check whether this is necessary or not
                                if(group_idx_last == 0):
                                    if nibble_idx in [0, 2, 8, 10]:
                                        in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

                                        if(in_diff != trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                            dummy_r3[key_idx] = 9999

                                    if nibble_idx in [1, 3, 9, 11]:
                                        for dummy_ele in r1_dummy_list[nibble_idx]:
                                            in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]
                                       
                                            # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                            if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                                break

                                            # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
                                            if (dummy_ele == r1_dummy_list[nibble_idx][len(r1_dummy_list[nibble_idx]) - 1]):
                                                dummy_r3[key_idx] = 9999
                                           
                        # for the qr group 1 and 3
                        if nibble_idx in [4, 6, 12, 14]:
                            r2_dummy_list  = list(product(*[r1_dummy_list[(nibble_idx//4) + 8*j] for j in range(4)]))
                            pos_ele = 0 

                            for mid_key_ele in r2_dummy_list:
                                mid_key = [0 for i in range(32)]
                                for i in range(4):
                                    mid_key[(nibble_idx//4) + 8*i] = mid_key_ele[i]

                                dec_cip = [dec_cip^mid_key for dec_cip, mid_key in zip(dec_cip, mid_key)]
                                dec_fcip = [dec_fcip^mid_key for dec_fcip, mid_key in zip(dec_fcip, mid_key)]

                                # 3rd last layer
                                dec_cip = inv_sbox(dec_cip)
                                dec_fcip = inv_sbox(dec_fcip)
                               
                                dec_cip = inv_perm(dec_cip)
                                dec_fcip = inv_perm(dec_fcip)
                                   
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

                                if(in_diff != trail_list[cip_fcip_idx][0][0][nibble_idx]):
                                    break

                                # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
                                if (mid_key_ele == r2_dummy_list[len(r2_dummy_list) - 1]):
                                    dummy_r3[key_idx] = 9999


                        # # not checked, check after for 14 the cases is settled
                        # # ------------------------------------------------------
                        # if nibble_idx in [5, 7, 13, 15]:
                        #     r2_dummy_list  = list(product(*[r1_dummy_list[(nibble_idx//4) + 8*j] for j in range(4)]))
                        #     # flag is to check whether the key in dummy r3 is the original key or not
                        #     flag = 0 

                        #     for mid_key_ele in r2_dummy_list:
                        #         mid_key = [0 for i in range(32)]
                        #         for i in range(4):
                        #             mid_key[(nibble_idx//4) + 8*i] = mid_key_ele[i]

                        #         dec_cip = [dec_cip^mid_key for dec_cip, mid_key in zip(dec_cip, mid_key)]
                        #         dec_fcip = [dec_fcip^mid_key for dec_fcip, mid_key in zip(dec_fcip, mid_key)]

                        #         # 3rd last layer
                        #         dec_cip = inv_sbox(dec_cip)
                        #         dec_fcip = inv_sbox(dec_fcip)
                               
                        #         dec_cip = inv_perm(dec_cip)
                        #         dec_fcip = inv_perm(dec_fcip)
                                   
                        #         for dummy_ele in r1_dummy_list[nibble_idx]:
                        #             in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]
                               
                        #             # if any of the cls rep satisfies the in diff then the key4 is a possible key
                        #             if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                        #                 flag = 1
                        #                 break

                        #         # if the flag is 1, this means for some mid layer key and eq last layer key the input diff and the output diff
                        #         # satisfies
                        #         if (flag == 1):
                        #             break

                        #         # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
                        #         if (mid_key_ele == r2_dummy_list[len(r2_dummy_list) - 1]):
                        #             dummy_r3[key_idx] = 9999

            # printing the len of reduced keyspace
            ctr = 0
            for i in dummy_r3:
                if (i != 9999):
                    ctr = ctr+1
                if (((original_key[0], original_key[8], original_key[16], original_key[24]), (original_key[2], original_key[10], original_key[18], original_key[26]), (original_key[4], original_key[12], original_key[20], original_key[28]), (original_key[6], original_key[14], original_key[22], original_key[30])) == i):
                    print('original key is there for r3_keyspace[0].\n')
            print('len of reduced keyspace: ', ctr)








#                                     for dummy_ele in r1_dummy_list[nibble_idx]:
#                                         in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]
    
#                                         # if any of the cls rep satisfies the in diff then the key4 is a possible key
#                                         if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                             pos_ele = 1 
#                                             break

#                                     # if the element is a possible element then true :
#                                     if (pos_ele == 1): 
#                                         break

#                                     # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
#                                     if (mid_key_ele  == r2_dummy_list[len(r2_dummy_list) - 1]):
#                                         dummy_r3[key_idx] = 9999
    







#                                 dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
#                                 dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

#                                 # 3rd last layer
#                                 dec_cip = inv_sbox(dec_cip)
#                                 dec_fcip = inv_sbox(dec_fcip)
                               
#                                 dec_cip = inv_perm(dec_cip)
#                                 dec_fcip = inv_perm(dec_fcip)
                                   
#                                 # check whether this is necessary or not
#                                 if(group_idx_last == 0):
#                                     if nibble_idx in [4, 6]:
#                                         in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

#                                         if(in_diff != trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                             dummy_r3[key_idx] = 9999
#                                             # till this euro
#                                             -------------------------------------------------







                            #else:
                            #    # for nibbles 20, 22, 28, 30
                            #    if ((nibble_idx%2) == 1):
                            #        in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]


                            #        # for printing purpose
                            #        if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                            #            count = count + 1

                            #        if(in_diff != trail_list[cip_fcip_idx][0][0][nibble_idx]):
                            #            dummy_r3[key_idx] = 9999
                            #    # for nibbles 21, 23, 29, 31
                            #    else:
                            #        for dummy_ele in r1_dummy_list[nibble_idx]:
                            #            in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]
                                   
                            #            # if any of the cls rep satisfies the in diff then the key4 is a possible key
                            #            if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                            #                count = count + 1
                            #                break

                            #            # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
                            #            if (dummy_ele == r1_dummy_list[nibble_idx][len(r1_dummy_list[nibble_idx]) - 1]):
                            #                # rej_count = rej_count + 1
                            #                dummy_r3[key_idx] = 9999


                        ## for nibble 4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 26, 27
                        #if(nibble_idx in [4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 26, 27]):
                            ## last layer
                            #dec_cip = inv_perm(cip)
                            #dec_fcip = inv_perm(fcip)

                            #dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                            #dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                           
                            #dec_cip = inv_sbox(dec_cip)
                            #dec_fcip = inv_sbox(dec_fcip)
                           
                            #'''flag = 1    
                            #for i in range(16):
                            #    if(dec_cip[2*i+1]^dec_fcip[2*i+1] != trail_list[cip_fcip_idx][2][0][2*i+1]):
                            #        flag = 0
                            #        break
                                   
                            #if(flag == 0): 
                            #    dummy_r3[key_idx] = 9999
                            #    continue'''
                               
                            ## 2nd last layer
                            #dec_cip = inv_perm(dec_cip)
                            #dec_fcip = inv_perm(dec_fcip)
                           
                            ## making mid key from the 0th ele of r2 keyspace
                            #mid_key = [0 for i in range(32)]
                            #for qr in range(8):
                            #    for i in range(4):
                            #        mid_key[qr + 8*i] = r2_keyspace[qr][0][i]
                               

                            ## if (nibble_idx == 12):
                            ##     mid_key[27] = 4
                            ## if (nibble_idx == 13):
                            ##     mid_key[27] = 4
                            ## if (nibble_idx == 14):
                            ##     mid_key[27] = 4
                            ## if (nibble_idx == 15):
                            ##     mid_key[27] = 4

                            ##key_27_list = [1, 4, 0xb, 0xe]
                            ##for mid in key_27_list:
                            #    #mid_key[27] = 4

                            #dec_cip = [dec_cip^mid_key for dec_cip, mid_key in zip(dec_cip, mid_key)]
                            #dec_fcip = [dec_fcip^mid_key for dec_fcip, mid_key in zip(dec_fcip, mid_key)]

                           
                            ## 3rd last layer
                            #dec_cip = inv_sbox(dec_cip)
                            #dec_fcip = inv_sbox(dec_fcip)
                               
                            #'''flag = 1    
                            #for i in range(16):
                            #    if(dec_cip[2*i+1]^dec_fcip[2*i+1] != trail_list[cip_fcip_idx][1][0][2*i+1]):
                            #        flag = 0
                            #        break
                               
                            #if(flag == 0): 
                            #    dummy_r3[key_idx] = 9999
                            #    continue'''
                               
                            #dec_cip = inv_perm(dec_cip)
                            #dec_fcip = inv_perm(dec_fcip)


                            ## for the left half nibbles 4, 5, 6, 7, 12, 13, 14, 15, 16,17,18,19,24,25,26,27 
                            #if (group_idx_last == 0):
                            #    # for nibbles 4, 6, 12, 14
                            #    if ((nibble_idx%2) == 0):
                            #        in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

                            #        # for printing purpose
                            #        if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                            #            count = count + 1
                            #            #break

                            #        else:
                            #            dummy_r3[key_idx] = 9999

                            #    # for nibbles 5, 7, 13, 15
                            #    else:
                            #        for dummy_ele in r1_dummy_list[nibble_idx]:
                            #            in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]
                                   
                            #            # if any of the cls rep satisfies the in diff then the key4 is a possible key
                            #            if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                            #                count = count + 1
                            #                break

                            #            # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
                            #            if (dummy_ele == r1_dummy_list[nibble_idx][len(r1_dummy_list[nibble_idx]) - 1]):
                            #                # rej_count = rej_count + 1
                            #                dummy_r3[key_idx] = 9999

                            #else:
                            #    # for nibbles 17, 19, 25, 27
                            #    if ((nibble_idx%2) == 1):
                            #        in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

                            #        # for printing purpose
                            #        if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                            #            count = count + 1
                            #            #break

                            #    else:
                            #        # for nibbles 16,18,24,26
                            #        for dummy_ele in r1_dummy_list[nibble_idx]:
                            #            in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]
                                   
                            #            # if any of the cls rep satisfies the in diff then the key4 is a possible key
                            #            if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
                            #                count = count + 1
                            #                break

                            #            # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
                            #            if (dummy_ele == r1_dummy_list[nibble_idx][len(r1_dummy_list[nibble_idx]) - 1]):
                            #                # rej_count = rej_count + 1
                            #                dummy_r3[key_idx] = 9999
                                   
                                   
                                   
                    #print('count: ', count)
                    #print('rej count: ', rej_count)

            #'''dummy1 = []
            #for key in dummy_r3:
                #if(key == 9999):
                    #continue
                #if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
                    #print('left key is there in dummy r3.')
                #dummy1.append(key)
            #print('dummy1 len: ', len(dummy1))
            #print('distinct ele in dummy1 len: ', len(set(dummy1)))'''

            ##if (nibble_idx == 12):
                ##print('keyspace at nibble 12: ', dummy1)

        for key in dummy_r3:
            if(key != 9999):
                r3_keyspace[group_idx_last].append(key)


        print('len r3 keyspace ', group_idx_last, ': ', len(r3_keyspace[group_idx_last]))

        '''print('r3 keyspace ', group_idx_last, ': ')
        for i in r3_keyspace[group_idx_last]:
            print(i, end = ', ')'''

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
    fault_round = 3 
    fault_round_idx = 80 - fault_round

    # initializing trail list and cip fcip list
    trail_list = []
    cip_fcip_list = []

    # the number of faults in an exp
    no_of_faults = 32

    for times in range(no_of_faults):
        # choosing nibble randomly
        fault_nibble = secrets.randbelow(32) 

        # choosing random single bit fault from list
        fault_val_list = [1, 2, 4, 8]
        fault_val_idx = secrets.randbelow(4)
        fault_val = fault_val_list[fault_val_idx]  

        fault_state_list = [[] for i in range(80)]
        fault_state_list = fault_oracle(msg, key_layer, key_core, fault_state_list, fault_round_idx, fault_nibble, fault_val)
        fcip = fault_state_list[79].copy()

        cip_fcip_list.append([cip, fcip])

        # taking cip output diff
        cip_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
        trail_list = finding_trail_3_round(cip_diff, fault_val, fault_nibble, trail_list)


    global original_key
    original_key = inv_perm(key_core)

    # r1 attack
    r1_keyspace = [[i for i in range(16)] for _ in range(32)]    
    r1_keyspace = attack_r1(trail_list, r1_keyspace, cip)
    print('\nr1 keyspace done.')
    for i in range(32):
        print('for the ' + str(i) + 'th nibble: \t', r1_keyspace[i])

    # r2 attack
    r2_keyspace = attack_r2(trail_list, r1_keyspace, cip_fcip_list)
    print('\nr2 keyspace done.')
    # ok till this

    r3_keyspace = attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list)

    if (((original_key[0], original_key[8], original_key[16], original_key[24]), (original_key[2], original_key[10], original_key[18], original_key[26]), (original_key[4], original_key[12], original_key[20], original_key[28]), (original_key[6], original_key[14], original_key[22], original_key[30]))  in r3_keyspace[0]):
        print('original key is there for r3_keyspace[0].\n')

    print('len of r3 keyspace[0]: ', len(r3_keyspace[0]))
    # print(r3_keyspace[0])
    print('\n\ndone.')


#     # for i in range(8):
#     #     print('\nfor group ' + str(i) + ': ', r2_keyspace[i])



# #     # checking whether the original key is there in the r2 keyspace or not
#     # print('\n\n')
#     original_key = inv_perm(key_core)
#     for i in range(8):
#         print((original_key[i+0], original_key[i+8], original_key[i+16], original_key[i+24]))
#         if ((original_key[i+0], original_key[i+8], original_key[i+16], original_key[i+24]) in r2_keyspace[i]):
#             print('original key is there for the group idx ' + str(i) + '.')
#     # qr_key = [0 for i in range(8)]


#     # checksum is for checking whether the key is in the qr group or not
#     # print('\n\n')
#     r2_check_sum = 0
#     for qr in range(8):
#         qr_key[qr] = ((original_key[qr + 0], original_key[qr + 8], original_key[qr + 16], original_key[qr + 24]))
#         if (qr_key[qr] in r2_keyspace[qr]):
#             # print('key is there for ', qr)
#             r2_check_sum = r2_check_sum + 1  

#     # if (r2_check_sum == 8):
#     #     return 1
        
#     # print('msg: ', pt)
#     # print('key: ', key)
#     # print('\n\n')

#     # return 0


#     r3_keyspace = [[], []]
#     r3_keyspace = attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list)


#     left_half_key = ((qr_key[0], qr_key[2], qr_key[4], qr_key[6]))
#     right_half_key = ((qr_key[1], qr_key[3], qr_key[5], qr_key[7]))

#     print('left half key:', left_half_key)
#     # print('right half key:', right_half_key)

#     print('\n\n')
#     if (left_half_key in r3_keyspace[0]):
#         print('eeeeeeee, left half key is in there.')

#     if (right_half_key in r3_keyspace[1]):
#         print('eeeeeeee, right half key is in there.')








#     # printing original key
#     print('\n\noriginal key:')
    
#     print(inv_permute_bits(key))
#     print('\n\n', [[inv_permute_bits(key)[qr + 8*i] for i in range(4)] for qr in range(8)])


if __name__ == '__main__':
    # for exp in range(100):
    for exp in range(1):
        out = main()
        if (out == 1):
            print('exp ', exp, ' success.')
        else:
            print('exp ', exp, ' fails.')
            break

