# gist: fifth round attack on the simple key schedule of default cipher
# ------------------------------------------------------------------------------------------------------------

# from default import *
from finding_trail import *

from itertools import product
import random, secrets
import sys


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

        fifth_layer_input = trail[4][0]
        fifth_layer_output = trail[4][1]

        for i in range(32):
            if fifth_layer_input[i] != 0:
                dummy_list = [fifth_layer_input[i], fifth_layer_output[i]]
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
                if (trail_list[cip_fcip_idx][3][0][nibble_idx] != 0):
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
                                if(in_diff == trail_list[cip_fcip_idx][3][0][nibble_idx]):
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
                                if(in_diff == trail_list[cip_fcip_idx][3][0][nibble_idx]):
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
                                if(in_diff == trail_list[cip_fcip_idx][3][0][nibble_idx]):
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
                                if(in_diff == trail_list[cip_fcip_idx][3][0][nibble_idx]):
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
                                if(in_diff == trail_list[cip_fcip_idx][3][0][nibble_idx]):
                                    count = count+1
                                    # when the conditon satisfies for the first class representator then it will not check for the other one
                                    break
                                else:
                                    # if the key4 is there but it doesnot satisfies the in diff condition and it becomes the last class repesentator then remove 
                                    if ((key4 in r2_keyspace[group_idx]) and (i == dummy_list[len(dummy_list) - 1])):
                                        r2_keyspace[group_idx].remove(key4)

    return r2_keyspace


def attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list):    
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

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

    # in the third last group there are only 2 groups, 0 and 1 
    for group_idx_last in [0,1]:
        # producting the key space of 3rd last round
        dummy_r3 = list(product(*[r2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))

        for nibble_idx in nibble_idx_list[group_idx_last]:
            # for each cip and faulty cip text pair
            print('\nfor nibble idx:', nibble_idx)
            for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):

               # if the diff appears in the nibble idx, then do the following 
                if (trail_list[cip_fcip_idx][2][0][nibble_idx] != 0): 
                    # extract cip and faulty cip
                    cip = cip_fcip[0]
                    fcip = cip_fcip[1]

                    # initializing the count for each key of r3_keyspace
                    count = 0 
                    rej_count = 0 

                    # for each key in the key list
                    for key_idx, key in enumerate(dummy_r3):
                        if(key == 9999):
                            continue

                        # forming the last round key from the group idx
                        last_key = [0 for i in range(32)]
                        for group_idx_mid in range(4):
                            for key_0 in range(4):
                                last_key[group_idx_last + 2*group_idx_mid + 8*key_0] = key[group_idx_mid][key_0]

                        # for qr group 0, 2, 5, 7
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

                            dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                            dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                            # 3rd last layer
                            dec_cip = inv_sbox(dec_cip)
                            dec_fcip = inv_sbox(dec_fcip)

                            dec_cip = inv_perm(dec_cip)
                            dec_fcip = inv_perm(dec_fcip)

                            if(group_idx_last == 0):
                                if ((nibble_idx%2) == 0):
                                    in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

                                    # for printing purpose
                                    if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
                                        count = count + 1

                                    if(in_diff != trail_list[cip_fcip_idx][2][0][nibble_idx]):
                                        dummy_r3[key_idx] = 9999

                                else:
                                    for dummy_ele in r1_dummy_list[nibble_idx]:
                                        in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]

                                        # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                        if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
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
                                    in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]


                                    # for printing purpose
                                    if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
                                        count = count + 1

                                    if(in_diff != trail_list[cip_fcip_idx][2][0][nibble_idx]):
                                        dummy_r3[key_idx] = 9999

                                # for nibbles 20, 22, 28, 30
                                else:
                                    for dummy_ele in r1_dummy_list[nibble_idx]:
                                        in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]

                                        # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                        if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
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

                            for eq_key in eq_key_list:
                                # last layer
                                dec_cip = inv_perm(cip)
                                dec_fcip = inv_perm(fcip)

                                dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                                dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                                dec_cip = inv_sbox(dec_cip)
                                dec_fcip = inv_sbox(dec_fcip)

                                # 2nd last layer
                                dec_cip = inv_perm(dec_cip)
                                dec_fcip = inv_perm(dec_fcip)

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
                                dec_cip = inv_sbox(dec_cip)
                                dec_fcip = inv_sbox(dec_fcip)

                                dec_cip = inv_perm(dec_cip)
                                dec_fcip = inv_perm(dec_fcip)


                                flag1 = 1
                                # for the left half nibbles 4, 5, 6, 7, 12, 13, 14, 15, 16,17,18,19,24,25,26,27 
                                if (group_idx_last == 0):
                                    # for nibbles 4, 6, 12, 14
                                    # flag1 = 0
                                    if ((nibble_idx%2) == 0):
                                        in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

                                        # for printing purpose
                                        if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
                                            count = count + 1
                                            flag1 = 0
                                            break

                                    # for nibbles 5, 7, 13, 15
                                    else:
                                        # flag1 is used to break the for loop in r1 dummy list
                                        flag1 = 1

                                        for dummy_ele in r1_dummy_list[nibble_idx]:
                                            in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]

                                            # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                            if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
                                                count = count + 1
                                                flag1 = 0
                                                break

                                        if(flag1 == 0):
                                            break

                                else:
                                    # for nibbles 17, 19, 25, 27
                                    if ((nibble_idx%2) == 1):
                                        in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

                                        # for printing purpose
                                        if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
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
                                            in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]

                                            # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                            if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
                                                count = count + 1
                                                flag1 = 0
                                                break

                                        if(flag1 == 0):
                                            break


                                if (eq_key == eq_key_list[len(eq_key_list) - 1]):
                                    dummy_r3[key_idx] = 9999


            # printing the len of reduced keyspace
            ctr = 0
            for i in dummy_r3:
                if (i != 9999):
                    ctr = ctr+1
                if (((original_key[0], original_key[8], original_key[16], original_key[24]), (original_key[2], original_key[10], original_key[18], original_key[26]), (original_key[4], original_key[12], original_key[20], original_key[28]), (original_key[6], original_key[14], original_key[22], original_key[30])) == i):
                    print('original key is there for r3_keyspace[0].\n')

                if (((original_key[1], original_key[9], original_key[17], original_key[25]), (original_key[3], original_key[11], original_key[19], original_key[27]), (original_key[5], original_key[13], original_key[21], original_key[29]), (original_key[7], original_key[15], original_key[23], original_key[31])) == i):
                    print('original key is there for r3_keyspace[1].\n')

            print('len of reduced keyspace: ', ctr)


        for key in dummy_r3:
            if(key != 9999):
                r3_keyspace[group_idx_last].append(key)

    return r3_keyspace


# 4th round attack on default cipher
def attack_r4(trail_list, r1_keyspace, r2_keyspace, r3_keyspace, cip_fcip_list):    
    # sbox and inv sbox of default layer
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # making the nibble list from the corresponding group idx
    nibble_idx_list = [i for i in range(32)]

    r4_keyspace = []

    # producting the key space of 3rd last round
    dummy_r4 = list(product(r3_keyspace[0], r3_keyspace[1]))

    for nibble_idx in nibble_idx_list:
        # for each cip and faulty cip text pair
        for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):

           # if the diff appears in the nibble idx, then do the following 
            if (trail_list[cip_fcip_idx][1][0][nibble_idx] != 0):
                # extract cip and faulty cip
                cip = cip_fcip[0]
                fcip = cip_fcip[1]

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
                    dec_cip = inv_perm(cip)
                    dec_fcip = inv_perm(fcip)

                    dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]

                    # 2nd last layer
                    dec_cip = inv_perm(inv_sbox(dec_cip))
                    dec_fcip = inv_perm(inv_sbox(dec_fcip))

                    dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]

                    # 3rd last layer
                    dec_cip = inv_perm(inv_sbox(dec_cip))
                    dec_fcip = inv_perm(inv_sbox(dec_fcip))

                    dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]

                    # 4th last layer
                    dec_cip = inv_perm(inv_sbox(dec_cip))
                    dec_fcip = inv_perm(inv_sbox(dec_fcip))

                    # taking inv sbox table
                    in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

                    # checking whether the input diff is same as the diff in trail or not
                    if(in_diff != trail_list[cip_fcip_idx][1][0][nibble_idx]):
                        # removing the key tuple if it does not satisfy the diff
                        dummy_r4[key_idx] = 9999

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


# 5th round attack on default cipher
def attack_r5(trail_list, r1_keyspace, r2_keyspace, r3_keyspace, r4_keyspace, cip_fcip_list):    
    # sbox and inv sbox of default layer
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # making the nibble list from the corresponding group idx
    nibble_idx_list = [i for i in range(32)]

    r5_keyspace = []

    for nibble_idx in nibble_idx_list:
        # for each cip and faulty cip text pair
        for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):

           # if the diff appears in the nibble idx, then do the following 
            if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
                # extract cip and faulty cip
                cip = cip_fcip[0]
                fcip = cip_fcip[1]

                for key_idx, last_key in enumerate(r4_keyspace):
                    if(last_key == 9999):
                        continue

                    # last layer
                    dec_cip = inv_perm(cip)
                    dec_fcip = inv_perm(fcip)

                    dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]

                    # 2nd last layer
                    dec_cip = inv_perm(inv_sbox(dec_cip))
                    dec_fcip = inv_perm(inv_sbox(dec_fcip))

                    dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]

                    # 3rd last layer
                    dec_cip = inv_perm(inv_sbox(dec_cip))
                    dec_fcip = inv_perm(inv_sbox(dec_fcip))

                    dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]

                    # 4th last layer
                    dec_cip = inv_perm(inv_sbox(dec_cip))
                    dec_fcip = inv_perm(inv_sbox(dec_fcip))

                    dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]

                    # 5th last layer
                    dec_cip = inv_perm(inv_sbox(dec_cip))
                    dec_fcip = inv_perm(inv_sbox(dec_fcip))

                    in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

                    # checking whether the input diff is same as the diff in trail or not
                    if(in_diff != trail_list[cip_fcip_idx][0][0][nibble_idx]):
                        r4_keyspace[key_idx] = 9999

    for last_key in r4_keyspace:
        if (last_key == 9999):
            continue

        r5_keyspace.append(last_key)

    return r5_keyspace


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

    # --------------------------------------------------------------------------------------
    # oracle related things
    # --------------------------------------------------------------------------------------
    # initializing state list to store all the state vals
    state_list = [[] for i in range(no_of_rounds)]
    state_list = oracle(msg, key_layer, key_core, state_list)

    # taking the last outpur as cip
    cip = state_list[no_of_rounds-1].copy()

    # --------------------------------------------------------------------------------------
    # fault oracle related things
    # --------------------------------------------------------------------------------------
    # defining fault round and fault val
    fault_round = 5 
    fault_round_idx = no_of_rounds - fault_round

    # initializing trail list and cip fcip list
    trail_list = []
    cip_fcip_list = []

    # the number of faults in an exp
    no_of_faults = 5

    # giving fault at each nibble
    #fix_fault_nibble = [i for i in range(32)]
    #fix_fault_nibble = [0, 4, 8, 12, 16, 20, 24, 28] #unique key recovery:: verified!!
    #fix_fault_nibble = [0, 4, 8, 16, 20, 24] #unique key recovery:: verified!!
    fix_fault_nibble = [0, 8, 11, 16, 24] #unique key recovery:: verified!!
    #fix_fault_nibble = [0, 1, 16, 17]

    for times in range(no_of_faults):
        # choosing fix nibble 
        fault_nibble = fix_fault_nibble[times] 

        # choosing fixed single bit value, here we are taking 4, as for 4 the hw of the output diff is max.
        # The same thing will happen for 2 also
        fault_val = 4  

        fault_state_list = [[] for i in range(no_of_rounds)]
        fault_state_list = fault_oracle(msg, key_layer, key_core, fault_state_list, fault_round_idx, fault_nibble, fault_val)
        fcip = fault_state_list[no_of_rounds-1].copy()

        cip_fcip_list.append([cip, fcip])

        # taking cip output diff
        cip_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
        trail_list = finding_trail_5_round(cip_diff, fault_val, fault_nibble, trail_list)

    global original_key
    original_key = inv_perm(key_core)

    print('\noriginal key: ', original_key)

    # ------------------------------------------------------------------------------------
    # r1 attack
    # ------------------------------------------------------------------------------------
    r1_keyspace = [[i for i in range(16)] for _ in range(32)]    
    r1_keyspace = attack_r1(trail_list, r1_keyspace, cip)

    for i in range(32):
        print('key choices for nibble ' + str(i) + ': ', r1_keyspace[i])

    # ------------------------------------------------------------------------------------
    # r2 attack
    # ------------------------------------------------------------------------------------
    r2_keyspace = attack_r2(trail_list, r1_keyspace, cip_fcip_list)

    for qr in range(8):
        # print('\n\nkey space for ' + str(qr) + 'grp: ', r2_keyspace[qr])
        if ((original_key[qr+0], original_key[qr+8], original_key[qr+16], original_key[qr+24]) in r2_keyspace[qr]):
            print('key is there for the qr group ' + str(qr))

    # ------------------------------------------------------------------------------------
    # r3 attack
    # ------------------------------------------------------------------------------------
    r3_keyspace = attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list)
    print('r3 keyspace done.')
    #print('r3 keyspace:', r3_keyspace)

    # ------------------------------------------------------------------------------------
    # r4 attack
    # ------------------------------------------------------------------------------------
    r4_keyspace = attack_r4(trail_list, r1_keyspace, r2_keyspace, r3_keyspace, cip_fcip_list)
    print('r4 keyspace done.')
    print('len of r4 keyspace:', r4_keyspace)
    print('r4 keyspace:', len(r4_keyspace))

    # ------------------------------------------------------------------------------------
    # r5 attack
    # ------------------------------------------------------------------------------------
    r5_keyspace = attack_r5(trail_list, r1_keyspace, r2_keyspace, r3_keyspace, r4_keyspace, cip_fcip_list)
    print('r5 keyspace done.')
    print('len of r5 keyspace:', r5_keyspace)
    print('r5 keyspace:', len(r5_keyspace))



if __name__ == '__main__':
    # for exp in range(100):
    for exp in range(1):
        out = main()
        if (out == 1):
            print('exp ', exp, ' success.')
        else:
            print('exp ', exp, ' fails.')
            break

