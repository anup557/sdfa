# gist: the file contains the attack portion of the second last round
# ----------------------------------------------------------------------------------------

from finding_trail import *

from itertools import product
import random, secrets

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

    return r2_keyspace

