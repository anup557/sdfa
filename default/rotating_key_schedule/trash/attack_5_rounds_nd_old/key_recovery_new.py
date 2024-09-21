# gist: fifth round attack on the simple key schedule of default cipher
# ------------------------------------------------------------------------------------------------------------

# from default import *
from finding_trail import *
from equivalent_keys_find import *

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
def attack_r2(trail_list, r1_keyspace, k3, cip_fcip_list):    
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

                        in_diff = inv_sbox_table[dec_cip[nibble_idx]^k3[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^k3[nibble_idx]]

                        # checking whether the input diff is same as the diff in trail or not
                        if(in_diff == trail_list[cip_fcip_idx][3][0][nibble_idx]):
                            count = count+1
                            break

                        else:
                            r2_keyspace[group_idx].remove(key4)

    return r2_keyspace



# 3rd round attack on default cipher
def attack_r3(trail_list, r2_keyspace, k0, k1, k2, k3, cip_fcip_list):
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # making the nibble list from the corresponding group idx
    nibble_idx_list = [[i for i in range(16)], [i for i in range(16, 32)]]

    r3_keyspace = [[], []]

    # in the third last group there are only 2 groups, 0 and 1 
    for group_idx_last in [0, 1]:
        # producting the key space of 3rd last round
        dummy_r3 = list(product(*[r2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))
        print('initial len:', len(dummy_r3))

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
                        dec_cip = inv_perm(cip)
                        dec_fcip = inv_perm(fcip)

                        dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                        dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

                        # 2nd last layer
                        dec_cip = inv_perm(inv_sbox(dec_cip))
                        dec_fcip = inv_perm(inv_sbox(dec_fcip))

                        dec_cip = [dec_cip^k3 for dec_cip, k3 in zip(dec_cip, k3)]
                        dec_fcip = [dec_fcip^k3 for dec_fcip, k3 in zip(dec_fcip, k3)]

                        # 3rd last layer
                        dec_cip = inv_perm(inv_sbox(dec_cip))
                        dec_fcip = inv_perm(inv_sbox(dec_fcip))

                        in_diff = inv_sbox_table[dec_cip[nibble_idx]^k2[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^k2[nibble_idx]]

                        # checking whether the input diff is same as the diff in trail or not
                        if(in_diff == trail_list[cip_fcip_idx][2][0][nibble_idx]):
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


# returns the cip and fcip list of 4th last round where k0 is xored and here we have to reduce the key space of k0
def rotating_key_schedule_finding_trail(cip, fcip, nks):
    diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
    # print('\n\n\nat last round:\t', diff)

    # last layer
    dec_cip = inv_perm(cip)
    dec_fcip = inv_perm(fcip)

    layer_key = nks[3].copy()
    dec_cip = [dec_cip^layer_key for dec_cip, layer_key in zip(dec_cip, layer_key)]
    dec_fcip = [dec_fcip^layer_key for dec_fcip, layer_key in zip(dec_fcip, layer_key)]

    # 2nd last layer
    dec_cip = inv_sbox(dec_cip)
    dec_fcip = inv_sbox(dec_fcip)

    diff = [dec_cip^dec_fcip for dec_cip, dec_fcip in zip(dec_cip, dec_fcip)]
    # print('2nd last round:\t', diff)

    dec_cip = inv_perm(dec_cip)
    dec_fcip = inv_perm(dec_fcip)

    layer_key = nks[2].copy()
    dec_cip = [dec_cip^layer_key for dec_cip, layer_key in zip(dec_cip, layer_key)]
    dec_fcip = [dec_fcip^layer_key for dec_fcip, layer_key in zip(dec_fcip, layer_key)]

    # 3rd last layer
    dec_cip = inv_sbox(dec_cip)
    dec_fcip = inv_sbox(dec_fcip)

    diff = [dec_cip^dec_fcip for dec_cip, dec_fcip in zip(dec_cip, dec_fcip)]
    # print('3rd last round:\t', diff)

    dec_cip = inv_perm(dec_cip)
    dec_fcip = inv_perm(dec_fcip)

    layer_key = nks[1].copy()
    dec_cip = [dec_cip^layer_key for dec_cip, layer_key in zip(dec_cip, layer_key)]
    dec_fcip = [dec_fcip^layer_key for dec_fcip, layer_key in zip(dec_fcip, layer_key)]


    dec_cip = inv_sbox(dec_cip)
    dec_fcip = inv_sbox(dec_fcip)

    # dec_cip1 = inv_perm(dec_cip)
    # dec_fcip1 = inv_perm(dec_fcip)

    # diff = [dec_cip1^dec_fcip1 for dec_cip1, dec_fcip1 in zip(dec_cip1, dec_fcip1)]
    # # print('4th last round:\t', diff)


    # layer_key = nks[0].copy()
    # dec_cip1 = [dec_cip1^layer_key for dec_cip1, layer_key in zip(dec_cip1, layer_key)]
    # dec_fcip1 = [dec_fcip1^layer_key for dec_fcip1, layer_key in zip(dec_fcip1, layer_key)]

    # dec_cip1 = inv_sbox(dec_cip1)
    # dec_fcip1 = inv_sbox(dec_fcip1)

    # diff = [dec_cip1^dec_fcip1 for dec_cip1, dec_fcip1 in zip(dec_cip1, dec_fcip1)]
    # # print('4th last round:\t', diff)

    return [dec_cip, dec_fcip]



def single_key(keyspace):
    key = []
    # print('keyspace: ', keyspace)
    for nibble in keyspace:
        if len(nibble) != 1:
            raise RuntimeError(f"expected a single key, got {len(nibble)}")
        key.append(nibble[0])

    #key = permute_bits(key)
    return key



def attack_enc(key_core, starting_keyset):
    # sbox and inv sbox of default layer
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # getting round keys from the core key
    key_layer = key_schedule(key_core)

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]

    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            # taking random msg
            msg = [secrets.randbelow(16) for _ in range(32)]

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
            fault_state_list = [[] for i in range(no_of_rounds)]

            # here for k3, we gave the fault before just one round
            fault_round_idx = no_of_rounds - 1
            fault_state_list = fault_oracle(msg, key_layer, key_core, fault_state_list, fault_round_idx, nibble_idx, delta_in)
            fcip = fault_state_list[no_of_rounds-1].copy()


            cip = inv_perm(cip)
            fcip = inv_perm(fcip)

            dummy_keysp = []
            for key_r1 in keyspace[nibble_idx]:
                if  ((inv_sbox_table[cip[nibble_idx] ^ key_r1] ^ inv_sbox_table[fcip[nibble_idx] ^ key_r1]) == delta_in):    
                    dummy_keysp.append(key_r1)

            keyspace[nibble_idx] = dummy_keysp.copy()

    return keyspace
    



def attack_enc1(key_core, k3, starting_keyset):
    # sbox and inv sbox of default layer
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # getting round keys from the core key
    key_layer = key_schedule(key_core)

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]

    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            # taking random msg
            msg = [secrets.randbelow(16) for _ in range(32)]

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
            fault_state_list = [[] for i in range(no_of_rounds)]

            # here for k2, we gave the fault before just one round
            fault_round_idx = no_of_rounds - 2
            fault_state_list = fault_oracle(msg, key_layer, key_core, fault_state_list, fault_round_idx, nibble_idx, delta_in)
            fcip = fault_state_list[no_of_rounds-1].copy()

            # last layer
            dec_cip = inv_perm(cip)
            dec_fcip = inv_perm(fcip)

            dec_cip = [i^j for i, j in zip(dec_cip, k3)]
            dec_fcip = [i^j for i, j in zip(dec_fcip, k3)]

            # 2nd last layer
            dec_cip = inv_perm(inv_sbox(dec_cip))
            dec_fcip = inv_perm(inv_sbox(dec_fcip))

            dummy_keysp = []
            for key_r1 in keyspace[nibble_idx]:
                if  ((inv_sbox_table[dec_cip[nibble_idx] ^ key_r1] ^ inv_sbox_table[dec_fcip[nibble_idx] ^ key_r1]) == delta_in):    
                    dummy_keysp.append(key_r1)

            keyspace[nibble_idx] = dummy_keysp.copy()

    return keyspace



def attack_enc2(key_core, k2, k3, starting_keyset):
    # sbox and inv sbox of default layer
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # getting round keys from the core key
    key_layer = key_schedule(key_core)

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]

    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            # taking random msg
            msg = [secrets.randbelow(16) for _ in range(32)]

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
            fault_state_list = [[] for i in range(no_of_rounds)]

            # here for k1, we gave the fault before just one round
            fault_round_idx = no_of_rounds - 3
            fault_state_list = fault_oracle(msg, key_layer, key_core, fault_state_list, fault_round_idx, nibble_idx, delta_in)
            fcip = fault_state_list[no_of_rounds-1].copy()

            # last layer
            dec_cip = inv_perm(cip)
            dec_fcip = inv_perm(fcip)

            dec_cip = [i^j for i, j in zip(dec_cip, k3)]
            dec_fcip = [i^j for i, j in zip(dec_fcip, k3)]

            # 2nd last layer
            dec_cip = inv_perm(inv_sbox(dec_cip))
            dec_fcip = inv_perm(inv_sbox(dec_fcip))

            dec_cip = [i^j for i, j in zip(dec_cip, k2)]
            dec_fcip = [i^j for i, j in zip(dec_fcip, k2)]

            # 3rd last layer
            dec_cip = inv_perm(inv_sbox(dec_cip))
            dec_fcip = inv_perm(inv_sbox(dec_fcip))

            dummy_keysp = []
            for key_r1 in keyspace[nibble_idx]:
                if  ((inv_sbox_table[dec_cip[nibble_idx] ^ key_r1] ^ inv_sbox_table[dec_fcip[nibble_idx] ^ key_r1]) == delta_in):    
                    dummy_keysp.append(key_r1)

            keyspace[nibble_idx] = dummy_keysp.copy()

    return keyspace



def attack_enc3(key_core, k1, k2, k3, starting_keyset):
    # sbox and inv sbox of default layer
    sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
    inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

    # getting round keys from the core key
    key_layer = key_schedule(key_core)

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]

    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            # taking random msg
            msg = [secrets.randbelow(16) for _ in range(32)]

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
            fault_state_list = [[] for i in range(no_of_rounds)]

            # here for k1, we gave the fault before just one round
            fault_round_idx = no_of_rounds - 4
            fault_state_list = fault_oracle(msg, key_layer, key_core, fault_state_list, fault_round_idx, nibble_idx, delta_in)
            fcip = fault_state_list[no_of_rounds-1].copy()

            # last layer
            dec_cip = inv_perm(cip)
            dec_fcip = inv_perm(fcip)

            dec_cip = [i^j for i, j in zip(dec_cip, k3)]
            dec_fcip = [i^j for i, j in zip(dec_fcip, k3)]

            # 2nd last layer
            dec_cip = inv_perm(inv_sbox(dec_cip))
            dec_fcip = inv_perm(inv_sbox(dec_fcip))

            dec_cip = [i^j for i, j in zip(dec_cip, k2)]
            dec_fcip = [i^j for i, j in zip(dec_fcip, k2)]

            # 3rd last layer
            dec_cip = inv_perm(inv_sbox(dec_cip))
            dec_fcip = inv_perm(inv_sbox(dec_fcip))

            dec_cip = [i^j for i, j in zip(dec_cip, k1)]
            dec_fcip = [i^j for i, j in zip(dec_fcip, k1)]

            # 4th last layer
            dec_cip = inv_perm(inv_sbox(dec_cip))
            dec_fcip = inv_perm(inv_sbox(dec_fcip))

            dummy_keysp = []
            for key_r1 in keyspace[nibble_idx]:
                if  ((inv_sbox_table[dec_cip[nibble_idx] ^ key_r1] ^ inv_sbox_table[dec_fcip[nibble_idx] ^ key_r1]) == delta_in):    
                    dummy_keysp.append(key_r1)

            keyspace[nibble_idx] = dummy_keysp.copy()

    return keyspace



def main():
    # taking a msg of 128 bits
    msg = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 
    #msg = [secrets.randbelow(16) for _ in range(32)]

    global no_of_rounds
    no_of_rounds = 80

    # defining key list for default core
    key_core = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 
    # key_core = [secrets.randbelow(16) for _ in range(32)]

    # defining original key list for default layer
    key_layer = key_schedule(key_core)

    # --------------------------------------------------------------------------------------
    # normalized key schedule related things
    # --------------------------------------------------------------------------------------
    nks_list = normalize_key_schedule(key_layer).copy()
    nks_list1 = normalize_key_schedule1(key_layer).copy()
    nks_list2 = normalize_key_schedule2(key_layer).copy()
    nks_list3 = normalize_key_schedule3(key_layer).copy()

    # recovering k1, k2, k3 by giving 2 faults at each nibble
    k3 = single_key(attack_enc(key_core, range(4)))
    k2 = single_key(attack_enc1(key_core, k3, range(4)))
    k1 = single_key(attack_enc2(key_core, k2, k3, range(4)))
    k0 = attack_enc3(key_core, k1, k2, k3, range(16))

    nks = [[] for _ in range(4)]
    nks[3] = k3.copy()
    nks[2] = k2.copy()
    nks[1] = k1.copy()
    nks[0] = k0.copy()

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
    fault_round = 8 
    fault_round_idx = no_of_rounds - fault_round

    # initializing trail list and cip fcip list
    trail_list = []
    cip_fcip_list = []

    # the number of faults in an exp
    no_of_faults = 32

    # giving fault at each nibble
    fix_fault_nibble = [i for i in range(32)]
    #fix_fault_nibble = [0, 4, 8, 12, 16, 20, 24, 28] #unique key recovery:: verified!!
    #fix_fault_nibble = [0, 4, 8, 16, 20, 24] #unique key recovery:: verified!!
    # fix_fault_nibble = [0, 8, 11, 16, 24] #unique key recovery:: verified!!
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

        inter_cip_fcip_list = rotating_key_schedule_finding_trail(cip, fcip, nks)

        cip_fcip_list.append(inter_cip_fcip_list.copy())

        inter_cip = inter_cip_fcip_list[0].copy()
        inter_fcip = inter_cip_fcip_list[1].copy()

        # finding the trail after decrypting the 3 rounds by k3, k2, k1
        cip_diff = [inter_cip^inter_fcip for inter_cip, inter_fcip in zip(inter_cip, inter_fcip)]

        # taking cip output diff
        trail_list = finding_trail_5_round(cip_diff, fault_val, fault_nibble, trail_list).copy()

    global original_key
    original_key = inv_perm(nks_list[0])

    print('\noriginal key: ', original_key)

    # ------------------------------------------------------------------------------------
    # r2 attack
    # ------------------------------------------------------------------------------------
    r2_keyspace = attack_r2(trail_list, k0, k3, cip_fcip_list)

    for qr in range(8):
        # print('\n\nkey space for ' + str(qr) + 'grp: ', r2_keyspace[qr])
        if ((original_key[qr+0], original_key[qr+8], original_key[qr+16], original_key[qr+24]) in r2_keyspace[qr]):
            print('key is there for the qr group ' + str(qr))



    # done upto r2 attack
    # ------------------------------------------------------------------------------------
    # r3 attack
    # ------------------------------------------------------------------------------------
    r3_keyspace = attack_r3(trail_list, r2_keyspace, k0, k1, k2, k3, cip_fcip_list)
    print('r3 keyspace done.')
    print('r3 keyspace:', r3_keyspace)

    ### ------------------------------------------------------------------------------------
    ### r4 attack
    ### ------------------------------------------------------------------------------------
    ##r4_keyspace = attack_r4(trail_list, r1_keyspace, r2_keyspace, r3_keyspace, cip_fcip_list)
    ##print('r4 keyspace done.')
    ##print('len of r4 keyspace:', r4_keyspace)
    ##print('r4 keyspace:', len(r4_keyspace))

    ### ------------------------------------------------------------------------------------
    ### r5 attack
    ### ------------------------------------------------------------------------------------
    ##r5_keyspace = attack_r5(trail_list, r1_keyspace, r2_keyspace, r3_keyspace, r4_keyspace, cip_fcip_list)
    ##print('r5 keyspace done.')
    ##print('len of r5 keyspace:', r5_keyspace)
    ##print('r5 keyspace:', len(r5_keyspace))



if __name__ == '__main__':
    # for exp in range(100):
    for exp in range(1):
        out = main()
        if (out == 1):
            print('exp ', exp, ' success.')
        else:
            print('exp ', exp, ' fails.')
            break

