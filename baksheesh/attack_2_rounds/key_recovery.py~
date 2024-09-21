# gist: code for the 3 rounds of the baksheesh cipher. 
# attack r1:  Using the input and output difference of the key nibbles in last round the keyspace has been reduced.
#             Due to the LS structured property of the baksheesh sbox, after one in-out diff, the keyspace of the nibble reduces
#             to 2^2 and after two in-out diff, this reduces to 2^1.

# attack_r2:  Here we have taken the product keyspace of the reduced r1 keyspace.
#             The reduction of the r2 keyspace is being done in three phases. In the first phase only the nibbles has been considered which 
#             after the permutation layer spread to the all even nibbles. In the second phase the same for the odd nibbles has been considered.
#             In the third phase, the we have taken the product of those key nibbles which has not been reduced to the unique one and check the
#             filter.

# attack_r3:  In this attack part, we have taken the reduced keyspace of r2 and check whether the in-out diff for the third last round has
#             been satisfied or not.

# Result:     Using this 3 round distinguisher, for fixed 1 fault val in distinct nibbles, we get the unique key choice for all of the cases.
# ------------------------------------------------------------------------------------------------------------

# from default import *
from finding_trail import *

from itertools import product
import random, secrets
import sys

def find_last_layer_diff_list(trail_list): 
    diff_list = [[] for _ in range(32)]

    for trail in trail_list:
        # extracting last layer input output
        frst_layer_input = trail[0][0]
        frst_layer_output = trail[0][1]

        # extracting mid layer input output
        second_layer_input = trail[1][0]
        second_layer_output = trail[1][1]

        # extracting diff for a nibble
        for i in range(32):
            if second_layer_input[i] != 0:
                dummy_list = [second_layer_input[i], second_layer_output[i]]
                if dummy_list not in diff_list[i]:
                    diff_list[i].append(dummy_list)

    return diff_list


# key recovery attack of the last round 
def attack_r1(trail_list, r1_keyspace, cip):    
    # sbox table for default layer
    sbox_table = [0x3, 0x0, 0x6, 0xD, 0xB, 0x5, 0x8, 0xE, 0xC, 0xF, 0x9, 0x2, 0x4, 0xA, 0x7, 0x1]
    inv_sbox_table = [0x1, 0xf, 0xb, 0x0, 0xc, 0x5, 0x2, 0xe, 0x6, 0xa, 0xd, 0x4, 0x8, 0x3, 0x7, 0x9]

    last_layer_diff_list = [] 
    last_layer_diff_list = find_last_layer_diff_list(trail_list) 

    # for the add round key
    cip[8] = cip[8]^0x8;
    cip = inv_perm(cip)
    
    for idx in range(32):    
       for in_out_diff in last_layer_diff_list[idx]:
       
           #if idx == 2:
               #print('nibble 2 input, output diff::', in_out_diff)
           if len(in_out_diff) == 0:
               continue
           dummy_keysp = []
           for key_r1 in r1_keyspace[idx]:
               if  ((inv_sbox_table[cip[idx] ^ key_r1] ^ inv_sbox_table[cip[idx] ^ in_out_diff[1] ^ key_r1]) == in_out_diff[0]):    
                   dummy_keysp.append(key_r1)
                   #if idx == 2:
                   #     print(key_r1)
           r1_keyspace[idx].clear()
           r1_keyspace[idx] = dummy_keysp

    return r1_keyspace    


# circular left shift for the round key of baksheesh cipher
def circ_left_shift(msg):
    carry_bit_prev = 0 
    for i in range(32):
        carry_bit = (msg[i]>>3)&1
        msg[i] = ((msg[i]<<1)|carry_bit_prev)&0xf
        carry_bit_prev = carry_bit

    msg[0] |= carry_bit_prev&0xf

    return msg 


# key recovery attack on round 2
def attack_r2(trail_list, r1_keyspace, cip_fcip_list):    
    # sbox and the inv sbox of baksheesh cipher
    sbox_table = [0x3, 0x0, 0x6, 0xD, 0xB, 0x5, 0x8, 0xE, 0xC, 0xF, 0x9, 0x2, 0x4, 0xA, 0x7, 0x1]
    inv_sbox_table = [0x1, 0xf, 0xb, 0x0, 0xc, 0x5, 0x2, 0xe, 0x6, 0xa, 0xd, 0x4, 0x8, 0x3, 0x7, 0x9]

    # eq nibble list is to store the [nibble idx, values] that will be equal for all the reduced key values
    eq_nibble_list = []

    # ------------------------------------------------------------------------------------------------------
    # Part one. Here we have taken the nibbles so that after one permutation layer the nibbles spread to the 
    # even nibbles
    # ------------------------------------------------------------------------------------------------------
    r2_keyspace = list(product(r1_keyspace[0], r1_keyspace[1], r1_keyspace[2], r1_keyspace[3],
                                 r1_keyspace[8], r1_keyspace[9], r1_keyspace[10], r1_keyspace[11],
                                 r1_keyspace[16], r1_keyspace[17], r1_keyspace[18], r1_keyspace[19],
                                 r1_keyspace[24], r1_keyspace[25], r1_keyspace[26], r1_keyspace[27]))
    r2_keyspace_even = []

    # checking for this nibbles as for these only after two permutation layer the nibbles spread only in the 
    # even nibbles
    for nibble_idx in [0, 1, 2, 3, 8, 9, 10, 11]:
        print('\n*****************************************************************************************')
        print('len at initial: ', len(r2_keyspace))
        print('checking for nibble ' + str(nibble_idx) + ': ')
        for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):
            if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
                cip = cip_fcip[0]
                fcip = cip_fcip[1]

                for key_idx, key4 in enumerate(r2_keyspace):
                    if(r2_keyspace[key_idx] == 9999):
                        continue

                    # forming the last round key from the group idx
                    last_key = [0 for i in range(32)]

                    for idx_j, j in enumerate([0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27]):
                        last_key[j] = key4[idx_j]

                    last_key = perm(last_key).copy()
                    scnd_last_key = circ_left_shift(last_key.copy())

                    scnd_last_key0 = inv_perm(scnd_last_key).copy()
                    scnd_last_key0[nibble_idx] = ((scnd_last_key0[nibble_idx]&0xe)|0)&0xf
                    scnd_last_key0 = perm(scnd_last_key0).copy()

                    scnd_last_key1 = inv_perm(scnd_last_key).copy()
                    scnd_last_key1[nibble_idx] = ((scnd_last_key1[nibble_idx]&0xe)|1)&0xf
                    scnd_last_key1 = perm(scnd_last_key1).copy()

                    # ------------------------------------------------------------------------------
                    # for the last round
                    # ------------------------------------------------------------------------------
                    dec_cip = [cip^last_key for cip, last_key in zip(cip, last_key)]
                    dec_fcip = [fcip^last_key for fcip, last_key in zip(fcip, last_key)]

                    dec_cip = add_rc(dec_cip, NO_OF_ROUNDS-1)
                    dec_fcip = add_rc(dec_fcip, NO_OF_ROUNDS-1)

                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)

                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)

                    # ------------------------------------------------------------------------------
                    # for the second last round using scnd last round key with 0 in 0th bit
                    # ------------------------------------------------------------------------------
                    dec_cip0 = [i^j for i, j in zip(dec_cip, scnd_last_key0)]
                    dec_fcip0 = [i^j for i, j in zip(dec_fcip, scnd_last_key0)]

                    dec_cip0 = add_rc(dec_cip0, NO_OF_ROUNDS-2)
                    dec_fcip0 = add_rc(dec_fcip0, NO_OF_ROUNDS-2)

                    dec_cip0 = inv_perm(dec_cip0)
                    dec_fcip0 = inv_perm(dec_fcip0)

                    dec_cip0 = inv_sbox(dec_cip0)
                    dec_fcip0 = inv_sbox(dec_fcip0)

                    in_diff0 = [i^j for i, j in zip(dec_cip0, dec_fcip0)]

                    # ------------------------------------------------------------------------------
                    # for the second last round using scnd last round key with 1 in 0th bit
                    # ------------------------------------------------------------------------------
                    dec_cip1 = [i^j for i, j in zip(dec_cip, scnd_last_key1)]
                    dec_fcip1 = [i^j for i, j in zip(dec_fcip, scnd_last_key1)]

                    dec_cip1 = add_rc(dec_cip1, NO_OF_ROUNDS-2)
                    dec_fcip1 = add_rc(dec_fcip1, NO_OF_ROUNDS-2)

                    dec_cip1 = inv_perm(dec_cip1)
                    dec_fcip1 = inv_perm(dec_fcip1)

                    dec_cip1 = inv_sbox(dec_cip1)
                    dec_fcip1 = inv_sbox(dec_fcip1)

                    in_diff1 = [i^j for i, j in zip(dec_cip1, dec_fcip1)]

                    # checking whether the input diff is same as the diff in trail or not
                    if((in_diff0[nibble_idx] != trail_list[cip_fcip_idx][0][0][nibble_idx]) and 
                       (in_diff1[nibble_idx] != trail_list[cip_fcip_idx][0][0][nibble_idx])):
                        r2_keyspace[key_idx] = 9999

        # extracting the key values which passes the filter
        r2_keyspace_even = []
        for i in r2_keyspace:
            if (i != 9999):
                r2_keyspace_even.append(i)

        print('\nDone! Checking equality of the nibble pos.')

        # eq nibble is the nibble where the equality appears and eq_nibble_val is the corresponding nibble val
        eq_nibble = 0
        eq_nibble_val = 0
        for nibble_idx, nibble in enumerate([0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27]):
            for i in r2_keyspace_even:
                if (i[nibble_idx] != r2_keyspace_even[0][nibble_idx]):
                    break
                if (i == r2_keyspace_even[len(r2_keyspace_even)-1]):
                    print('eq for nibble ' + str(nibble) + '    nibble val:', r2_keyspace_even[0][nibble_idx])
                    eq_nibble = nibble
                    eq_nibble_val = r2_keyspace_even[0][nibble_idx]
                    eq_nibble_list.append([eq_nibble, eq_nibble_val])

        # updating the r2_keyspace
        r2_keyspace = r2_keyspace_even.copy()

    print('len of r2_keyspace of even nibbles: ', len(r2_keyspace_even))

    # ------------------------------------------------------------------------------------------------------
    # Part two. Here we have taken the nibbles so that after one permutation layer the nibbles spread to the 
    # odd nibbles
    # ------------------------------------------------------------------------------------------------------
    print('\n\n*****************************************************************************************')
    print('starting phase two:')
    print('*****************************************************************************************')
    r2_keyspace = list(product(r1_keyspace[4], r1_keyspace[5], r1_keyspace[6], r1_keyspace[7],
                                 r1_keyspace[12], r1_keyspace[13], r1_keyspace[14], r1_keyspace[15],
                                 r1_keyspace[20], r1_keyspace[21], r1_keyspace[22], r1_keyspace[23],
                                 r1_keyspace[28], r1_keyspace[29], r1_keyspace[30], r1_keyspace[31]))

    r2_keyspace_odd = []
    for nibble_idx in [20, 21, 22, 23, 28, 29, 30, 31]:
        print('\n*****************************************************************************************')
        print('len at initial: ', len(r2_keyspace))
        print('checking for nibble ' + str(nibble_idx) + ': ')
        for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):
            if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
                cip = cip_fcip[0]
                fcip = cip_fcip[1]

                for key_idx, key4 in enumerate(r2_keyspace):
                    if(r2_keyspace[key_idx] == 9999):
                        continue

                    # forming the last round key from the group idx
                    last_key = [0 for i in range(32)]

                    for idx_j, j in enumerate([4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31]):
                        last_key[j] = key4[idx_j]

                    last_key = perm(last_key).copy()
                    scnd_last_key = circ_left_shift(last_key.copy())

                    scnd_last_key0 = inv_perm(scnd_last_key).copy()
                    scnd_last_key0[nibble_idx] = ((scnd_last_key0[nibble_idx]&0xe)|1)&0xf
                    scnd_last_key0 = perm(scnd_last_key0).copy()

                    scnd_last_key1 = inv_perm(scnd_last_key).copy()
                    scnd_last_key1[nibble_idx] = ((scnd_last_key1[nibble_idx]&0xe)|0)&0xf
                    scnd_last_key1 = perm(scnd_last_key1).copy()

                    # ------------------------------------------------------------------------------
                    # for the last round
                    # ------------------------------------------------------------------------------
                    dec_cip = [cip^last_key for cip, last_key in zip(cip, last_key)]
                    dec_fcip = [fcip^last_key for fcip, last_key in zip(fcip, last_key)]

                    dec_cip = add_rc(dec_cip, NO_OF_ROUNDS-1)
                    dec_fcip = add_rc(dec_fcip, NO_OF_ROUNDS-1)

                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)

                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)

                    # ------------------------------------------------------------------------------
                    # for the second last round using scnd last round key with 1 in 0th bit
                    # ------------------------------------------------------------------------------
                    dec_cip0 = [i^j for i, j in zip(dec_cip, scnd_last_key0)]
                    dec_fcip0 = [i^j for i, j in zip(dec_fcip, scnd_last_key0)]

                    dec_cip0 = add_rc(dec_cip0, NO_OF_ROUNDS-2)
                    dec_fcip0 = add_rc(dec_fcip0, NO_OF_ROUNDS-2)

                    dec_cip0 = inv_perm(dec_cip0)
                    dec_fcip0 = inv_perm(dec_fcip0)

                    dec_cip0 = inv_sbox(dec_cip0)
                    dec_fcip0 = inv_sbox(dec_fcip0)

                    in_diff0 = [i^j for i, j in zip(dec_cip0, dec_fcip0)]

                    # ------------------------------------------------------------------------------
                    # for the second last round using scnd last round key with 0 in 0th bit
                    # ------------------------------------------------------------------------------
                    dec_cip1 = [i^j for i, j in zip(dec_cip, scnd_last_key1)]
                    dec_fcip1 = [i^j for i, j in zip(dec_fcip, scnd_last_key1)]

                    dec_cip1 = add_rc(dec_cip1, NO_OF_ROUNDS-2)
                    dec_fcip1 = add_rc(dec_fcip1, NO_OF_ROUNDS-2)

                    dec_cip1 = inv_perm(dec_cip1)
                    dec_fcip1 = inv_perm(dec_fcip1)

                    dec_cip1 = inv_sbox(dec_cip1)
                    dec_fcip1 = inv_sbox(dec_fcip1)

                    in_diff1 = [i^j for i, j in zip(dec_cip1, dec_fcip1)]

                    # checking whether the input diff is same as the diff in trail or not
                    if((in_diff0[nibble_idx] != trail_list[cip_fcip_idx][0][0][nibble_idx]) and 
                       (in_diff1[nibble_idx] != trail_list[cip_fcip_idx][0][0][nibble_idx])):
                        r2_keyspace[key_idx] = 9999

        r2_keyspace_odd = []
        for i in r2_keyspace:
            if (i != 9999):
                r2_keyspace_odd.append(i)

        print('len of update keyspace: ', len(r2_keyspace_odd))
        print('\nDone! Checking equality of the nibble pos.')

        # eq nibble is the nibble where the equality appears and eq_nibble_val is the corresponding nibble val
        eq_nibble = 0
        eq_nibble_val = 0
        for nibble_idx, nibble in enumerate([4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31]):
            for i in r2_keyspace_odd:
                if (i[nibble_idx] != r2_keyspace_odd[0][nibble_idx]):
                    break
                if (i == r2_keyspace_odd[len(r2_keyspace_odd)-1]):
                    print('eq for nibble ' + str(nibble) + '    nibble val:', r2_keyspace_odd[0][nibble_idx])
                    eq_nibble = nibble
                    eq_nibble_val = r2_keyspace_odd[0][nibble_idx]
                    eq_nibble_list.append([eq_nibble, eq_nibble_val])

        # updating the r2_keyspace
        r2_keyspace = r2_keyspace_odd.copy()

    print('len of r2_keyspace of odd nibbles: ', len(r2_keyspace_odd))

    # ------------------------------------------------------------------------------------------------------
    # Part three. Here we have taken the non-reduced nibble and place the unique nibble values and run the prog
    # again to reduce the product keyspace
    # ------------------------------------------------------------------------------------------------------
    print('\n\n*****************************************************************************************')
    print('starting phase three:')
    print('*****************************************************************************************')
    # taking the product of reduced even and odd keyspace of r2
    r2_keyspace = list(product(r2_keyspace_even, r2_keyspace_odd))

    # for each of the key nibbles
    for nibble_idx in [p for p in range(32)]:
        print('\n*****************************************************************************************')
        print('len at initial: ', len(r2_keyspace))
        print('checking for nibble ' + str(nibble_idx) + ': ')

        for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):
            if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
                cip = cip_fcip[0]
                fcip = cip_fcip[1]

                for key_idx, key4 in enumerate(r2_keyspace):
                    if(r2_keyspace[key_idx] == 9999):
                        continue

                    # forming the last round key from the group idx
                    last_key = [0 for i in range(32)]

                    # putting the even key nibbles in the position to make last key
                    for idx_j, j in enumerate([0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27]):
                        last_key[j] = key4[0][idx_j]

                    # putting the odd key nibbles in the position to make last key
                    for idx_j, j in enumerate([4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31]):
                        last_key[j] = key4[1][idx_j]

                    last_key = perm(last_key).copy()
                    scnd_last_key = circ_left_shift(last_key.copy())

                    # ------------------------------------------------------------------------------
                    # for the last round
                    # ------------------------------------------------------------------------------
                    dec_cip = [cip^last_key for cip, last_key in zip(cip, last_key)]
                    dec_fcip = [fcip^last_key for fcip, last_key in zip(fcip, last_key)]

                    dec_cip = add_rc(dec_cip, NO_OF_ROUNDS-1)
                    dec_fcip = add_rc(dec_fcip, NO_OF_ROUNDS-1)

                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)

                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)

                    # ------------------------------------------------------------------------------
                    # for the second last round using scnd last round key with 1 in 0th bit
                    # ------------------------------------------------------------------------------
                    dec_cip = [i^j for i, j in zip(dec_cip, scnd_last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, scnd_last_key)]

                    dec_cip = add_rc(dec_cip, NO_OF_ROUNDS-2)
                    dec_fcip = add_rc(dec_fcip, NO_OF_ROUNDS-2)

                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)

                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)

                    in_diff = [i^j for i, j in zip(dec_cip, dec_fcip)]

                    # checking whether the input diff is same as the diff in trail or not
                    if(in_diff[nibble_idx] != trail_list[cip_fcip_idx][0][0][nibble_idx]): 
                        r2_keyspace[key_idx] = 9999

        # taking the keys that passes the filter i.e. the intersection keyspace
        update_r2_keyspace = []
        for i in r2_keyspace:
            if (i != 9999):
                update_r2_keyspace.append(i)

        # storing the updated r2 keyspace at each time
        print('len of update keyspace: ', len(update_r2_keyspace))
        r2_keyspace = update_r2_keyspace.copy()

    print('len of r2_keyspace of odd nibbles: ', len(r2_keyspace))

    # storing the reduced keys before the last permutation layer
    update_r2_keyspace = []
    for key4 in r2_keyspace:
        last_key = [0 for i in range(32)]

        # putting the even key nibbles in the position to make last key
        for idx_j, j in enumerate([0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27]):
            last_key[j] = key4[0][idx_j]

        # putting the odd key nibbles in the position to make last key
        for idx_j, j in enumerate([4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31]):
            last_key[j] = key4[1][idx_j]

        update_r2_keyspace.append(last_key)

    return update_r2_keyspace


def main():
    # msg = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 
    msg = [secrets.randbelow(16) for _ in range(32)]

    # defining key list for default core
    # key = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 
    key = [secrets.randbelow(16) for _ in range(32)]
    original_key = key.copy()

    global NO_OF_ROUNDS
    NO_OF_ROUNDS = 35

    # --------------------------------------------------------------------------------------
    # oracle related things
    # --------------------------------------------------------------------------------------
    # initializing state list to store all the state vals
    state_list = [[] for i in range(NO_OF_ROUNDS)]
    state_list = oracle(msg, key, state_list)

    # taking the last outpur as cip
    cip = state_list[NO_OF_ROUNDS-1].copy()

    # --------------------------------------------------------------------------------------
    # fault oracle related things
    # --------------------------------------------------------------------------------------
    # defining fault round and fault val
    fault_round = 2
    fault_round_idx = NO_OF_ROUNDS - fault_round

    # initializing trail list and cip fcip list
    trail_list = []
    cip_fcip_list = []

    # the number of faults in an exp
    no_of_faults = 40

    # giving fault at each nibble
    #fix_fault_nibble = [i for i in range(32)]
    #fix_fault_nibble = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,0,4,8,12,16,20,24,28,1,5,9,13,17,21,25,29] #48, unique key recovery verified!!
    
    fix_fault_nibble = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,0,4,8,12,16,20,24,28] #40, unique key recovery verified!!
    
    #fault_value = [1,2,4]

    for times in range(no_of_faults):
    
        val = secrets.randbelow(3)
        # choosing fix nibble 
        fault_nibble = fix_fault_nibble[times] 

        # choosing fixed single bit value, here we are taking 4, as for 4 the hw of the output diff is max.
        # The same thing will happen for 2 also
        
        if times > 31:
            fault_val = 8
        else:
            fault_val = 1 #When # of faults = 40, 48

        fault_state_list = [[] for i in range(NO_OF_ROUNDS)]
        fault_state_list = fault_oracle(msg, key, fault_state_list, fault_round_idx, fault_nibble, fault_val)
        fcip = fault_state_list[NO_OF_ROUNDS-1].copy()

        cip_fcip_list.append([cip, fcip])

        # taking cip output diff
        cip_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
        trail_list = finding_trail_2_round(cip_diff, fault_val, fault_nibble, trail_list)

    global round_key_list 
    round_key_list = generate_round_keys(original_key)
    print('original key: ', inv_perm(round_key_list[NO_OF_ROUNDS]))
    print('second round original key: ', inv_perm(round_key_list[NO_OF_ROUNDS-1]))

    # --------------------------------------------------------------------------------
    # r1 attack
    # --------------------------------------------------------------------------------
    r1_keyspace = [[i for i in range(16)] for _ in range(32)]    
    r1_keyspace = attack_r1(trail_list, r1_keyspace, cip.copy())
    print('\nr1 keyspace done.')
    for i in range(32):
        if (inv_perm(round_key_list[NO_OF_ROUNDS])[i] not in r1_keyspace[i]):
            print('\nkey nibble not there for nibble ' + str(i))
        print('for the ' + str(i) + 'th nibble: \t', r1_keyspace[i])


    #print('trail list:', trail_list)
    # --------------------------------------------------------------------------------
    # r2 attack
    # --------------------------------------------------------------------------------
    r2_keyspace = attack_r2(trail_list, r1_keyspace, cip_fcip_list)
    print('r2_keyspace:', r2_keyspace)
    print('\nr2 keyspace done.')
    
    print('original key: ', inv_perm(round_key_list[NO_OF_ROUNDS]))



if __name__ == '__main__':
    # for exp in range(100):
    for exp in range(1):
        out = main()
        if (out == 1):
            print('exp ', exp, ' success.')
        else:
            print('exp ', exp, ' fails.')
            break

