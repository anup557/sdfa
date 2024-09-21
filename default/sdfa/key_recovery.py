# gist: code for the last round sdfa for default, here in each nibble if 2 bit faults are set, then without
# [0, 3] and [1, 2] the key space is coming as unique (i.e. in total 64 bit faults). In the other two cases
# the key space for each nibble is coming as 2^1.
# ------------------------------------------------------------------------------------------------------------

from default import *

from itertools import product
import random, secrets

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

    no_of_rounds = 80

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
    fault_round = 1
    fault_round_idx = no_of_rounds - fault_round

    # initializing trail list and cip fcip list
    trail_list = []
    cip_fcip_list = []

    # the number of faults in an exp
    no_of_faults = 32

    # giving fault at each nibble
    fix_fault_nibble = [i for i in range(32)]

    # bit pos list is the bit positions where at each nibble the fault is given 
    # without [0, 3], [1, 2], in those cases, it reduces to 2^1 at each nibble
    bit_pos_list = [0, 1]

    # initializing the r1 keyspace for the last round
    r1_keyspace = [[i for i in range(16)] for j in range(32)]

    for times in range(no_of_faults):
        # choosing fix nibble 
        fault_nibble = fix_fault_nibble[times%len(fix_fault_nibble)] 

        for bit_pos in bit_pos_list:
            fault_state_list = [[] for i in range(no_of_rounds)]
            fault_state_list = fault_oracle(msg, key_layer, key_core, fault_state_list, fault_round_idx, fault_nibble, bit_pos)

            fcip = fault_state_list[no_of_rounds-1].copy()

            # taking intermediate bit value from prev round's state_val
            inter_bit_val = (fault_state_list[fault_round_idx-1][fault_nibble]>>bit_pos)&1

            # --------------------------------------------------------------------------------
            # attack portion after one fault
            # --------------------------------------------------------------------------------
            inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

            # taking cip output diff
            cip_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]

            # decrypting the last round
            dec_cip = cip.copy()
            dec_fcip = fcip.copy()

            dec_cip = inv_perm(dec_cip)
            dec_fcip = inv_perm(dec_fcip)

            # update r1 keyspace nibble is to store the updated keyspace of the faulty nibble
            update_r1_keyspace_nibble = []
            for key_r1 in r1_keyspace[fault_nibble]:
                # applying dfa
                if  ((inv_sbox_table[dec_cip[fault_nibble]^key_r1] ^ inv_sbox_table[dec_fcip[fault_nibble]^key_r1]) == (1<<bit_pos)):
                    # applying sfa
                    if ((inv_sbox_table[dec_cip[fault_nibble]^key_r1] >> bit_pos)&1 == inter_bit_val):
                        update_r1_keyspace_nibble.append(key_r1)

            # updating the r1 keyspace for the fault nibble
            r1_keyspace[fault_nibble] = update_r1_keyspace_nibble.copy()

    # --------------------------------------------------------------------------------
    # printing the r1 keyspace
    # --------------------------------------------------------------------------------
    print('for r1 keyspace:')
    for i in range(32):
        print('for nibble ' + str(i) + ': ', r1_keyspace[i])
 
    # printing the original key
    original_key = inv_perm(key_core)
    print('\noriginal key: ', original_key)


if __name__ == '__main__':
    # for exp in range(100):
    for exp in range(1):
        out = main()
        if (out == 1):
            print('exp ', exp, ' success.')
        else:
            print('exp ', exp, ' fails.')
            break

