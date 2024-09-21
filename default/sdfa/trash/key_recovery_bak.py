# gist: It the sdfa attack on baksheesh cipher. Here the fault is given at the 34th round and after giving the
# faults at 0, 3 th bit position at each nibble its coming unique choice of the round key. Hence total 64 bit set faults
# are needed to make the keyspace of the last round unique. If the fault is given at some other 2 bit combinations,
# then each nibble key space reduces to 2^1 from 2^4.
# ------------------------------------------------------------------------------------------------------------

# from default import *
from fault_oracle import *

from itertools import product
import random, secrets
import sys


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
    fault_round = 1
    fault_round_idx = NO_OF_ROUNDS - fault_round

    # initializing trail list and cip fcip list
    trail_list = []
    cip_fcip_list = []

    # the number of faults in an exp
    no_of_faults = 48

    # giving fault at each nibble
    fix_fault_nibble = [i for i in range(32)]

    # bit pos list is the bit positions where at each nibble the fault is given 
    # for bit position [0, 3], [1, 3] and [2, 3] its coming unique choice
    bit_pos_list = [2, 3]
    
    # initializing the r1 keyspace for the last round
    r1_keyspace = [[i for i in range(16)] for j in range(32)]

    for times in range(no_of_faults):
        # choosing fix nibble 
        fault_nibble = fix_fault_nibble[times%len(fix_fault_nibble)] 

        for bit_pos in bit_pos_list:
            fault_state_list = [[] for i in range(NO_OF_ROUNDS)]
            fault_state_list = fault_oracle(msg, key, fault_state_list, fault_round_idx, fault_nibble, bit_pos)
            fcip = fault_state_list[NO_OF_ROUNDS-1].copy()

            # taking intermediate bit value from prev round's state_val
            inter_bit_val = (fault_state_list[fault_round_idx-1][fault_nibble]>>bit_pos)&1

            # --------------------------------------------------------------------------------
            # attack portion after one fault
            # --------------------------------------------------------------------------------
            inv_sbox_table = [0x1, 0xf, 0xb, 0x0, 0xc, 0x5, 0x2, 0xe, 0x6, 0xa, 0xd, 0x4, 0x8, 0x3, 0x7, 0x9]

            # taking cip output diff
            cip_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]

            # decrypting the last round
            dec_cip = cip.copy()
            dec_fcip = fcip.copy()

            # xor with 0x8 is for the round constant of the last round
            dec_cip[8] = dec_cip[8]^0x8;
            dec_fcip[8] = dec_fcip[8]^0x8;

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

    global round_key_list 
    round_key_list = generate_round_keys(original_key)
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

