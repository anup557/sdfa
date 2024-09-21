# gist: the faulty oracle for sdfa of the baksheesh cipher
# ----------------------------------------------------------------------------------------

from oracle import *

def inv_perm(msg):
    # permutation table of gift
    inv_perm_table = [  0, 5, 10, 15, 16, 21, 26, 31, 32, 37, 42, 47, 48, 53, 58, 63, 64, 69, 74, 79, 80, 
                        85, 90, 95, 96, 101, 106, 111, 112, 117, 122, 127, 12, 1, 6, 11, 28, 17, 22, 27, 
                        44, 33, 38, 43, 60, 49, 54, 59, 76, 65, 70, 75, 92, 81, 86, 91, 108, 97, 102, 107,
                        124, 113, 118, 123, 8, 13, 2, 7, 24, 29, 18, 23, 40, 45, 34, 39, 56, 61, 50, 55, 72, 
                        77, 66, 71, 88, 93, 82, 87, 104, 109, 98, 103, 120, 125, 114, 119, 4, 9, 14, 3, 20, 
                        25, 30, 19, 36, 41, 46, 35, 52, 57, 62, 51, 68, 73, 78, 67, 84, 89, 94, 83, 100, 105, 110, 99, 116, 121, 126, 115]

    # storing the state values into bits
    state_bits = [0 for i in range(128)]
    for nibble in range(32):
        for bit in range(4):
            state_bits[4 * nibble + bit] = (msg[nibble] >> bit) & 0x1 

    # permute the bits
    perm_bits = [0 for i in range(128)]
    for bit in range(128):
        perm_bits[inv_perm_table[bit]] = state_bits[bit]

    # making cip from permute bits
    cip = [0 for i in range(32)]
    for nibble in range(32):
        cip[nibble] = 0;
        for bit in range(4):
            cip[nibble] ^= perm_bits[4 * nibble + bit] << bit;

    return cip 


def fault_oracle(msg, original_key, state_list, fault_round, fault_nibble, bit_pos):
    # defining number of rounds for default and core layer
    global NO_OF_ROUNDS
    NO_OF_ROUNDS = 35

    key = original_key.copy()
    round_key_list = generate_round_keys(key)

    msg = add_round_key(msg, round_key_list[0])

    # round functions
    for round_num in range(NO_OF_ROUNDS):
        # xoring fault val at fault round
        if (round_num == fault_round):
            fault_val = 1<<bit_pos
            msg[fault_nibble] = msg[fault_nibble]^fault_val

        if (print_details == "true"):
            print("\n********************************************************************************")
            print("for round " + str(round_num) + ": ")
            print("********************************************************************************")

        msg = sbox(msg)
        msg = perm(msg)
        msg = add_rc(msg, round_num)
        msg = add_round_key(msg, round_key_list[round_num+1])

        state_list[round_num] = msg.copy()

    # for printing purpose
    if (print_details == "true"):
        print("********************************************************************************")

    return state_list 


