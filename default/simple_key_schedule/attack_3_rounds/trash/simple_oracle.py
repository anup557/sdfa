# gist: the oracle for the default cipher
# -------------------------------------------------------------------------------------------

# -------------------------------------------------------------------------------------------
# If the print details is true then only all the state values will print
# -------------------------------------------------------------------------------------------
print_details = "false"
# print_details = "true"

def sbox(msg, layer):
    # sbox table for default layer
    sbox_default_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]

    # sbox table for default core
    sbox_core_table = [0x1, 0x9, 0x6, 0xf, 0x7, 0xc, 0x8, 0x2, 0xa, 0xe, 0xd, 0x0, 0x4, 0x3, 0xb, 0x5]

    if(layer == 'default'):
        sbox_table = sbox_default_table
    if(layer == 'core'):
        sbox_table = sbox_core_table

    cip = [0 for i in range(32)]
    # replacing nibble values of state with sbox values
    for nibble_idx, nibble in enumerate(msg):
        cip[nibble_idx] = sbox_table[nibble]

    if (print_details == "true"):
        print('after sbox:\t', cip)
    
    return cip


def perm(msg):
    # permutation table of gift
    perm_table = [0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3, 4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7, 8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11, 12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15, 16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19, 20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23, 24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27, 28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31]

    # storing the state values into bits
    state_bits = [0 for i in range(128)]
    for nibble in range(32):
        for bit in range(4):
            state_bits[4 * nibble + bit] = (msg[nibble] >> bit) & 0x1

    # permute the bits
    perm_bits = [0 for i in range(128)]
    for bit in range(128):
        perm_bits[perm_table[bit]] = state_bits[bit]

    # making cip from permute bits
    cip = [0 for i in range(32)]
    for nibble in range(32):
        cip[nibble] = 0;
        for bit in range(4):
            cip[nibble] ^= perm_bits[4 * nibble + bit] << bit;

    if (print_details == "true"):
        print('after p-layer:\t', cip)

    return cip


def add_round_key(msg, key):
    # xoring nibbles of msg and key
    cip = [msg^key for msg, key in zip(msg, key)]

    if (print_details == "true"):
        print('round key:', key)
        print('after addrk:\t', cip)

    return cip
        

# this is for core fucntion. Its key updation of core key taken from maria's default.cpp
def rotating_key_update(key):
    temp_key = [0 for i in range(32)]
    for i in range(32):
        temp_key[i] = key[(i + 8) % 32]

    for i in range(24):
        key[i] = temp_key[i];

    key[24] = temp_key[27]
    key[25] = temp_key[24]
    key[26] = temp_key[25]
    key[27] = temp_key[26]

    key[28] = ((temp_key[28] & 0xc) >> 2) ^ ((temp_key[29] & 0x3) << 2) 
    key[29] = ((temp_key[29] & 0xc) >> 2) ^ ((temp_key[30] & 0x3) << 2) 
    key[30] = ((temp_key[30] & 0xc) >> 2) ^ ((temp_key[31] & 0x3) << 2) 
    key[31] = ((temp_key[31] & 0xc) >> 2) ^ ((temp_key[28] & 0x3) << 2) 

    if (print_details == "true"):
        print('round key:\t', key)

    return key


# key schedule function
def generate_round_keys(key):
    round_key = [[] for rnd in range(4)]
    round_key[0] = key.copy()

    # defining rc for key schedule
    rc = [0 for i in range(32)]
    rc[31] = 8

    for rnd in range(3):
        round_key[rnd+1] = round_key[rnd].copy()
        # for i in range(4):
        round_key[rnd+1] = sbox(round_key[rnd+1], 'default').copy()
        round_key[rnd+1] = perm(round_key[rnd+1]).copy()
        round_key[rnd+1] = [round_key[rnd+1]^rc for round_key[rnd+1], rc in zip(round_key[rnd+1], rc)]

    return round_key


# defining oracle
def oracle(msg, original_key, state_list):
    # defining number of rounds for default and core layer
    no_of_rounds = 80
    core_rounds = 24
    default_rounds = 28

    # copying 0-th list in state list[0]
    state_list[0] = msg.copy()
    key = original_key.copy()

    for round_num in range(no_of_rounds):
        # default core
        if ((round_num >= default_rounds) and (round_num < (default_rounds+core_rounds))):
            if(print_details == "true"):
                print('\n' + '*'*100)
                print('for default core:')
                print('*'*100)

                print('for round ' + str(round_num - default_rounds) + ': ')

            msg = sbox(msg, 'core')
            msg = perm(msg)
            msg = add_round_key(msg, key)

            key = rotating_key_update(key) 

        # front and back default layer
        else:
            # key = key_layer.copy()

            if(print_details == "true"):
                print('\n' + '*'*100)
                print('for default layer:')
                print('*'*100)

                print('for round ' + str(round_num) + ': ')

            msg = sbox(msg, 'default')
            msg = perm(msg)
            msg = add_round_key(msg, key)

        # copying msg at each round
        state_list[round_num] = msg.copy()

    return state_list

