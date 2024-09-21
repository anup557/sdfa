
# If the print details is true then only all the state values will print
print_details = "false"
# print_details = "true"


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

# # original oracle
# def oracle(msg, key_layer, key_core):
#     # defining number of rounds for default and core layer
#     no_of_rounds = 80
#     core_rounds = 24
#     default_rounds = 28

#     for round_num in range(no_of_rounds):
#         # default core
#         if ((round_num >= default_rounds) and (round_num < (default_rounds+core_rounds))):
#             key = key_core

#             print('\n' + '*'*100)
#             print('for default core:')
#             print('*'*100)

#             print('for round ' + str(round_num - default_rounds) + ': ')

#             msg = sbox(msg, 'core')
#             print('after sbox:\t', msg)

#             msg = perm(msg)
#             print('after perm:\t', msg)

#             msg = add_round_key(msg, key)
#             print('add rk:\t\t', key)
#             print('after add rk:\t', msg)

#             key = rotating_key_update(key) 

#         # front and back default layer
#         else:
#             key = key_layer

#             print('\n' + '*'*100)
#             print('for default layer:')
#             print('*'*100)

#             print('for round ' + str(round_num) + ': ')

#             msg = sbox(msg, 'default')
#             print('after sbox:\t', msg)

#             msg = perm(msg)
#             print('after perm:\t', msg)

#             msg = add_round_key(msg, key[round_num%4])
#             print('add rk:\t\t', key[round_num%4])
#             print('after add rk:\t', msg)

#     return msg


def oracle(msg, key_layer, key_core, state_list):
    # defining number of rounds for default and core layer
    no_of_rounds = 80
    core_rounds = 24
    default_rounds = 28

    # copying 0-th list in state list[0]
    state_list[0] = msg.copy()

    for round_num in range(no_of_rounds):
        # default core
        if ((round_num >= default_rounds) and (round_num < (default_rounds+core_rounds))):
            # initially when default core starts, then key is key_core
            if (round_num == default_rounds):
                key = key_core.copy()

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
            key = key_layer.copy()

            if(print_details == "true"):
                print('\n' + '*'*100)
                print('for default layer:')
                print('*'*100)

                print('for round ' + str(round_num) + ': ')

            msg = sbox(msg, 'default')
            msg = perm(msg)
            msg = add_round_key(msg, key[round_num%4])

        # copying msg at each round
        state_list[round_num] = msg.copy()

    return state_list


def fault_oracle(msg, key_layer, key_core, state_list, fault_round, fault_nibble, bit_pos):
    # defining number of rounds for default and core layer
    no_of_rounds = 80
    core_rounds = 24
    default_rounds = 28

    # copying 0-th list in state list[0]
    state_list[0] = msg.copy()

    for round_num in range(no_of_rounds):
        # xoring fault val at fault round
        if (round_num == fault_round):
            fault_val = 1<<bit_pos
            msg[fault_nibble] = msg[fault_nibble]^fault_val


        # default core
        if ((round_num >= default_rounds) and (round_num < (default_rounds+core_rounds))):
            # initially when default core starts, then key is key_core
            if (round_num == default_rounds):
                key = key_core.copy()

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
            key = key_layer.copy()

            if(print_details == "true"):
                print('\n' + '*'*100)
                print('for default layer:')
                print('*'*100)
                print('for round ' + str(round_num) + ': ')

            msg = sbox(msg, 'default')
            msg = perm(msg)
            msg = add_round_key(msg, key[round_num%4])

        # copying msg at each round
        state_list[round_num] = msg.copy()

    return state_list


if __name__=='__main__':
    msg = [i%16 for i in range(32)]

    # defining normalized key list for default layer
    key_layer = [[10, 15, 10, 14, 2, 5, 0, 0, 14, 1, 11, 10, 10, 6, 6, 15, 10, 15, 5, 11, 15, 10, 5, 13, 13, 15, 10, 7, 7, 14, 4, 10], 
            [1, 1, 2, 3, 2, 3, 1, 1, 2, 0, 2, 0, 2, 0, 1, 2, 3, 2, 2, 1, 0, 0, 1, 1, 3, 0, 1, 0, 1, 1, 1, 0],
            [1, 2, 3, 1, 0, 2, 2, 1, 1, 2, 1, 1, 3, 1, 2, 1, 1, 2, 1, 0, 0, 2, 3, 1, 0, 3, 3, 3, 1, 0, 2, 1],
            [3, 1, 1, 3, 3, 1, 2, 1, 3, 1, 3, 1, 2, 1, 0, 1, 2, 3, 1, 2, 1, 3, 2, 3, 2, 0, 1, 1, 0, 3, 3, 0]]

    # # defining original key list for default layer
    # key_layer = [[12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10], 
    #              [7, 1, 15, 10, 4, 3, 1, 4, 6, 7, 3, 13, 1, 0, 11, 5, 10, 4, 3, 14, 6, 15, 7, 13, 13, 4, 3, 7, 4, 1, 2, 2], 
    #              [7, 11, 4, 1, 5, 0, 12, 7, 1, 5, 10, 10, 12, 14, 15, 1, 1, 13, 10, 0, 10, 3, 8, 7, 9, 14, 11, 4, 7, 9, 3, 7], 
    #              [5, 8, 1, 7, 3, 15, 11, 15, 9, 9, 7, 7, 2, 13, 15, 13, 11, 5, 1, 3, 1, 8, 4, 8, 8, 2, 0, 8, 0, 0, 12, 3]]

    # defining key list for default core
    key_core = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 


    # initializing state list to store all the state vals
    state_list = [[] for i in range(80)]
    state_list = oracle(msg, key_layer, key_core, state_list)
    print('\ncip:', state_list[79])
    print('\n\n')


    # defining fault round and fault val
    fault_round = 48
    fault_nibble = 0
    fault_val = 1

    fault_state_list1 = [[] for i in range(80)]
    fault_state_list1 = fault_oracle(msg, key_layer, key_core, fault_state_list1, fault_round, fault_nibble, fault_val)
    print('\ncip:', fault_state_list1[79])
    print('\n\n')

    # print('\noriginal:')
    # for i in range(80):
    #     print('at round ' + str(i) + ': ', state_list[i])

    # print('\nfor fault:')
    # for i in range(80):
    #     print('at round ' + str(i) + ': ', fault_state_list1[i])

    for round_num in range(80):
        if (round_num == 28):
            print('\n\n')
        if (round_num == 52):
            print('\n\n')

        state_diff = [state_list[round_num]^fault_state_list1[round_num] for state_list[round_num], fault_state_list1[round_num] in zip(state_list[round_num], fault_state_list1[round_num])]
        print('diff at round ' + str(round_num) + ': ', state_diff)




