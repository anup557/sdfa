# gist: code for the 3 rounds of the default cipher for simple key schedule.
# This is key recovery attack according to our work. In this prog we have used trail to find out the reduced keyspace.
# Here we give fault val 2 or 4 in 32 distinct nibbles. The reduced keyspace in the average case is 1.
# ------------------------------------------------------------------------------------------------------------



# key recovery attack on round 2
def attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list):    
    # sbox and the inv sbox of baksheesh cipher
    sbox_table = [0x3, 0x0, 0x6, 0xD, 0xB, 0x5, 0x8, 0xE, 0xC, 0xF, 0x9, 0x2, 0x4, 0xA, 0x7, 0x1]
    inv_sbox_table = [0x1, 0xf, 0xb, 0x0, 0xc, 0x5, 0x2, 0xe, 0x6, 0xa, 0xd, 0x4, 0x8, 0x3, 0x7, 0x9]

    print('\n\n*****************************************************************************************')
    print('starting attack r3')
    print('*****************************************************************************************')
    r3_keyspace = r2_keyspace.copy()

    for nibble_idx in [p for p in range(32)]:
        print('\n*****************************************************************************************')
        print('checking for nibble ' + str(nibble_idx) + ': ')
        for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):
            if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
                cip = cip_fcip[0]
                fcip = cip_fcip[1]

                for key_idx, last_key in enumerate(r3_keyspace):
                    if(r3_keyspace[key_idx] == 9999):
                        continue

                    last_key = perm(last_key).copy()
                    scnd_last_key = circ_left_shift(last_key.copy())
                    third_last_key = circ_left_shift(scnd_last_key.copy())

                    # ------------------------------------------------------------------------------
                    # for the last round
                    # ------------------------------------------------------------------------------
                    dec_cip = [i^j for i, j in zip(cip, last_key)]
                    dec_fcip = [i^j for i, j in zip(fcip, last_key)]

                    dec_cip = add_rc(dec_cip, NO_OF_ROUNDS-1)
                    dec_fcip = add_rc(dec_fcip, NO_OF_ROUNDS-1)

                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)

                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)

                    # ------------------------------------------------------------------------------
                    # for the second last round
                    # ------------------------------------------------------------------------------
                    dec_cip = [i^j for i, j in zip(dec_cip, scnd_last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, scnd_last_key)]

                    dec_cip = add_rc(dec_cip, NO_OF_ROUNDS-2)
                    dec_fcip = add_rc(dec_fcip, NO_OF_ROUNDS-2)

                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)

                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)

                    # ------------------------------------------------------------------------------
                    # for the third last round
                    # ------------------------------------------------------------------------------
                    dec_cip = [i^j for i, j in zip(dec_cip, third_last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, third_last_key)]

                    dec_cip = add_rc(dec_cip, NO_OF_ROUNDS-3)
                    dec_fcip = add_rc(dec_fcip, NO_OF_ROUNDS-3)

                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)

                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)

                    in_diff = [i^j for i, j in zip(dec_cip, dec_fcip)]

                    # checking whether the input diff is same as the diff in trail or not
                    if(in_diff[nibble_idx] != trail_list[cip_fcip_idx][0][0][nibble_idx]): 
                        r3_keyspace[key_idx] = 9999

        # extracting the satisfied keys
        update_r3_keyspace = []
        for i in r3_keyspace:
            if (i != 9999):
                update_r3_keyspace.append(i)

        print('len of update keyspace: ', len(update_r3_keyspace))
        # updating the r3 keyspace
        r3_keyspace = update_r3_keyspace.copy()

    return r3_keyspace


# def attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list):    
#     sbox_table = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]
#     inv_sbox_table = [0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9]

#     # making the nibble list from the corresponding group idx
#     # nibble_idx_list = [[i for i in range(16)], [i for i in range(16, 32)]]
#     nibble_idx_list = [[0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7, 12, 13, 14, 15], [20, 21, 22, 23, 28, 29, 30, 31, 16, 17, 18, 19, 24, 25, 26, 27]] 

#     r3_keyspace = [[], []]

#     # r1 dummy list is to store the cls representatives of r1 keyspace
#     r1_dummy_list = [[] for i in range(32)]
#     for nibble_idx in range(32):
#         for i in range(4):
#             if (i in r1_keyspace[nibble_idx]):
#                 r1_dummy_list[nibble_idx].append(i)

#     # in the third last group there are only 2 groups, 0 and 1 
#     for group_idx_last in [0,1]:
#         print('2,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n')
#         print(len(r2_keyspace[0]), len(r2_keyspace[1]), len(r2_keyspace[2]), len(r2_keyspace[3]), len(r2_keyspace[4]), len(r2_keyspace[5]), len(r2_keyspace[6]), len(r2_keyspace[7]))
#         print("Space consumed by the list using getsizeof:",sys.getsizeof(r2_keyspace[0]))
#         # producting the key space of 3rd last round
#         dummy_r3 = list(product(*[r2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))

#         for nibble_idx in nibble_idx_list[group_idx_last]:
#             # for each cip and faulty cip text pair
#             print('\nfor nibble idx:', nibble_idx)
#             for cip_fcip_idx, cip_fcip in enumerate(cip_fcip_list):

#                # if the diff appears in the nibble idx, then do the following 
#                 if (trail_list[cip_fcip_idx][0][0][nibble_idx] != 0):
#                     # extract cip and faulty cip
#                     cip = cip_fcip[0]
#                     fcip = cip_fcip[1]

#                     # initializing the count for each key of r3_keyspace
#                     count = 0
#                     rej_count = 0

#                     # for each key in the key list
#                     for key_idx, key in enumerate(dummy_r3):
#                         if(key == 9999):
#                             continue

#                         # forming the last round key from the group idx
#                         last_key = [0 for i in range(32)]
#                         for group_idx_mid in range(4):
#                             for key_0 in range(4):
#                                 last_key[group_idx_last + 2*group_idx_mid + 8*key_0] = key[group_idx_mid][key_0]

#                         # for qr group 0, 2, 5, 7
#                         if(nibble_idx in [0, 1, 2, 3, 8, 9, 10, 11, 20, 21, 22, 23, 28, 29, 30, 31]):
#                             # last layer
#                             dec_cip = inv_perm(cip)
#                             dec_fcip = inv_perm(fcip)

#                             dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
#                             dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

#                             # 2nd last layer
#                             dec_cip = inv_sbox(dec_cip)
#                             dec_fcip = inv_sbox(dec_fcip)

#                             dec_cip = inv_perm(dec_cip)
#                             dec_fcip = inv_perm(dec_fcip)

#                             dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
#                             dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

#                             # 3rd last layer
#                             dec_cip = inv_sbox(dec_cip)
#                             dec_fcip = inv_sbox(dec_fcip)

#                             dec_cip = inv_perm(dec_cip)
#                             dec_fcip = inv_perm(dec_fcip)

#                             if(group_idx_last == 0):
#                                 if ((nibble_idx%2) == 0):
#                                     in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]


#                                     # for printing purpose
#                                     if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                         count = count + 1

#                                     if(in_diff != trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                         dummy_r3[key_idx] = 9999

#                                 else:
#                                     for dummy_ele in r1_dummy_list[nibble_idx]:
#                                         in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]

#                                         # if any of the cls rep satisfies the in diff then the key4 is a possible key
#                                         if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                             count = count + 1
#                                             break

#                                         # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
#                                         if (dummy_ele == r1_dummy_list[nibble_idx][len(r1_dummy_list[nibble_idx]) - 1]):
#                                             # rej_count = rej_count + 1
#                                             dummy_r3[key_idx] = 9999

#                             # for nibbles 20, 21, 22, 23, 28, 29, 30, 31
#                             else:
#                                 # for nibbles 21, 23, 29, 31
#                                 if ((nibble_idx%2) == 1):
#                                     in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]


#                                     # for printing purpose
#                                     if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                         count = count + 1

#                                     if(in_diff != trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                         dummy_r3[key_idx] = 9999

#                                 # for nibbles 20, 22, 28, 30
#                                 else:
#                                     for dummy_ele in r1_dummy_list[nibble_idx]:
#                                         in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]

#                                         # if any of the cls rep satisfies the in diff then the key4 is a possible key
#                                         if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                             count = count + 1
#                                             break

#                                         # if the dummy ele is the last one in the list then it will remove the original key combo from the key list
#                                         if (dummy_ele == r1_dummy_list[nibble_idx][len(r1_dummy_list[nibble_idx]) - 1]):
#                                             # rej_count = rej_count + 1
#                                             dummy_r3[key_idx] = 9999

#                         # for nibble 4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 26, 27
#                         if(nibble_idx in [4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 26, 27]):
#                             eq_key_list = []
#                             if(len(r2_keyspace[nibble_idx//4]) > 16):
#                                 eq_key_list = r2_keyspace[nibble_idx//4].copy()
#                             else:
#                                 eq_key_list.append(r2_keyspace[nibble_idx//4][0])

#                             for eq_key in eq_key_list:
#                                 # last layer
#                                 dec_cip = inv_perm(cip)
#                                 dec_fcip = inv_perm(fcip)

#                                 dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
#                                 dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]

#                                 dec_cip = inv_sbox(dec_cip)
#                                 dec_fcip = inv_sbox(dec_fcip)

#                                 # 2nd last layer
#                                 dec_cip = inv_perm(dec_cip)
#                                 dec_fcip = inv_perm(dec_fcip)

#                                 # making mid key from the 0th ele of r2 keyspace
#                                 mid_key = [0 for i in range(32)]
#                                 for qr in range(8):
#                                     for i in range(4):
#                                         mid_key[qr + 8*i] = r2_keyspace[qr][0][i]

#                                 for i in range(4):
#                                     mid_key[nibble_idx//4+8*i] = eq_key[i]

#                                 dec_cip = [dec_cip^mid_key for dec_cip, mid_key in zip(dec_cip, mid_key)]
#                                 dec_fcip = [dec_fcip^mid_key for dec_fcip, mid_key in zip(dec_fcip, mid_key)]


#                                 # 3rd last layer
#                                 dec_cip = inv_sbox(dec_cip)
#                                 dec_fcip = inv_sbox(dec_fcip)

#                                 dec_cip = inv_perm(dec_cip)
#                                 dec_fcip = inv_perm(dec_fcip)


#                                 flag1 = 1
#                                 # for the left half nibbles 4, 5, 6, 7, 12, 13, 14, 15, 16,17,18,19,24,25,26,27 
#                                 if (group_idx_last == 0):
#                                     # for nibbles 4, 6, 12, 14
#                                     # flag1 = 0
#                                     if ((nibble_idx%2) == 0):
#                                         in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

#                                         # for printing purpose
#                                         if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                             count = count + 1
#                                             flag1 = 0
#                                             break

#                                     # for nibbles 5, 7, 13, 15
#                                     else:
#                                         # flag1 is used to break the for loop in r1 dummy list
#                                         flag1 = 1

#                                         for dummy_ele in r1_dummy_list[nibble_idx]:
#                                             in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]

#                                             # if any of the cls rep satisfies the in diff then the key4 is a possible key
#                                             if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                                 count = count + 1
#                                                 flag1 = 0
#                                                 break

#                                         if(flag1 == 0):
#                                             break

#                                 else:
#                                     # for nibbles 17, 19, 25, 27
#                                     if ((nibble_idx%2) == 1):
#                                         in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

#                                         # for printing purpose
#                                         if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                             if (key == ((15, 0, 10, 1), (3, 3, 6, 0), (6, 0, 10, 4), (9, 15, 7, 14))):
#                                                 print('left key is there.')
#                                             if (key == ((3, 3, 9, 14), (11, 1, 12, 4), (10, 2, 10, 10), (5, 1, 3, 1))):
#                                               print('right key is there.')

#                                             count = count + 1
#                                             flag1 = 0
#                                             break

#                                     else:
#                                         # for nibbles 16,18,24,26
#                                         for dummy_ele in r1_dummy_list[nibble_idx]:
#                                             in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]

#                                             # if any of the cls rep satisfies the in diff then the key4 is a possible key
#                                             if(in_diff == trail_list[cip_fcip_idx][0][0][nibble_idx]):
#                                                 count = count + 1
#                                                 flag1 = 0
#                                                 break

#                                         if(flag1 == 0):
#                                             break

#                                 if (eq_key == eq_key_list[len(eq_key_list) - 1]):
#                                     dummy_r3[key_idx] = 9999


#             # printing the len of reduced keyspace
#             ctr = 0 
#             for i in dummy_r3:
#                 if (i != 9999):
#                     ctr = ctr+1
#                 if (((original_key[0], original_key[8], original_key[16], original_key[24]), (original_key[2], original_key[10], original_key[18], original_key[26]), (original_key[4], original_key[12], original_key[20], original_key[28]), (original_key[6], original_key[14], original_key[22], original_key[30])) == i):
#                     print('original key is there for r3_keyspace[0].\n')

#                 if (((original_key[1], original_key[9], original_key[17], original_key[25]), (original_key[3], original_key[11], original_key[19], original_key[27]), (original_key[5], original_key[13], original_key[21], original_key[29]), (original_key[7], original_key[15], original_key[23], original_key[31])) == i):
#                     print('original key is there for r3_keyspace[1].\n')

#             print('len of reduced keyspace: ', ctr)


#         for key in dummy_r3:
#             if(key != 9999):
#                 r3_keyspace[group_idx_last].append(key)


#         # print('len r3 keyspace ', group_idx_last, ': ', len(r3_keyspace[group_idx_last]))

#         # print('r3 keyspace ', group_idx_last, ': ')
#         # for i in r3_keyspace[group_idx_last]:
#         #     print(i, end = ', ')

#     # print('\n\n')
#     return r3_keyspace


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
    fault_round = 3 
    fault_round_idx = NO_OF_ROUNDS - fault_round

    # initializing trail list and cip fcip list
    trail_list = []
    cip_fcip_list = []

    # the number of faults in an exp
    no_of_faults = 28

    # giving fault at each nibble
    fix_fault_nibble = [i for i in range(32)]

    for times in range(no_of_faults):
        # choosing fix nibble 
        fault_nibble = fix_fault_nibble[times] 

        # choosing fixed single bit value, here we are taking 4, as for 4 the hw of the output diff is max.
        # The same thing will happen for 2 also
        fault_val = 1  

        fault_state_list = [[] for i in range(NO_OF_ROUNDS)]
        fault_state_list = fault_oracle(msg, key, fault_state_list, fault_round_idx, fault_nibble, fault_val)
        fcip = fault_state_list[NO_OF_ROUNDS-1].copy()

        cip_fcip_list.append([cip, fcip])

        # taking cip output diff
        cip_diff = [cip^fcip for cip, fcip in zip(cip, fcip)]
        trail_list = finding_trail_3_round(cip_diff, fault_val, fault_nibble, trail_list)

    #print('trail list::\n', trail_list)
    
    global round_key_list 
    round_key_list = generate_round_keys(original_key)
    print('original key: ', inv_perm(round_key_list[NO_OF_ROUNDS]))
    print('second round original key: ', inv_perm(round_key_list[NO_OF_ROUNDS-1]))

    # r1 attack
    r1_keyspace = [[i for i in range(16)] for _ in range(32)]    
    r1_keyspace = attack_r1(trail_list, r1_keyspace, cip.copy())
    print('\nr1 keyspace done.')
    for i in range(32):
        if (inv_perm(round_key_list[NO_OF_ROUNDS])[i] not in r1_keyspace[i]):
            print('\nkey nibble not there for nibble ' + str(i))
        print('for the ' + str(i) + 'th nibble: \t', r1_keyspace[i])

    # r2 attack
    r2_keyspace = attack_r2(trail_list, r1_keyspace, cip_fcip_list)
    print('\nr2 keyspace done.')
    # # # ok till this

    # # r3_keyspace = attack_r3(trail_list, r1_keyspace, r2_keyspace, cip_fcip_list)

    # # print('len of r3 keyspace[0]: ', len(r3_keyspace[0]))
    # # print('len of r3 keyspace[1]: ', len(r3_keyspace[1]))
    # # # print(r3_keyspace[0])
    # # print('\n\ndone.')


if __name__ == '__main__':
    # for exp in range(100):
    for exp in range(1):
        out = main()
        if (out == 1):
            print('exp ', exp, ' success.')
        else:
            print('exp ', exp, ' fails.')
            break

