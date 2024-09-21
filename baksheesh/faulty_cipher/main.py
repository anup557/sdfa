# gist: the prog prints the state list and the faulty state list after giving a difference at the fault round
# for baksheesh cipher
# -------------------------------------------------------------------------------------------------

from fault_oracle import *

if __name__=='__main__':
    # -------------------------------------------------------------------------------------------------
    # oracle
    # -------------------------------------------------------------------------------------------------
    # giving msg and key according to the test vectors
    msg = [0xc, 0x1, 0x8, 0x0, 0xa, 0x3, 0x4, 0x9, 0x6, 0x2, 0x1, 0xe, 0x5, 0x0, 0x8, 0x7, 0xd, 0x3, 0xf, 0x3, 0x6, 0xf, 0xb, 0xa, 0x1, 0x3, 0x5, 0x7, 0x1, 0x5, 0x6, 0xe]
    key = [0x5, 0x1, 0x9, 0x6, 0x7, 0xe, 0x1, 0x2, 0x3, 0x5, 0x2, 0x4, 0x8, 0x9, 0xa, 0x3, 0x3, 0xe, 0x1, 0x6, 0xc, 0xb, 0x2, 0x5, 0xb, 0xf, 0xf, 0xe, 0x0, 0x2, 0x9, 0x5]

    NO_OF_ROUNDS = 35
    state_list = [[] for i in range(NO_OF_ROUNDS)]
    state_list = oracle(msg, key, state_list)
    print('\ncip:', state_list[NO_OF_ROUNDS-1])

    # -------------------------------------------------------------------------------------------------
    # faulty oracle
    # -------------------------------------------------------------------------------------------------
    # defining fault round and fault val
    fault_round = 32
    fault_nibble = 0
    fault_val = 1

    fault_state_list = [[] for i in range(NO_OF_ROUNDS)]
    fault_state_list = fault_oracle(msg, key, fault_state_list, fault_round, fault_nibble, fault_val)
    print('\nfcip:', fault_state_list[NO_OF_ROUNDS-1])
    print('\n\n')

    # -------------------------------------------------------------------------------------------------
    # printing the differences
    # -------------------------------------------------------------------------------------------------
    # print('\noriginal:')
    # for i in range(80):
    #     print('at round ' + str(i) + ': ', state_list[i])

    # print('\nfor fault:')
    # for i in range(80):
    #     print('at round ' + str(i) + ': ', fault_state_list1[i])

    for round_num in range(NO_OF_ROUNDS):
        state_diff = [state_list[round_num]^fault_state_list[round_num] for state_list[round_num], fault_state_list[round_num] in zip(state_list[round_num], fault_state_list[round_num])]
        print('diff at round ' + str(round_num) + ': ', state_diff)




