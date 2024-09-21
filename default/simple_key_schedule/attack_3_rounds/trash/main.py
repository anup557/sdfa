# gist: the prog prints the state list and the faulty state list after giving a difference at the fault round
# -------------------------------------------------------------------------------------------------

from fault_oracle import *

# -------------------------------------------------------------------------------------------------
# If the print details is true then only all the state values will print
# -------------------------------------------------------------------------------------------------
print_details = "false"
# print_details = "true"


if __name__=='__main__':
    # -------------------------------------------------------------------------------------------------
    # oracle
    # -------------------------------------------------------------------------------------------------
    msg = [i%16 for i in range(32)]

    # # defining normalized key list for default layer
    # key_layer = [[10, 15, 10, 14, 2, 5, 0, 0, 14, 1, 11, 10, 10, 6, 6, 15, 10, 15, 5, 11, 15, 10, 5, 13, 13, 15, 10, 7, 7, 14, 4, 10], 
    #         [1, 1, 2, 3, 2, 3, 1, 1, 2, 0, 2, 0, 2, 0, 1, 2, 3, 2, 2, 1, 0, 0, 1, 1, 3, 0, 1, 0, 1, 1, 1, 0],
    #         [1, 2, 3, 1, 0, 2, 2, 1, 1, 2, 1, 1, 3, 1, 2, 1, 1, 2, 1, 0, 0, 2, 3, 1, 0, 3, 3, 3, 1, 0, 2, 1],
    #         [3, 1, 1, 3, 3, 1, 2, 1, 3, 1, 3, 1, 2, 1, 0, 1, 2, 3, 1, 2, 1, 3, 2, 3, 2, 0, 1, 1, 0, 3, 3, 0]]

    # defining key list for default core
    key = [12, 9, 5, 14, 2, 5, 0, 15, 1, 1, 2, 12, 5, 9, 6, 9, 5, 0, 5, 2, 15, 12, 10, 13, 2, 0, 12, 1, 8, 8, 2, 10] 

    # initializing state list to store all the state vals
    state_list = [[] for i in range(80)]
    state_list = oracle(msg, key, state_list)
    print('\ncip:', state_list[79])
    print('\n\n')

    # -------------------------------------------------------------------------------------------------
    # faulty oracle
    # -------------------------------------------------------------------------------------------------
    # defining fault round and fault val
    fault_round = 48
    fault_nibble = 0
    fault_val = 1

    fault_state_list = [[] for i in range(80)]
    fault_state_list = fault_oracle(msg, key, fault_state_list, fault_round, fault_nibble, fault_val)
    print('\ncip:', fault_state_list[79])
    print('\n\n')

    # -------------------------------------------------------------------------------------------------
    # printing the differences
    # -------------------------------------------------------------------------------------------------
    # # print('\noriginal:')
    # # for i in range(80):
    # #     print('at round ' + str(i) + ': ', state_list[i])

    # # print('\nfor fault:')
    # # for i in range(80):
    # #     print('at round ' + str(i) + ': ', fault_state_list1[i])

    # for round_num in range(80):
    #     if (round_num == 28):
    #         print('\n\n')
    #     if (round_num == 52):
    #         print('\n\n')

    #     state_diff = [state_list[round_num]^fault_state_list1[round_num] for state_list[round_num], fault_state_list1[round_num] in zip(state_list[round_num], fault_state_list1[round_num])]
    #     print('diff at round ' + str(round_num) + ': ', state_diff)




