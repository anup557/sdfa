# gist: the simple faulty oracle for the default cipher
# ----------------------------------------------------------------------------------------

from simple_oracle import *

def fault_oracle(msg, original_key, state_list, fault_round, fault_nibble, fault_val):
    # defining number of rounds for default and core layer
    no_of_rounds = 80
    core_rounds = 24
    default_rounds = 28

    # copying 0-th list in state list[0]
    state_list[0] = msg.copy()
    key = original_key.copy()

    for round_num in range(no_of_rounds):
        # xoring fault val at fault round
        if (round_num == fault_round):
            msg[fault_nibble] = msg[fault_nibble]^fault_val

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

        # front and back default layer
        else:
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

