# gist: the faulty oracle for the default cipher
# ----------------------------------------------------------------------------------------

from oracle import *

def fault_oracle(msg, key, state_list, fault_round, fault_nibble, fault_val):
    # defining number of rounds for default and core layer
    no_of_rounds = 80
    core_rounds = 24
    default_rounds = 28

    # copying 0-th list in state list[0]
    state_list[0] = msg.copy()

    round_key = []
    round_key = generate_round_keys(key).copy()

    for round_num in range(no_of_rounds):
        # xoring fault val at fault round
        if (round_num == fault_round):
            msg[fault_nibble] = msg[fault_nibble]^fault_val

        # default core
        if ((round_num >= default_rounds) and (round_num < (default_rounds+core_rounds))):
            # initially when default core starts, then key is key_core
            if (round_num == default_rounds):
                key = key.copy()

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
            if(print_details == "true"):
                print('\n' + '*'*100)
                print('for default layer:')
                print('*'*100)
                print('for round ' + str(round_num) + ': ')

            msg = sbox(msg, 'default')
            msg = perm(msg)
            msg = add_round_key(msg, round_key[round_num%4])

        # copying msg at each round
        state_list[round_num] = msg.copy()

    return state_list

