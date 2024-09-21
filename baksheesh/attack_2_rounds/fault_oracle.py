# gist: the faulty oracle for the default cipher
# ----------------------------------------------------------------------------------------

from oracle import *

def fault_oracle(msg, original_key, state_list, fault_round, fault_nibble, fault_val):
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


