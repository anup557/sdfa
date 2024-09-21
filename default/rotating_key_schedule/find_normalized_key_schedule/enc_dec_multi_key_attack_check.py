# to check whether the ciphertext is correct or not using the equivalent keys 

#!/usr/bin/env python3
from sage.all import GF, matrix, block_matrix, vector, Ideal
from sage.crypto.sboxes import SBox
from sage.crypto.boolean_function import BooleanFunction

import sys
sys.path.append("./build")

from math import *
from default_cipher import *
import random, secrets

from util import *

from typing import *

from IPython import start_ipython


s_base = SBox([0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5])
si_base = s_base.inverse()


def get_delta_dec(known_keys, round_nr: int, idx: int, delta: int):
    ct = [random.randint(0,15) for _ in range(32)]
    set_fault(2, -1, idx, delta)
    a = c.decrypt(ct)
    set_fault(2, round_nr, idx, delta)
    b = c.decrypt(ct)

    set_fault(-1, -1, 0, 0)

    a = permute_bits(sub_cells(a))
    b = permute_bits(sub_cells(b))

    for key in known_keys:
        a = [aa ^ kk for aa, kk in zip(a, key)]
        b = [bb ^ kk for bb, kk in zip(b, key)]
        a = permute_bits(sub_cells(a))
        b = permute_bits(sub_cells(b))

    return a, b, [aa^bb for aa,bb in zip(a,b)]

def get_delta_enc(round_nr: int, idx: int, delta: int):
    set_fault(2, -1, idx, delta)
    pt = [random.randint(0,15) for _ in range(32)]
    a = c.encrypt(pt)
    set_fault(2, round_nr, idx, delta)
    b = c.encrypt(pt)

    set_fault(-1, -1, 0, 0)

    a = inv_permute_bits(a)
    b = inv_permute_bits(b)

    return a, b, [aa^bb for aa,bb in zip(a,b)]

def get_keyset(a, b, delta_in, sbox):
    keys = set()
    sbox_inv = sbox.inverse()

    for k_guess in range(16):
        # print(si(a ^ k_guess) ^ si(b ^ k_guess), "==", delta_in)
        if sbox_inv(a ^ k_guess) ^ sbox_inv(b ^ k_guess) == delta_in:
            keys.add(k_guess)

    return keys


def attack_dec(known_keys, starting_keyset):
    s = si_base
    si = s.inverse()
    
    print('known_keys', known_keys, len(known_keys) + 1)

    fault_deltas = [1, 2]
    keyspace = [list(starting_keyset) for _ in range(32)]
    print('...........keyspace: ', keyspace)
    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            a, b, delta = get_delta_dec(known_keys, len(known_keys) + 1, nibble_idx, delta_in)
            a, b = a[nibble_idx], b[nibble_idx]

            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if si(a ^ k_guess) ^ si(b ^ k_guess) == delta_in:
                    new_keyset.append(k_guess)
            keyspace[nibble_idx] = new_keyset
    
    print('----------------keyspace: ', keyspace)
    return keyspace

def attack_enc():
    s = s_base
    si = s.inverse()

    fault_deltas = [1, 2]
    keyspace = [list(range(16)) for _ in range(32)]
    for nibble_idx in range(32):
        for delta_in in fault_deltas:
            a, b, delta = get_delta_enc(27, nibble_idx, delta_in)
            a, b = a[nibble_idx], b[nibble_idx]

            new_keyset = list()
            for k_guess in keyspace[nibble_idx]:
                if si(a ^ k_guess) ^ si(b ^ k_guess) == delta_in:
                    new_keyset.append(k_guess)
            keyspace[nibble_idx] = new_keyset
    return keyspace

def keyspace_to_eq_system(keyspace, apply_permuation_matrix):
    a = matrix(GF(2), 64, 128)
    b = vector(GF(2), [1] * 64)

    matrix_row = 0
    for nibble_idx in range(32):
        poly = keyset_to_anf([(x,) for x in keyspace[nibble_idx]])
        for eq in Ideal(poly + 1).groebner_basis():
            # print(eq)
            a_, b_ = anf_to_equation(eq)

            a[matrix_row, nibble_idx*4:(nibble_idx+1)*4] += a_
            b[matrix_row] += b_[0]

            matrix_row += 1

    if apply_permuation_matrix:
        a = a * permutation_to_matrix(perm)

    return a, b

def single_key(keyspace):

    print('keyspace: ', keyspace)
    key = []
    for nibble in keyspace:
        if len(nibble) != 1:
            raise RuntimeError(f"expected a single key, got {len(nibble)}")
        key.append(nibble[0])
    return key

def main():
    global c, base_key, key_schedule, nks

    R = BooleanPolynomialRing(128, ["k" + str(i) for i in range(128)])

    prev_base_key = [random.randint(0,15) for _ in range(32)]
    # prev_base_key = [0x9,0x2,0x2,0xd,0x8,0x7,0x9,0x9,0x6,0x4,0x5,0xa,0x1,0x9,0x7,0x2,0x4,0x0,0x6,0x1,0x2,0x6,0x2,0x7,0xa,0xd,0xa,0xc,0x0,0x0,0x8,0xc]

    base_key = list(reversed(prev_base_key))

    c = DefaultCipher(base_key, 4, 4)
    key_schedule = c.key_schedule

    nks = normalize_key_schedule(key_schedule)

    pt = [i for i in range(32)]
    a = c.encrypt(pt)
    print('with original key cip:', a)
    print('\n\n\n\n')


    c.key_schedule = [nks[0], nks[1], nks[2], nks[3]]
    # c.key_schedule = [[3, 1, 0, 0, 3, 3, 2, 3, 1, 2, 0, 2, 1, 0, 0, 2, 2, 1, 0, 1, 3, 3, 2, 0, 0, 0, 1, 1, 2, 2, 2, 0],
    #     [2, 1, 3, 1, 3, 0, 0, 1, 2, 0, 1, 3, 3, 0, 1, 0, 2, 0, 2, 2, 0, 2, 3, 3, 0, 1, 3, 2, 1, 3, 2, 2],
    #     [0, 1, 1, 2, 3, 3, 3, 3, 1, 1, 1, 1, 0, 2, 0, 0, 0, 3, 2, 2, 3, 3, 2, 1, 2, 2, 3, 2, 1, 0, 1, 3],
    #     [12, 8, 6, 4, 10, 14, 2, 10, 8, 3, 9, 6, 4, 10, 7, 4, 8, 15, 7, 8, 9, 5, 7, 15, 6, 12, 3, 15, 5, 9, 15, 1]]

    # print('\n\nkey schedule:')
    # for key in key_schedule:
    #     print(key)

    # print('\nnormalised key schedule:')
    # for key in nks:
    #     print(key)

    b = c.encrypt(pt)

    # key_schedule1 = c.key_schedule
    # print('\n\nnew key schedule:')
    # for key in key_schedule1:
    #     print(key)

    print('\n\ncip:', a)
    print('\nfault cip:', b)
    return

    
    keys = []
    k0 = single_key(attack_dec(keys, range(4)))
    assert k0 == nks[0]
    keys.append(k0)

    k1 = single_key(attack_dec(keys, range(4)))
    assert k1 == nks[1]
    keys.append(k1)

    k2 = single_key(attack_dec(keys, range(4)))
    assert k2 == nks[2]
    keys.append(k2)

    k3_dec = attack_dec(keys, range(16))

    assert all(nks[3][nibble_idx] in k3_dec[nibble_idx] for nibble_idx in range(32))
    k3_enc = attack_enc()

    a_enc, b_enc = keyspace_to_eq_system(k3_enc, True)
    a_dec, b_dec = keyspace_to_eq_system(k3_dec, False)


    assert a_enc * state_to_vec(nks[3]) == b_enc
    assert a_dec * state_to_vec(nks[3]) == b_dec

    a = block_matrix(2, 1, [a_enc, a_dec])
    b = vector(GF(2), list(b_enc) + list(b_dec))
    if not a * state_to_vec(nks[3]) == b:
        print("keyspace reduction failed")
        return 1

    print(f"reduced keyspace to {128 - a.rank()} bits")

    start_ipython(user_ns=globals()|locals())


if __name__ == '__main__':
    sys.exit(main() or 0)
