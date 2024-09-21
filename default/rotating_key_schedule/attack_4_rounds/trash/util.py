from functools import lru_cache
from os import path, mkdir

from sage.all import GF, vector, matrix, BooleanPolynomialRing, load
from sage.crypto.sboxes import SBox

from itertools import product, chain, combinations


import sys
sys.path.append("./build")
from default_cipher import *

import json
from collections import Counter
from dataclasses import dataclass

from typing import *

s_base = SBox([0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5])
si_base = s_base.inverse()
linear_structures = [(0, 0), (6, 0xa), (9, 0xf), (0xf, 5)]
linear_structures1 = [(0, 0), (0xa, 6), (0xf, 9), (5, 0xf)]

perm = [
    0,  33, 66, 99,  96,  1,  34, 67, 64, 97,  2,  35, 32, 65, 98,  3,
    4,  37, 70, 103, 100, 5,  38, 71, 68, 101, 6,  39, 36, 69, 102, 7,
    8,  41, 74, 107, 104, 9,  42, 75, 72, 105, 10, 43, 40, 73, 106, 11,
    12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15,
    16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
    20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23,
    24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27,
    28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31
]

@dataclass
class Fault:
    round_nr: int
    bit_idx: int
    a: List[int]
    b: List[int]
    delta: List[int]

    def nibble_idx(self):
        return self.bit_idx// 4
    def fault_delta(self):
        return 1 << (self.bit_idx % 4)


def fmt_state(state, replace_zeros=False):
    s = "".join(hex(x)[2:] for x in reversed(state))
    if replace_zeros:
        s = s.replace('0', '.')
    return s

def state_to_int(state):
    return int(fmt_state(state), 16)

def state_to_vec(state):
    v = vector(GF(2), 128)
    for nibble_idx in range(32):
        for bit_idx in range(4):
            v[nibble_idx * 4 + bit_idx] = ((state[nibble_idx] >> bit_idx) & 1)
    return v

def vec_to_state(vec):
    state = [0 for _ in range(32)]
    for nibble_idx in range(32):
        for bit_idx in range(4):
            state[nibble_idx] |= int(vec[nibble_idx * 4 + bit_idx]) << bit_idx
    return state

def keyschedule_to_vec(ks):
    vecs = [state_to_vec(k) for k in ks]
    vec = vector(GF(2), sum((list(v) for v in vecs), start=[]))
    return vec

def vec_to_keyschedule(vec):
    numkeys = vec.length() // 128
    return [vec_to_state(vec[i*128:(i+1)*128]) for i in range(numkeys)]


def parse_state(s):
    assert len(s) == 32
    s = s.replace('.', '0')
    res = [None] * 32
    for nibble_idx in range(32):
        res[nibble_idx] = int(s[31 - nibble_idx], 16)
    return res


def save_distr(distr, filename):
    with open(filename, "w") as f:
        json.dump({fmt_state(k): v for k,v in distr.items()}, f, indent=4, sort_keys=True)


def load_distr(filename):
    with open(filename, "r") as f:
        tmp = json.load(f)
    return {tuple(parse_state(k)): v for k, v in tmp.items()}

def possible_out_deltas(in_delta, direction):
    if direction == "fwd":
        ddt = s_base.difference_distribution_table()
    elif direction == "bwd":
        ddt = si_base.difference_distribution_table()
    else:
        raise RuntimeError("invalid direction")

    return [out_delta for out_delta in range(ddt.ncols()) if ddt[in_delta, out_delta]]


def apply_round(in_delta_map, direction):
    out_delta_map = {}


    for in_delta, prob in in_delta_map.items():

        out_deltas = [possible_out_deltas(x, direction) for x in in_delta]

        for num_transitions in (len(x) for x in out_deltas):
            prob /= num_transitions

        for out_delta in product(*out_deltas):
            if direction == "fwd":
                permuted = tuple(permute_bits(out_delta))
            elif direction == "bwd":
                permuted = tuple(inv_permute_bits(out_delta))
            else:
                raise RuntimeError("invalid direction")

            try:
                existing_prob = out_delta_map[permuted]
            except KeyError:
                existing_prob = 0

            out_delta_map[permuted] = existing_prob + prob

    return out_delta_map


def powerset(iterable):
    "powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s)+1))


def apply_round_to_possible_deltas(possible_deltas, direction:str):
    #print("bar")
    bases = []
    for nibble_idx, nibble_deltas in enumerate(possible_deltas):
        for nibble_delta in nibble_deltas:
            el = [0] * 32
            el[nibble_idx] = nibble_delta
            bases.append(tuple(el))

    next_deltas = apply_round({x: 1 for x in bases}, direction)
    next_nibble_deltas = [set() for _ in range(32)]

    for delta, _ in next_deltas.items():
        for nibble_idx, nibble_delta in enumerate(delta):
             next_nibble_deltas[nibble_idx].add(nibble_delta)

    result = [{sum(y) for y in powerset(x)} for x in next_nibble_deltas]

    return result

def apply_n_rounds(delta, direction, rounds):
    for _ in range(rounds):
        delta = apply_round(delta, direction)
    return delta

@lru_cache(maxsize=None)
def get_distr(fault_bit: int, rounds: int, direction: str):
    dirpath = path.join(path.abspath(path.dirname(__file__)), "cache")
    if not path.isdir(dirpath):
        mkdir(dirpath)
    filepath = path.join(dirpath, f"{direction}-{rounds}-{fault_bit}.json")

    if path.isfile(filepath):
        return load_distr(filepath)

    nibble_idx = fault_bit // 4
    bit_idx = fault_bit % 4

    in_delta = [0] * 32
    in_delta[nibble_idx] = 1<<bit_idx

    in_delta = tuple(in_delta)

    distr = apply_n_rounds({in_delta: 1}, direction, rounds)

    save_distr(distr, filepath)
    return distr

@lru_cache(maxsize=None)
def get_nibble_distr(fault_bit, rounds, direction: str):
    distr = get_distr(fault_bit, rounds, direction)

    nibble_delta_prob = [Counter() for _ in range(32)]
    for delta, prob in distr.items():
        for counter, nibble_delta in zip(nibble_delta_prob, delta):
            counter[nibble_delta] += prob

    print("prob distr::", nibble_delta_prob)
    return nibble_delta_prob


@lru_cache(maxsize=None)
def get_possible_deltas_fast(fault_bit, rounds, direction: str):
    SLOW_LIMIT = 3
    distr = get_distr(fault_bit, min(rounds, SLOW_LIMIT), direction)

    nibble_delta_prob = [Counter() for _ in range(32)]
    for delta, prob in distr.items():
        for counter, nibble_delta in zip(nibble_delta_prob, delta):
            counter[nibble_delta] += prob


    possible_deltas = [set(c.keys()) for c in nibble_delta_prob]

    for _ in range(rounds - SLOW_LIMIT):
        possible_deltas = apply_round_to_possible_deltas(possible_deltas, direction)

    return possible_deltas

def print_ks(key_schedule):
    for key in key_schedule:
        print(fmt_state(key))


def permutation_to_matrix(perm):
    m = matrix(GF(2), len(perm))
    for i, p in enumerate(perm):
        m[i, p] = 1
    return m


def keyset_to_anf(keyspace, varrange=None):
    for key in keyspace:
        bits = len(key) * 4
        break

    if varrange is None:
        R = BooleanPolynomialRing(bits, "x")
        variables = [R("x" + str(i)) for i in range(bits)]
    else:
        assert bits == len(varrange)
        R = BooleanPolynomialRing(bits, ["k" + str(i) for i in varrange])
        variables = [R("k" + str(i)) for i in varrange]

    poly = R(0)
    for key in keyspace:
        key_int = 0
        for idx, nibble in enumerate(key):
            key_int += nibble << (idx * 4)

        key_bits = list(reversed([int(x) for x in f"{key_int:0b}".rjust(bits, '0')]))

        tmp_poly = R(1)

        for var, key_bit in zip(variables, key_bits):
            tmp_poly *= var + 1 + key_bit

        poly = poly + tmp_poly + poly * tmp_poly
    return poly

def anf_to_equation(anf):
    if anf.degree() > 1:
        raise ValueError("argument `anf` must be linear")

    a = matrix(GF(2), [0] * 4)
    b = vector(GF(2), [0])

    for term in anf.terms():
        if term.is_one():
            b[0] += 1
        else:
            a[0, term.index()] += 1

    b[0] += 1 # we start with a*k + b == 1 but require a * k == b
    return a, b

def normalize_key_schedule(key_schedule: List[List[int]]):
    in_mask = 0xc
    in_value = 0

    key_schedule = [[y for y in x] for x in key_schedule]
    

    # print('key_schedule: ', key_schedule)
    
    # print('key_schedule[3] ', key_schedule[3])
    # print('inv_perm of key_schedule[3] ', inv_permute_bits(key_schedule[3]))
    for round_idx, round_key in reversed(list(enumerate(key_schedule))):
    
        if(round_idx > 0):
            # print('round index: ', round_idx)
            #if(round_idx == 3):
            round_key = inv_permute_bits(round_key)
            # print('round_key: ', round_idx, round_key)
            next_key_delta = [0 for _ in range(32)]

            for nibble_idx, nibble in enumerate(round_key):

                for delta_in, delta_out in linear_structures1:
                    if (nibble ^ delta_in) & in_mask == in_value:
                        round_key[nibble_idx] ^= delta_in
                        next_key_delta[nibble_idx] ^= delta_out
                        break
                else:
                    raise RuntimeError("invalid in_mask or in_value")
                    
            # print('after normalization round_key: ', round_idx, round_key)
            #if(round_idx == 3):
            round_key = permute_bits(round_key)
            for i in range(32):
                key_schedule[round_idx][i] = round_key[i]
            #next_key_delta = inv_permute_bits(next_key_delta)
            #key_schedule[round_idx - 1] = inv_permute_bits(key_schedule[round_idx - 1])
            for nibble_idx, delta in enumerate(next_key_delta):
                key_schedule[round_idx - 1][nibble_idx] ^= delta
                


    return key_schedule
    
    
def normalize_key_schedule1(key_schedule: List[List[int]]):
    in_mask = 0xc
    in_value = 0

    key_schedule = [[y for y in x] for x in key_schedule]
    

    # print('key_schedule: ', key_schedule)
    
    # print('key_schedule[3] ', key_schedule[3])
    # print('inv_perm of key_schedule[3] ', inv_permute_bits(key_schedule[3]))
    for round_idx, round_key in reversed(list(enumerate(key_schedule))):
    
        if(round_idx > 0):
            # print('round index: ', round_idx)
            #if(round_idx == 3):
            round_key = inv_permute_bits(round_key)
            # print('round_key: ', round_idx, round_key)
            next_key_delta = [0 for _ in range(32)]

            for nibble_idx, nibble in enumerate(round_key):

                for delta_in, delta_out in linear_structures1:
                    if ( (nibble ^ delta_in) >= 4 ) and ( (nibble ^ delta_in) <= 7 ):
                        round_key[nibble_idx] ^= delta_in
                        next_key_delta[nibble_idx] ^= delta_out
                        break
                else:
                    raise RuntimeError("invalid in_mask or in_value")
                    
            # print('after normalization round_key: ', round_idx, round_key)
            #if(round_idx == 3):
            round_key = permute_bits(round_key)
            for i in range(32):
                key_schedule[round_idx][i] = round_key[i]
            #next_key_delta = inv_permute_bits(next_key_delta)
            #key_schedule[round_idx - 1] = inv_permute_bits(key_schedule[round_idx - 1])
            for nibble_idx, delta in enumerate(next_key_delta):
                key_schedule[round_idx - 1][nibble_idx] ^= delta
                


    return key_schedule
    
    
def normalize_key_schedule2(key_schedule: List[List[int]]):
    in_mask = 0xc
    in_value = 0

    key_schedule = [[y for y in x] for x in key_schedule]
    

    # print('key_schedule: ', key_schedule)
    
    # print('key_schedule[3] ', key_schedule[3])
    # print('inv_perm of key_schedule[3] ', inv_permute_bits(key_schedule[3]))
    for round_idx, round_key in reversed(list(enumerate(key_schedule))):
    
        if(round_idx > 0):
            # print('round index: ', round_idx)
            #if(round_idx == 3):
            round_key = inv_permute_bits(round_key)
            # print('round_key: ', round_idx, round_key)
            next_key_delta = [0 for _ in range(32)]

            for nibble_idx, nibble in enumerate(round_key):

                for delta_in, delta_out in linear_structures1:
                    if ( (nibble ^ delta_in) >= 8 ) and ( (nibble ^ delta_in) <= 11 ):
                        round_key[nibble_idx] ^= delta_in
                        next_key_delta[nibble_idx] ^= delta_out
                        break
                else:
                    raise RuntimeError("invalid in_mask or in_value")
                    
            # print('after normalization round_key: ', round_idx, round_key)
            #if(round_idx == 3):
            round_key = permute_bits(round_key)
            for i in range(32):
                key_schedule[round_idx][i] = round_key[i]
            #next_key_delta = inv_permute_bits(next_key_delta)
            #key_schedule[round_idx - 1] = inv_permute_bits(key_schedule[round_idx - 1])
            for nibble_idx, delta in enumerate(next_key_delta):
                key_schedule[round_idx - 1][nibble_idx] ^= delta
                


    return key_schedule
    
    
    
def normalize_key_schedule3(key_schedule: List[List[int]]):
    in_mask = 0xc
    in_value = 0

    key_schedule = [[y for y in x] for x in key_schedule]
    

    # print('key_schedule: ', key_schedule)
    
    # print('key_schedule[3] ', key_schedule[3])
    # print('inv_perm of key_schedule[3] ', inv_permute_bits(key_schedule[3]))
    for round_idx, round_key in reversed(list(enumerate(key_schedule))):
    
        if(round_idx > 0):
            # print('round index: ', round_idx)
            #if(round_idx == 3):
            round_key = inv_permute_bits(round_key)
            # print('round_key: ', round_idx, round_key)
            next_key_delta = [0 for _ in range(32)]

            for nibble_idx, nibble in enumerate(round_key):

                for delta_in, delta_out in linear_structures1:
                    if ( (nibble ^ delta_in) >= 12 ) and ( (nibble ^ delta_in) <= 15 ):
                        round_key[nibble_idx] ^= delta_in
                        next_key_delta[nibble_idx] ^= delta_out
                        break
                else:
                    raise RuntimeError("invalid in_mask or in_value")
                    
            # print('after normalization round_key: ', round_idx, round_key)
            #if(round_idx == 3):
            round_key = permute_bits(round_key)
            for i in range(32):
                key_schedule[round_idx][i] = round_key[i]
            #next_key_delta = inv_permute_bits(next_key_delta)
            #key_schedule[round_idx - 1] = inv_permute_bits(key_schedule[round_idx - 1])
            for nibble_idx, delta in enumerate(next_key_delta):
                key_schedule[round_idx - 1][nibble_idx] ^= delta
                


    return key_schedule

@lru_cache(maxsize=None)
def get_normalization_matrix(numkeys):
    dirpath = path.join(path.abspath(path.dirname(__file__)), "cache")
    if not path.isdir(dirpath):
        mkdir(dirpath)
    fname = path.join(dirpath, f"normalization-matrix-{numkeys}.sobj")

    try:
        return load(fname)
    except FileNotFoundError:
        pass

    result = matrix(GF(2), 128 * numkeys, 128 * numkeys)

    for idx in range(numkeys * 128):
        in_vec = vector(GF(2), numkeys * 128)
        in_vec[idx] = 1
        out_vec = keyschedule_to_vec(normalize_key_schedule(vec_to_keyschedule(in_vec)))
        result[:, idx] = out_vec

    try:
        result.save(fname)
    except IOError:
        pass
    return result
