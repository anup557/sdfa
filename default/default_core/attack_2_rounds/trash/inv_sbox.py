if __name__=='__main__':
    sbox_table = [0x1, 0x9, 0x6, 0xf, 0x7, 0xc, 0x8, 0x2, 0xa, 0xe, 0xd, 0x0, 0x4, 0x3, 0xb, 0x5]

    inv_sbox = [0 for i in range(16)]

    for i in range(16):
        inv_sbox[sbox_table[i]] = i
    print('inv sbox: ', inv_sbox)



