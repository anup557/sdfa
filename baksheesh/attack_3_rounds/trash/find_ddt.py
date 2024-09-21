# gist: the prog computes the ddt of the given sbox. For this the user has to give only the sbox of the corresp
# cipher and call the ddt function, the prog prints the ddt of the sbox
# --------------------------------------------------------------------------------------------------------

# function to find the ddt
def find_ddt(sbox):
    # initializing the ddt table
    ddt = [[0 for i in range(16)] for j  in range(16)]

    # calculating the ddt from the sbox
    for row in range(16):
        for in_diff in range(16):
            ddt[in_diff][sbox[row]^sbox[row^in_diff]] += 1
            
    return ddt


if __name__=='__main__':
    # cipher = 'present'
    # sbox = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

    # cipher = 'default'
    # sbox = [0x0, 0x3, 0x7, 0xe, 0xd, 0x4, 0xa, 0x9, 0xc, 0xf, 0x1, 0x8, 0xb, 0x2, 0x6, 0x5]
    
    # cipher = 'gift'
    # sbox = [0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9, 0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe]

    # cipher = 'baksheesh'
    # sbox = [0x3, 0x0, 0x6, 0xD, 0xB, 0x5, 0x8, 0xE, 0xC, 0xF, 0x9, 0x2, 0x4, 0xA, 0x7, 0x1]
    # inv_sbox of baksheesh
    # sbox = [1, 15, 11, 0, 12, 5, 2, 14, 6, 10, 13, 4, 8, 3, 7, 9]

    # # sbox of default core
    # cipher = 'default'
    # sbox = [0x1, 0x9, 0x6, 0xf, 0x7, 0xc, 0x8, 0x2, 0xa, 0xe, 0xd, 0x0, 0x4, 0x3, 0xb, 0x5]

    # inv_sbox of default core
    cipher = 'default_core'
    sbox = [11, 0, 7, 13, 12, 15, 2, 4, 6, 1, 8, 14, 5, 10, 9, 3]
    # ***********************************************************************************
    
    ddt = find_ddt(sbox)

    # printing the ddt, to print '.' in other pos the printing is big
    print('ddt of ' + str(cipher) + ': \n')
    for i in range(16):
        in_diff = []
        for j in range(16):
            if (ddt[i][j] != 0):
                in_diff.append(j)
        print(in_diff, end = ', ')


