import aes_constants
from copy import copy
# Same as aes_128.py, but without deepcopy.

# Input must be a 4-byte array.
def RotWord (byte_array_4):
    temp = byte_array_4[0]
    for i in range(0, 3):
        byte_array_4[i] = byte_array_4[i + 1]
    byte_array_4[3] = temp

def SubWord (byte_array_4):
    for i in range(len(byte_array_4)):
        byte_array_4[i] = aes_constants.S_Box()[byte_array_4[i]]

def SubWord_Inv(byte_array_4):
    for i in range(len(byte_array_4)):
        byte_array_4[i] = aes_constants.Inv_S_Box()[byte_array_4[i]]

# XOR between 2 arrays of bytes. They must be of the same length.
def byte_array_xor(a1: bytearray, a2: bytearray):
    for i in range(len(a1)):
        a1[i] = a1[i] ^ a2[i]

def AES_128_AddRoundKey(ex_key, state, round):
    ex_key_joined = ex_key[4*round+0] + ex_key[4*round+1] + ex_key[4*round+2] + ex_key[4*round+3]
    byte_array_xor(state, ex_key_joined)

# Not the most elegant way, but deadlines.
# State is a matrix of 16 bytes, column-major order representation.
def AES_128_ShiftRows(state):
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

def AES_128_MixColumns_SingleColumn(state_c, i):
    column0, column1, column2, column3 = state_c[i:i+4]
    state_c[i] = aes_constants.mcmul_2()[column0] ^ aes_constants.mcmul_3()[column1] ^ column2 ^ column3
    state_c[i+1] = column0 ^ aes_constants.mcmul_2()[column1] ^ aes_constants.mcmul_3()[column2] ^ column3
    state_c[i+2] = column0 ^ column1 ^ aes_constants.mcmul_2()[column2] ^ aes_constants.mcmul_3()[column3]
    state_c[i+3] = aes_constants.mcmul_3()[column0] ^ column1 ^ column2 ^ aes_constants.mcmul_2()[column3]

def AES_128_MixColumns(state):
    for i in range (4):
        AES_128_MixColumns_SingleColumn(state, 4*i)

# Special version of encryption function that receives round_keys as parameter.
# Used for CTR mode to avoid performing key scheduling more than once.
def AES_128_11R_CTR_A (state: bytearray, round_keys):
    # Initial AddRoundKey
    AES_128_AddRoundKey(round_keys, state, 0)
    for i in range(1, 10):
        # print(f'Round: {i}')
        # print(f'State: {[hex(b) for b in state]}')
        # SubBytes
        SubWord(state)
        # print(f'After Sub: {[hex(b) for b in state]}')
        # ShiftRows
        AES_128_ShiftRows(state)
        # print(f'After Shift: {[hex(b) for b in state]}')
        # MixColumns
        AES_128_MixColumns(state)
        # print(f'After Mix: {[hex(b) for b in state]}')
        # AddRoundKey
        AES_128_AddRoundKey(round_keys, state, i)
        # print(f'After AddRoundKey: {[hex(b) for b in state]}')
    # Last Round
    SubWord(state)
    AES_128_ShiftRows(state)
    AES_128_AddRoundKey(round_keys, state, 10)
    return state