
from copy import deepcopy
import aes_constants

# Input must be a 4-byte array.
def RotWord (byte_array_4):
    rotated_array = deepcopy(byte_array_4)
    temp = byte_array_4[0]
    for i in range(0, 3):
        rotated_array[i] = rotated_array[i + 1]
    rotated_array[3] = temp
    return rotated_array

def SubWord (byte_array_4):
    new_array = deepcopy(byte_array_4)
    for i in range(len(byte_array_4)):
        new_array[i] = aes_constants.S_Box()[byte_array_4[i]]
    return new_array

def SubWord_Inv(byte_array_4):
    new_array = deepcopy(byte_array_4)
    for i in range(len(byte_array_4)):
        new_array[i] = aes_constants.Inv_S_Box()[byte_array_4[i]]
    return new_array

# XOR between 2 arrays of bytes. They must be of the same length.
def byte_array_xor(a1, a2):
    result = []
    for i in range(len(a1)):
        result.append(a1[i] ^ a2[i])
    return result

def AES_128_Key_Expansion(key128):
    # key128 should be an array of 16 bytes.
    # expanded_key will be 11 arrays of 4-byte arrays.
    expanded_key = [[0x00]*4] * 44
    for i in range(0,4):
        temp = []
        for j in range(0,4):
            temp.append(key128[4*i+j])
        expanded_key[i] = temp

    for i in range(4, 44):
        temp = deepcopy(expanded_key[i-1])
        if (i % 4 == 0):
            temp = SubWord(RotWord(temp))
            temp = byte_array_xor(temp, aes_constants.rcon()[i//4])
        expanded_key[i] = byte_array_xor(expanded_key[i-4], temp)
    return expanded_key


def AES_128_AddRoundKey(ex_key, state, round):
    ex_key_joined = ex_key[4*round+0] + ex_key[4*round+1] + ex_key[4*round+2] + ex_key[4*round+3]
    return byte_array_xor(ex_key_joined, state)


# Not the most elegant way, but deadlines.
# State is a matrix of 16 bytes, column-major order representation.
def AES_128_ShiftRows(state):
    new_state = deepcopy(state)
    new_state[1] = state[5]
    new_state[2] = state[10]
    new_state[3] = state[15]
    new_state[5] = state[9]
    new_state[6] = state[14]
    new_state[7] = state[3]
    new_state[9] = state[13]
    new_state[10] = state[2]
    new_state[11] = state[7]
    new_state[13] = state[1]
    new_state[14] = state[6]
    new_state[15] = state[11]
    return new_state

def AES_128_ShiftRows_Inv(state):
    new_state = deepcopy(state)
    new_state[1] = state[13]
    new_state[2] = state[10]
    new_state[3] = state[7]
    new_state[5] = state[1]
    new_state[6] = state[14]
    new_state[7] = state[11]
    new_state[9] = state[5]
    new_state[10] = state[2]
    new_state[11] = state[15]
    new_state[13] = state[9]
    new_state[14] = state[6]
    new_state[15] = state[3]
    return new_state

def AES_128_MixColumns_SingleColumn(column):
    new_column = deepcopy(column)
    new_column[0] = aes_constants.mcmul_2()[column[0]] ^ aes_constants.mcmul_3()[column[1]] ^ column[2] ^ column[3]
    new_column[1] = column[0] ^ aes_constants.mcmul_2()[column[1]] ^ aes_constants.mcmul_3()[column[2]] ^ column[3]
    new_column[2] = column[0] ^ column[1] ^ aes_constants.mcmul_2()[column[2]] ^ aes_constants.mcmul_3()[column[3]]
    new_column[3] = aes_constants.mcmul_3()[column[0]] ^ column[1] ^ column[2] ^ aes_constants.mcmul_2()[column[3]]
    return new_column

def AES_128_MixColumns_SingleColumn_Inv(column):
    new_column = deepcopy(column)
    new_column[0] = aes_constants.mcmul_14()[column[0]] ^ aes_constants.mcmul_11()[column[1]] ^ aes_constants.mcmul_13()[column[2]] ^ aes_constants.mcmul_9()[column[3]]
    new_column[1] = aes_constants.mcmul_9()[column[0]] ^ aes_constants.mcmul_14()[column[1]] ^ aes_constants.mcmul_11()[column[2]] ^ aes_constants.mcmul_13()[column[3]]
    new_column[2] = aes_constants.mcmul_13()[column[0]] ^ aes_constants.mcmul_9()[column[1]] ^ aes_constants.mcmul_14()[column[2]] ^ aes_constants.mcmul_11()[column[3]]
    new_column[3] = aes_constants.mcmul_11()[column[0]] ^ aes_constants.mcmul_13()[column[1]] ^ aes_constants.mcmul_9()[column[2]] ^ aes_constants.mcmul_14()[column[3]]
    return new_column

def AES_128_MixColumns(state):
    new_state = deepcopy(state)
    for i in range (4):
        new_column = AES_128_MixColumns_SingleColumn(state[4*i:4*i+4])
        for j in range(4):
            new_state[4*i+j] = new_column[j]
    return new_state

def AES_128_MixColumns_Inv(state):
    new_state = deepcopy(state)
    for i in range (4):
        new_column = AES_128_MixColumns_SingleColumn_Inv(state[4*i:4*i+4])
        for j in range(4):
            new_state[4*i+j] = new_column[j]
    return new_state

# Block must be an array of 16 bytes, 128 bits in total.
def AES_128_11R (key128, block):
    state = deepcopy(block)
    round_keys = AES_128_Key_Expansion(key128)
    # Initial AddRoundKey
    state = AES_128_AddRoundKey(round_keys, state, 0)
    for i in range(1, 10):
        # SubBytes
        state = SubWord(state)
        # ShiftRows
        state = AES_128_ShiftRows(state)
        # MixColumns
        state = AES_128_MixColumns(state)
        # AddRoundKey
        state = AES_128_AddRoundKey(round_keys, state, i)
    # Last Round
    state = SubWord(state)
    state = AES_128_ShiftRows(state)
    state = AES_128_AddRoundKey(round_keys, state, 10)
    return state

def AES_128_11R_Inv (key128, block):
    state = deepcopy(block)
    round_keys = AES_128_Key_Expansion(key128)
    # Initial AddRoundKey
    state = AES_128_AddRoundKey(round_keys, state, 10)
    for i in range(1, 10):
        # Inverse ShiftRows
        state = AES_128_ShiftRows_Inv(state)
        # Inverse SubBytes
        state = SubWord_Inv(state)
        # AddRoundKey
        state = AES_128_AddRoundKey(round_keys, state, 10 - i)
        # Inverse MixColumns
        state = AES_128_MixColumns_Inv(state)
    # Last Round
    state = AES_128_ShiftRows_Inv(state)
    state = state = SubWord_Inv(state)
    state = AES_128_AddRoundKey(round_keys, state, 0)
    return state

# Special version of encryption function that receives round_keys as parameter.
# Used for CTR mode to avoid performing key scheduling more than once.
def AES_128_11R_CTR (block, round_keys):
    state = deepcopy(block)
    # Initial AddRoundKey
    state = AES_128_AddRoundKey(round_keys, state, 0)
    for i in range(1, 10):
        # SubBytes
        state = SubWord(state)
        # ShiftRows
        state = AES_128_ShiftRows(state)
        # MixColumns
        state = AES_128_MixColumns(state)
        # AddRoundKey
        state = AES_128_AddRoundKey(round_keys, state, i)
    # Last Round
    state = SubWord(state)
    state = AES_128_ShiftRows(state)
    state = AES_128_AddRoundKey(round_keys, state, 10)
    return state

def expand_test(key_4bytes):
    expanded_key = [[0x00]*4]
    # expanded_key[0] = (key_4bytes[0] << 3*8) + (key_4bytes[1] << 2*8) + (key_4bytes[2] << 8) + key_4bytes[3]
    expanded_key[0][0] = key_4bytes[0]
    expanded_key[0][1] = key_4bytes[1]
    expanded_key[0][2] = key_4bytes[2]
    expanded_key[0][3] = key_4bytes[3]
    return expanded_key