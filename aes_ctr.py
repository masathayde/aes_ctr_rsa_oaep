from aes_128 import AES_128_Key_Expansion
import random
import os
from helper import bytes_xor
import time
import aes_constants
from copy import copy

def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()

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


# Output: cyphertext and nonce
def AES_128_CTR(data: bytearray, nonce: bytes, round_keys: bytes) -> bytes:
    numberOfBlocks = -(len(data)//-16) # ceiling division
    lastBlockLength = len(data) % 16
    if (lastBlockLength == 0): # In case the datastream's length is a multiple of 16
        lastBlockLength = 16
    stream = b''
    noncePlusCounter = (nonce << 32)
    for i in range(0, numberOfBlocks - 1):
        counterBlock = bytearray(int.to_bytes(noncePlusCounter, 16, 'big'))
        keystream = AES_128_11R_CTR_A(counterBlock, round_keys)
        stream = stream + (bytes_xor(data[i*16:i*16+16], bytes(keystream)))
        noncePlusCounter += 1
    # Last block
    i = numberOfBlocks - 1
    counterBlock = bytearray(int.to_bytes(noncePlusCounter, 16, 'big'))
    keystream = AES_128_11R_CTR_A(counterBlock, round_keys)
    stream = stream + (bytes_xor(data[i*16:i*16+lastBlockLength], bytes(keystream[:lastBlockLength])))
    return stream

# key = 299984085813498672233706979041151314691
# # number = 1123231413242324242323423
# data = b'\xff\x07'
# key_b = key.to_bytes(16, 'big')
# round_keys = AES_128_Key_Expansion(key_b)
# nonce = (1 << 95) + random.getrandbits(95)

# result = AES_128_CTR(data, nonce, round_keys)
# result_int = int.from_bytes(result, 'big')
# print("Input: ")
# print(hex(int.from_bytes(data, 'big')))
# print("Nonce: ")
# print(hex(nonce))
# print("Key: ")
# print(hex(key))
# print("Result: ")
# print(hex(result_int))
# dec = AES_128_CTR(result, nonce, round_keys)
# print(dec)

# File test
# start_time = time.time()

# nonce = (1 << 95) + random.getrandbits(95)
# bufferSz = 512 * 1024
# filename = "night.mp3"
# fileSz = os.path.getsize(filename)
# total = fileSz/bufferSz
# it = 0
# round_keys = AES_128_Key_Expansion(key_b)
# with open(filename, "rb") as f, open("cipher.bin", "wb") as o:
#     bytestream = f.read(bufferSz)
#     while bytestream != b'':
#         printProgressBar(it, total, 'Encrypt: ')
#         stream = AES_128_CTR(bytestream, key_b, nonce, round_keys)
#         o.write(stream)
#         bytestream = f.read(bufferSz)
#         it +=1

# print("--- %s seconds ---" % (time.time() - start_time))

# it = 0
# with open("cipher.bin", "rb") as f, open("output.bin", "wb") as o:
#     stream = f.read(bufferSz)
#     while stream != b'':
#         printProgressBar(it, total, 'Decrypt: ')
#         plainstream = AES_128_CTR_enc(stream, key_b, nonce, round_keys)
#         o.write(plainstream)
#         stream = f.read(bufferSz)
#         it += 1

# print("--- %s seconds ---" % (time.time() - start_time))