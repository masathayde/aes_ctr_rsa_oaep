from pydoc import plain
from aes_128 import AES_128_Key_Expansion
from aes_128_a import AES_128_11R_CTR_A
import random
import os
from helper import bytes_xor
import time

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

key = 299984085813498672233706979041151314691
# number = 1123231413242324242323423
data = b'\xff\x07'
key_b = key.to_bytes(16, 'big')
round_keys = AES_128_Key_Expansion(key_b)
nonce = (1 << 95) + random.getrandbits(95)

result = AES_128_CTR(data, nonce, round_keys)
result_int = int.from_bytes(result, 'big')
print("Input: ")
print(hex(int.from_bytes(data, 'big')))
print("Nonce: ")
print(hex(nonce))
print("Key: ")
print(hex(key))
print("Result: ")
print(hex(result_int))
dec = AES_128_CTR(result, nonce, round_keys)
print(dec)

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
#         stream = AES_128_CTR_enc(bytestream, key_b, nonce, round_keys)
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