import math
import hashlib
import random
from mgf1 import MGF1
from helper import bytes_xor

def OAEP_enc (message: bytes, rsa_key_size_bits: int) -> bytes:
    hLen = hashlib.sha256().digest_size # in bytes
    k = math.ceil(rsa_key_size_bits/8) # in bytes
    mLen = len(message) # in bytes
    # Check to see if message has the correct size.
    if (mLen > k - 2*hLen - 2):
        raise ValueError("Message length is too long")
    
    # Using empty string as label.
    L = b""
    labelHash = hashlib.sha256(L).digest()
    # Creating padding string
    PS = b'\x00' * (k - mLen - 2 * hLen - 2)
    DB = labelHash + PS + b'\x01' + message
    seedInt = random.getrandbits(hLen*8) # Remember: mLen is in bytes, so we have to convert it to bits here.
    seed = seedInt.to_bytes(hLen, 'big')
    dbMask = MGF1(seed, k - hLen - 1)
    maskedDB = bytes_xor(DB, dbMask)
    seedMask = MGF1(maskedDB, hLen)
    maskedSeed = bytes_xor(seed, seedMask)
    final = b'\x00' + maskedSeed + maskedDB
    return final

def OAEP_dec (message: bytes) -> "tuple[bool, bytes]" :
    # Return values
    valid = False
    decodedMessage = b''
    hLen = hashlib.sha256().digest_size # in bytes
    k = len(message) # in bytes
    L = b""
    labelHash = hashlib.sha256(L).digest()
    # Split the message.
    firstByte = message[0]
    maskedSeed = message[1:hLen+1]
    maskedDB = message[hLen+1:]
    seedMask = MGF1(maskedDB, hLen)
    seed = bytes_xor(seedMask, maskedSeed)
    dbMask = MGF1(seed, k - hLen - 1)
    # Recovering data block.
    DB = bytes_xor(dbMask, maskedDB)
    # Slicing it up.
    labelHashPrime = DB[:hLen]
    # Looking for separator.
    separatorIndex = hLen
    for i in range(hLen, len(DB)):
        if DB[i] == 1:
            break
        separatorIndex += 1
    if (separatorIndex >= len(DB)):
        return valid, decodedMessage
    PS = DB[hLen: separatorIndex]
    Separator = DB[separatorIndex]
    M = DB[separatorIndex + 1:]
    # Verification.
    hashIsSame = (labelHash == labelHashPrime)
    psValid = (PS == b'\x00' * (separatorIndex - hLen))
    spValid = (Separator == 1)
    firstByteIsZero = (firstByte == 0)
    # print(hashIsSame)
    # print(psValid)
    # print(spValid)
    # print(firstByteIsZero)
    # Putting it all together.
    if (firstByteIsZero and hashIsSame and psValid and spValid):
        valid = True
        decodedMessage = M
    return valid, decodedMessage


def test():
    m = b'hello world'
    k = 2048
    enc = OAEP_enc(m, k)
    dec = OAEP_dec(enc)
    print(enc)
    print(dec)
