import oaep
from math import ceil
import rsa


def RSA_OAEP_enc (message: bytes, public_key: int, modulus: int) -> int:
    keySize = modulus.bit_length()
    paddedMessage = oaep.OAEP_enc(message, keySize)
    # print(paddedMessage)
    messageToInt = int.from_bytes(paddedMessage, 'big')
    return pow(messageToInt, public_key, modulus)

def RSA_OAEP_dec (message: int, private_key: int, modulus: int) -> "tuple[bool, bytes]":
    unRSAdMessage = pow(message, private_key, modulus)
    messageLength = ceil(modulus.bit_length()/8) 
    paddedBlock = unRSAdMessage.to_bytes(messageLength, 'big')
    # print(paddedBlock)
    return oaep.OAEP_dec(paddedBlock)

def testRSA ():
    m = b'aasff'
    N,e,d = rsa.RSA_2048()
    num = int(m.hex(), base=16)
    enc = pow(num,e,N)
    dec = pow(enc,d,N)
    r = dec.to_bytes(ceil(dec.bit_length()/8), 'big')
    print(dec == num)
    print(r == m)
    print(r)

def testRSA_int(num):
    N,e,d = rsa.RSA_2048()
    enc = pow(num,e,N)
    dec = pow(enc,d,N)
    print(num)
    print(dec)
    print(num == dec)


def test():
    m = b'im a blue man in a blue world'
    N,e,d = rsa.RSA_2048()
    enc = RSA_OAEP_enc(m, e, N)
    dec = RSA_OAEP_dec(enc, d, N)
    print(dec)
    print(dec[1] == m)