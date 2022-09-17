import sys
from aes_ctr import AES_128_CTR
from miller_rabin import millerRabinTest
from generate_prime import generatePrime
import aes_128
import padding

#number = int(sys.argv[1])
# number = random.getrandbits(1024)
# t = 40
# result = millerRabinTest(number, t)
# length = int(sys.argv[1])
# n = generatePrime(length)
# print(n)

# with open('key_example.txt') as f:
#   test = [ int(i) for i in f ]

# print(test)
# ex = aes_128.AES_128_Key_Expansion(test)

# with open('expanded_key.txt', 'w') as f:
#     for n in ex:
#         f.write(str(n))
#         f.write('\n')

def AES_128_11R_Test(key: bytes, data: bytes):
    dataBytes = bytes(data)
    block = padding.add_padding_PKCS_16Bytes(dataBytes)
    cipher_block = aes_128.AES_128_11R(key, block)
    decipher_block = aes_128.AES_128_11R_Inv(key, cipher_block)
    result = padding.remove_padding_PKCS_16Bytes(decipher_block)
    
    print("Input: ")
    print(dataBytes)
    print("Cipher text in hex: ")
    print(str(hex(int.from_bytes(cipher_block, 'big'))))

    print("Key: ")
    print(key)
    print("Deciphered text with padding: ")
    print(bytes(decipher_block))
    print("Deciphered text without padding: ")
    print(bytes(result))

    return dataBytes == bytes(result)


# key = 299984085813498672233706979041151314691
key = 0x2b7e151628aed2a6abf7158809cf4f3c
# number = 1123231413242324242323423
input0 = 0x6bc1bee22e409f96e93d7e117393172a
input1 = 0xae2d8a571e03ac9c9eb76fac45af8e51
iv = 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
key = key.to_bytes(16, 'big')
input0 = input0.to_bytes(-(input0.bit_length()//-8), 'big')
input1 = input1.to_bytes(-(input1.bit_length()//-8), 'big')
aes_obj = AES_128_CTR(key, iv)
result = aes_obj.execute(input0)
result1 = aes_obj.execute(input1)
print(hex(int.from_bytes(result, 'big')))
print(hex(int.from_bytes(result1, 'big')))
# result = AES_128_11R_Test(key, number)
# print(result)


