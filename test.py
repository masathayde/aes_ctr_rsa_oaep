import sys
from miller_rabin import millerRabinTest
from generate_prime import generatePrime
import aes_128
import aes_constants
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
key = 37777777777777777
# number = 1123231413242324242323423
number = b'oh hello'
key = key.to_bytes(16, 'big')
result = AES_128_11R_Test(key, number)
print(result)
