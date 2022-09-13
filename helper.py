import math

def str_2_int (message: str) -> int:
    return int.from_bytes(message.encode(), 'big')

def int_2_str (number: int) -> str:
    # Assumes each char is encoded in 8 bits.
    length = math.ceil(number.bit_length()/8)
    return number.to_bytes(length, 'big').decode()

# def bytes_xor (array0: bytes, array1: bytes) -> bytes:
#     # Convert both to int.
#     cv0 = int(array0.hex(), base=16)
#     cv1 = int(array1.hex(), base=16)
#     # Use normal int XOR.
#     result = cv0 ^ cv1
#     # Back to bytes
#     length = math.ceil(result.bit_length() / 8)
#     return result.to_bytes(length, 'big')

def bytes_xor (array0: bytes, array1: bytes) -> bytes:
    assert len(array0) == len(array1)
    result = b''
    for i in range(len(array0)):
        result = result + (array0[i] ^ array1[i]).to_bytes(1, 'big')
    return result