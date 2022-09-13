import hashlib
import math

def MGF1(seed: bytes, length: int, hash=hashlib.sha256) -> bytes:
    hashLen = hash().digest_size
    T = b""
    for counter in range(0, math.ceil(length/hashLen)):
        C = int.to_bytes(counter, 4, 'big')
        T += hash(seed + C).digest()
    return T[:length]

# Output is a string.
# To get an int from this: convert output to hex with hex().
# Then use int(output_in_hex, base=16)