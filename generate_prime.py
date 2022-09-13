import random
from miller_rabin import millerRabinTest

# Exceendingly small chance of not returning a prime.
def generatePrime (bit_length = 1024):
    # Generate random numbers of specified length and test them for primality with Miller-Rabin.
    # We do it enough times so the chances of not finding ones are very small (e^(-length)).
    for _ in range(3*(bit_length**2)):
        candidate = (random.getrandbits(bit_length - 2) << 1) + 1
        candidate = (1 << (bit_length - 1)) + candidate # Making sure the number will always have the desired length and no less.
        if (millerRabinTest(candidate, 40) == True):
            return candidate
    return 0