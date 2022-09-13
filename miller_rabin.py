import random

def millerRabinTest (number = 1, confidence = 40):

    if (number >= 1 and number <= 3):
        return True
    
    if (number % 2 == 0):
        return False

    # Let v = number - 1. We compute r and u, such that v = (2^r) * u, u being an odd number.
    v = number - 1
    r = 0
    while (v % 2 == 0):
        v = v // 2
        r += 1
    # v is now the u we were looking for.

    # We test witnesses up to the number of times determined by the confidence parameter.
    for index in range(confidence):
        a = random.randrange(2, number - 1)
        w = pow(a, v, number)
        if (w == 1 or w == number - 1):
            continue
        for i in range(1, r):
            w = pow(w, 2, number)
            if (w == number - 1):
                break
        else: return False

    return True