from generate_prime import generatePrime

# a is the bigger number of the two.
def extended_euclidian (a, b):
    if b == 0:
        return a, 1, 0

    gcd, s, t = extended_euclidian(b, a%b)
    x = t
    y = s - (a//b) * t
    return gcd, x, y

def RSA_2048 ():
    # e candidates: 3, 17, 257, 65537.
    # Not checking if e is coprime with phi(N). We just hope it is lol.
    e_candidates = (65537, 4294967297, 257, 17, 5, 3, 18446744073709551617)
    e = 65537
    index = 1
    p = generatePrime(1024)
    q = generatePrime(1024)
    N = p * q
    phiN = (p-1)*(q-1)
    gcd, x, d = extended_euclidian(phiN, e)
    while (gcd != 1 and index < 7):
        e = e_candidates[index]
        gcd, x, d = extended_euclidian(phiN, e)
        index += 1
    if (d < 0):
        d = phiN + d

    # Debug stuff
    # print("p: " + str(p))
    # print("q: " + str(q))
    # print("N: " + str(N))
    # print("phiN: " + str(phiN))
    # print("e: " + str(e))
    # print("d: " + str(d))

    return N, e, d

