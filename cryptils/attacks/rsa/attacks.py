from sage.all import *
from gmpy2 import iroot

def wiener(N, e):
    N, e = Integer(N), Integer(e)
    for f in (e / N).continued_fraction().convergents()[1:]:
        k, d = f.numerator(), f.denominator()
        if k == 0 or d % 2 == 0 or e*d % k != 1:
            continue

        phi = ((e * d) - 1) / k
        x = PolynomialRing(RationalField(), 'x').gen()
        f = x**2 - (N - phi + 1)*x + N
        roots = f.roots()
        if len(roots) != 2:
            continue

        p, q = int(roots[0][0]), int(roots[1][0])
        if p*q == N:
            return p, q
    return None

def hastad(ciphertexts, moduli, e):
    if len(ciphertexts) < e or len(moduli) < e or len(ciphertexts) != len(moduli):
        raise ValueError(f'Ciphertexts and moduli arrays must be the same size and neither can have less than e={e} elements.')

    return crt(ciphertexts[:e], moduli[:e]).nth_root(e)

def small_exponent(N, e, ciphertext, attempts = 0x100):
    for i in range(attempts):
        _root = iroot(int(ciphertext), int(e))
        if _root[1]:
            return _root[0]
        ciphertext += N
    return None

def pollards(N, iterations = 50):
    curr = Zmod(N)(2)

    for i in range(2, iterations):
        curr **= i
        res = gcd(curr - 1, N)
        if res != 1:
            return res
    else:
        return None

def fermat(N, rounds = 2**16):
    a = isqrt(N) + 1
    for i in range(rounds):
        if is_square((a + i)**2 - N):
            b = isqrt(a**2 - N)

            p = a + b
            q = a - b
            if p*q == N:
                return p, q
    return None
