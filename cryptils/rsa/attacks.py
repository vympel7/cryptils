from sage.all import *

def wiener(N, e):
    for f in (e / N).continued_fraction().convergents()[1:]:
        k, d = f.numerator(), f.denominator()
        phi = ((e * d) - 1) / k
        b = phi - 1 + N
        _sqrt = iroot(b^2 - 4*N, 2)
        if _sqrt[1]:
            p = (-b + _sqrt) / 2
            q = (-b - _sqrt) / 2
            return (p, q, d)

def hastad(ciphertexts, moduli, e):
    if len(ciphertexts) < e or len(moduli) < e or len(ciphertexts) != len(moduli):
        raise ValueError('Ciphertexts and moduli arrays must be the same size and neither can have less than e elements.')

    return crt(ciphertexts[:e], moduli[:e]).nth_root(e)

def small_exponent(N, e, ciphertext, attempts = 0x1000):
    for i in range(attempts):
        _root = iroot(ciphertext, e)
        if _root[1]:
            return _root[0]
        ciphertext += N
    return None
