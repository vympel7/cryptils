from cryptils.cryptils.ciphers.caesar import *
import string


def test_bruteforce():
    alphabets = string.ascii_lowercase
    print(bruteforce('normal', alphabets))

    alphabets = string.ascii_uppercase
    print(bruteforce('n0_upp&rc4se!', alphabets))

    alphabets = (string.ascii_lowercase, string.ascii_uppercase, string.digits)
    print(bruteforce('m1X3d', alphabets))

    alphabets = (string.ascii_lowercase + string.ascii_uppercase, string.digits)
    print(bruteforce('1nD3p3Nd3nT_d1G1ts', alphabets))

if __name__ == '__main__':
    test_bruteforce()
