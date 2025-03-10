from cryptils.implementations.cipher import AES
from cryptils.implementations.constants import AES_Sbox
from itertools import product
import numpy as np
import os

def one_round(plaintext1, plaintext2, ciphertext1, ciphertext2):
    p1 = np.frombuffer(plaintext1, dtype=np.uint8).reshape((4, 4)).T
    p2 = np.frombuffer(plaintext2, dtype=np.uint8).reshape((4, 4)).T
    c1 = np.frombuffer(ciphertext1, dtype=np.uint8).reshape((4, 4)).T
    c2 = np.frombuffer(ciphertext2, dtype=np.uint8).reshape((4, 4)).T

    c = AES(b'\0'*16, 0).inv_shift_rows(c1 ^ c2)

    rk0 = np.empty((16, 2), dtype=np.uint8)
    for i in np.arange(16):
        added = 0
        for byte1 in range(0, 256):
            rk_val = np.frombuffer(byte1.to_bytes(1), dtype=np.uint8)
            s1 = AES_Sbox[p1.flatten()[i] ^ rk_val]
            s2 = AES_Sbox[p2.flatten()[i] ^ rk_val]
            if s1 ^ s2 == c.flatten()[i]:
                rk0[(4*i + i // 4) % 16][added] = rk_val[0]
                added += 1
                if added == 2:
                    break
        else:
            raise ValueError('Round key values not found')

    rk0_keys = np.fromiter((rk0[j][prod[j]] for prod in product((0, 1), repeat=16) for j in np.arange(16)), dtype=np.uint8).reshape((65536, 16))

    for key in rk0_keys:
        key = key.tobytes()
        if AES(key, 1).encrypt_ecb(plaintext1) == ciphertext1:
            return key

    return None
