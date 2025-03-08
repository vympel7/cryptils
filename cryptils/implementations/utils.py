import numpy as np

def to_bits(data):
    assert isinstance(data, (bytes, bytearray))

    data_array = np.frombuffer(data, dtype=np.uint8)

    bits = (data_array[:, np.newaxis] >> np.arange(7, -1, -1)) & 1
    return bits.flatten()

def block_permute(block, table, subtract=1):
    assert isinstance(block, np.ndarray) and isinstance(table, np.ndarray)

    return block[table - subtract].astype(np.uint8)

def xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1

def gf_mul(a, n):
    s = 0
    while n:
        if n & 1: s ^= a
        n >>= 1
        a = xtime(a)
    return s & 0xff
