import numpy as np

def to_bits(data):
    assert isinstance(data, (bytes, bytearray))

    data_array = np.frombuffer(data, dtype=np.uint8)

    bits = (data_array[:, np.newaxis] >> np.arange(7, -1, -1)) & 1
    return bits.flatten()

def block_permute(block, table, m1=0):
    assert isinstance(block, np.ndarray) and isinstance(table, np.ndarray)

    return block[table - m1].astype(np.uint8)

def shift_right(arr, amount):
    assert isinstance(arr, np.ndarray)

    return np.roll(arr, amount)

def shift_left(arr, amount):
    assert isinstance(arr, np.ndarray)

    return np.roll(arr, int(arr.size - amount))

def block_xor(a, b):
    assert isinstance(a, np.ndarray) and isinstance(b, np.ndarray)

    return a ^ b
