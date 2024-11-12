import numpy as np

def xor(a, b):
    if not isinstance(a, (bytes, bytearray)):
        if isinstance(a, str) and all(c in string.hexdigits for c in a):
            a = bytes.fromhex(a)
        else:
            raise ValueError('Value to xor should be bytes/bytearray/hexstring')

    if not isinstance(b, (bytes, bytearray)):
        if isinstance(b, str) and all(c in string.hexdigits for c in b):
            b = bytes.fromhex(b)
        else:
            raise ValueError('Value to xor should be bytes/bytearray/hexstring')

    shorter, longer = (a, b) if len(a) < len(b) else (b, a)

    return bytes(longer[i] ^ shorter[i % len(shorter)] for i in range(len(longer)))

def blockify(data, block_size: int = 16, offset: int = 0, ignore_last: int = 0):
    ignore_last = len(data) if ignore_last == 0 else len(data) - ignore_last
    return [data[i:min(i + block_size, ignore_last)] for i in range(offset, len(data), block_size)]

def to_bits(data):
    assert isinstance(data, (bytes, bytearray))

    data_array = np.frombuffer(data, dtype=np.uint8)

    bits = (data_array[:, np.newaxis] >> np.arange(7, -1, -1)) & 1
    return bits.flatten()

def block_permute(block, table, subtract=1):
    assert isinstance(block, np.ndarray) and isinstance(table, np.ndarray)

    return block[table - subtract].astype(np.uint8)
