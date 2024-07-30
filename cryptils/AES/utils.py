from pwn import xor
from Crypto.Cipher import AES


def blockify(data, block_size: int = AES.block_size, offset: int = 0, ignore_last: int = 0):
    ignore_last = len(data) if ignore_last == 0 else len(data) - ignore_last
    return [data[i:min(i + block_size, ignore_last)] for i in range(offset, len(data), block_size)]
