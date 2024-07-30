from .utils import *

def recover_IV(encrypt_msg, decrypt_msg, msg: bytes = None):
    if msg is None:
        msg = b'0' * (2 * AES.block_size)

    data = blockify(encrypt_msg(msg))
    if len(data) < 2:
        raise ValueError('At least 2 blocks are needed for this attack')

    payload = data[0] + data[0]
    decrypted = blockify(decrypt_msg(payload))

    IV = xor(xor(decrypted[0], decrypted[1]), data[0])
    return IV
