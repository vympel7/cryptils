from .utils import *


class CBC(Interact):
    def __init__(self, target: str, port: int = None) -> None:
        super().__init__(target, port)

    def key_equals_iv(self, encrypt_msg, decrypt_msg, msg: bytes = None):
        if not self.connected():
            self.connect()

        if msg is None:
            msg = b'0' * (2 * AES.block_size)

        data = blockify(encrypt_msg(self.io, msg))
        if len(data) < 2:
            raise ValueError('At least 2 blocks are needed for this attack')

        payload = data[0] + data[0]
        decrypted = blockify(decrypt_msg(self.io, payload))

        KEY = IV = xor(xor(decrypted[0], decrypted[1]), data[0])
        return KEY

