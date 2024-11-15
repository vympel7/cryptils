from .constants import *
from cryptils.utils import *

# https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf

class DES:# {{{
    def __init__(self, key, rounds=DES_ROUNDS):# {{{
        self.key = to_bits(key)
        self.rounds = rounds

        if self.key.size != DES_KEY_SIZE:
            raise ValueError('Key should be 64 bits long.')

        self.keys = self.key_schedule(self.rounds)# }}}

    def key_schedule(self, rounds):# {{{
        keys = np.empty((rounds, DES_ROUND_KEY_SIZE), dtype=np.uint8)
        permuted = block_permute(self.key, PC1)

        c, d = np.split(permuted, 2)
        for i in range(rounds):
            c = np.roll(c, c.size - shifts[i])
            d = np.roll(d, d.size - shifts[i])
            keys[i] = block_permute(np.concatenate((c, d)), PC2)

        return keys# }}}

    def block_substitute(self, block):# {{{
        bits = np.split(block, block.size // 6)
        bits = np.array(bits)

        row = bits[:, 0] * 2 + bits[:, 5]
        col = bits[:, 1] * 8 + bits[:, 2] * 4 + bits[:, 3] * 2 + bits[:, 4]

        val = DES_Sboxes[np.arange(DES_Sboxes.shape[0]), row, col] 

        sub = np.empty(DES_BLOCK_SIZE // 2, dtype=np.uint8)

        sub[0::4] = (val & 8) >> 3
        sub[1::4] = (val & 4) >> 2
        sub[2::4] = (val & 2) >> 1
        sub[3::4] = (val & 1)

        return sub# }}}

    def block_apply_function(self, block, r):# {{{
        block = block_permute(block, E)

        block = block ^ self.keys[r]

        block = self.block_substitute(block)

        return block_permute(block, P)# }}}

    def block_encrypt(self, block):# {{{
        block = block_permute(block, IP)

        left, right = np.split(block, 2)

        for i in range(self.rounds - 1):
            calculated = self.block_apply_function(right, i)

            right, left = left ^ calculated, right

        left = left ^ self.block_apply_function(right, self.rounds - 1)

        final = np.concatenate((left, right))

        return block_permute(final, IP_1)# }}}

    def encrypt(self, plaintext):# {{{
        plaintext_bits = to_bits(plaintext)

        if plaintext_bits.size % DES_BLOCK_SIZE != 0:
            raise ValueError('Input size should be divisible by %d' % (DES_BLOCK_SIZE,))

        nblocks = plaintext_bits.size // DES_BLOCK_SIZE

        ciphertext_blocks = np.empty((nblocks, DES_BLOCK_SIZE), dtype=np.uint8)

        for i, block in enumerate(np.split(plaintext_bits, nblocks)):
            ciphertext_blocks[i] = self.block_encrypt(block)

        return bytes(np.packbits(ciphertext_blocks.flatten()))# }}}

    def block_decrypt(self, block):# {{{
        block = block_permute(block, IP)

        left, right = np.split(block, 2)

        left = left ^ self.block_apply_function(right, self.rounds - 1)

        for i in range(self.rounds - 2, -1, -1):
            calculated = self.block_apply_function(left, i)

            right, left = left, right ^ calculated

        final = np.concatenate((left, right))

        return block_permute(final, IP_1, 1)# }}}

    def decrypt(self, ciphertext):# {{{
        ciphertext_bits = to_bits(ciphertext)

        if ciphertext_bits.size % DES_BLOCK_SIZE != 0:
            raise ValueError('Input size should be divisible by %d' % (DES_BLOCK_SIZE,))

        nblocks = ciphertext_bits.size // DES_BLOCK_SIZE

        plaintext_blocks = np.empty((nblocks, DES_BLOCK_SIZE), dtype=np.uint8)

        for i, block in enumerate(np.split(ciphertext_bits, nblocks)):
            plaintext_blocks[i] = self.block_decrypt(block)

        return bytes(np.packbits(plaintext_blocks.flatten()))# }}}
# }}}
