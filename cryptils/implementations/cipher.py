from .constants import *
from cryptils.utils import *

class DES:# {{{
    def __init__(self, key, rounds=DES_ROUNDS):# {{{
        self.key = to_bits(key)
        self.rounds = rounds

        if self.key.size != DES_KEY_SIZE:
            raise ValueError(f'Key should be {DES_KEY_SIZE} bits.')

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

class AES:# {{{
    def __init__(self, key, rounds=None):# {{{
        self.key = to_bits(key)

        self.xtimes = lambda a: (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1) 

        if self.key.size not in AES_KEY_SIZES:
            raise ValueError(f'Key should be {AES_KEY_SIZES} bits.')

        self.rounds = AES_ROUNDS[AES_KEY_SIZES.index(self.key.size)] if rounds is None else rounds

        self.keys = self.key_expansion(self.rounds)# }}}

    def key_expansion(self, rounds):# {{{
        Nk = self.key.size // 32
        Nr = self.rounds

        words = np.empty((Nr + 1, Nk, 4), dtype=np.uint8)
        words[0] = np.array(np.split(np.packbits(self.key), Nk), dtype=np.uint8)

        for i in np.arange(Nk, 4 * (Nr + 1)):
            tmp = words[(i - 1) // Nk][(i - 1) % Nk]

            if i % Nk == 0:
                rotated = np.roll(tmp, 3)
                tmp = np.array([AES_Sbox[byte] for byte in rotated], dtype=np.uint8) ^ AES_Rcon[(i // Nk) - 1]

            elif Nk > 6 and i % Nk == 4:
                tmp = np.array([AES_Sbox[byte] for byte in tmp], dtype=np.uint8)

            words[i // Nk][i % Nk] = words[(i - Nk) // 4][(i - Nk) % 4] ^ tmp

        return words# }}}

    def add_round_key(self, block, r):# {{{
        return self.keys[r].T ^ block# }}}

    def sub_bytes(self, block):# {{{
        return np.array([AES_Sbox[b] for b in block.flatten()], dtype=np.uint8).reshape((4, 4))# }}}

    def shift_rows(self, block):# {{{
        return np.array([np.roll(block[i], (0, 3, 2, 1)[i]) for i in np.arange(4)], dtype=np.uint8)# }}}

    def mix_columns(self, block):# {{{
        return np.stack([
            np.array([
                self.xtimes(col[0]) ^ (self.xtimes(col[1]) ^ col[1]) ^ col[2] ^ col[3],
                col[0] ^ self.xtimes(col[1]) ^ (self.xtimes(col[2]) ^ col[2]) ^ col[3],
                col[0] ^ col[1] ^ self.xtimes(col[2]) ^ (self.xtimes(col[3]) ^ col[3]),
                (self.xtimes(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ self.xtimes(col[3]),
                ], dtype=np.uint8)
            for col in block.T], 1)# }}}

    def block_encrypt(self, block):# {{{
        state = np.packbits(block).reshape((4, 4)).astype(np.uint8).T

        state = self.add_round_key(state, 0)

        for r in np.arange(1, self.rounds):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, r)

        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.rounds)

        return state.T# }}}

    def encrypt(self, plaintext):# {{{
        plaintext_bits = to_bits(plaintext)

        if plaintext_bits.size % AES_BLOCK_SIZE != 0:
            raise ValueError('Input size should be divisible by %d' % (DES_BLOCK_SIZE,))

        nblocks = plaintext_bits.size // AES_BLOCK_SIZE

        ciphertext_blocks = np.empty((nblocks, AES_BLOCK_SIZE), dtype=np.uint8)

        for i, block in enumerate(np.split(plaintext_bits, nblocks)):
            ciphertext_blocks[i] = np.unpackbits(self.block_encrypt(block).flatten())

        return bytes(np.packbits(ciphertext_blocks.flatten()))# }}}
# }}}
