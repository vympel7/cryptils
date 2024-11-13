from cryptils.implementations import *
from cryptils.utils import *
from itertools import product

# Possible pre images of sbox value
def substitution_pre_images(image, sbox):# {{{
    indexes = np.where(sbox == image)

    rows = np.apply_along_axis(np.unpackbits, 0, indexes[0].astype(np.uint8))
    rows = np.concatenate((rows[6:8], rows[14:16], rows[22:24], rows[30:32]))

    cols = np.apply_along_axis(np.unpackbits, 0, indexes[1].astype(np.uint8))
    cols = np.concatenate((cols[4:8], cols[12:16], cols[20:24], cols[28:32]))

    pre_images = np.array([
        [rows[0], *cols[0:4], rows[1]],
        [rows[2], *cols[4:8], rows[3]],
        [rows[4], *cols[8:12], rows[5]],
        [rows[6], *cols[12:16], rows[7]]
    ])

    return pre_images# }}}

# Sbox output (before permutation)
def _from_LRs(top, bottom, last=False):# {{{
    L0, R0 = np.split(top, 2)
    L1, R1 = np.split(bottom, 2)

    function_output = L0 ^ L1 if last else R1 ^ L0

    return block_permute(function_output, P_1), R0# }}}

def single_round(plaintext, ciphertext, _last_round=True):# {{{
    plaintext_block = to_bits(plaintext)
    ciphertext_block = to_bits(ciphertext)

    if ciphertext_block.size != DES_BLOCK_SIZE or plaintext_block.size != DES_BLOCK_SIZE:
        raise ValueError('Ciphertext and plaintext should be exactly one DES block')

    permuted_plaintext = block_permute(plaintext_block, IP)
    permuted_ciphertext = block_permute(ciphertext_block, IP)

    anti_permuted_output, R0 = _from_LRs(permuted_plaintext, permuted_ciphertext, _last_round)

    round_key_parts = np.empty((8, 4, 6), dtype=np.uint8)

    for i in np.arange(0, anti_permuted_output.size, 4):
        bits = anti_permuted_output[i:i+4]

        pre_images = substitution_pre_images(bits[0] * 8 + bits[1] * 4 + bits[2] * 2 + bits[3], DES_Sboxes[i // 4])

        expanded = block_permute(R0, E)

        round_key_parts[i // 4] = pre_images ^ expanded[6 * i // 4:6 * (i + 4) // 4]

    pchoices = np.fromiter(product(*([[0, 1, 2, 3]] * 8), repeat=1), dtype=np.dtype((np.uint8, 8)), count=65536, like=np.empty((65536, 8)))

    round_keys = np.array([round_key_parts[np.arange(8), choices].flatten() for choices in pchoices])

    return round_keys# }}}

def two_rounds(plaintext, ciphertext):# {{{
    plaintext_block = to_bits(plaintext)
    ciphertext_block = to_bits(ciphertext)

    if ciphertext_block.size != DES_BLOCK_SIZE or plaintext_block.size != DES_BLOCK_SIZE:
        raise ValueError('Ciphertext and plaintext should be exactly one DES block')

    permuted_plaintext = block_permute(plaintext_block, IP)
    permuted_ciphertext = block_permute(ciphertext_block, IP)

    L0, R0 = np.split(permuted_plaintext, 2)
    L2, R2 = np.split(permuted_ciphertext, 2)

    L1, R1 = R0, R2

    middle = block_permute(np.concatenate((L1, R1)), IP_1)

    round1_keys = single_round(plaintext, bytes(np.packbits(middle)), _last_round=False)

    middle = block_permute(np.concatenate((L1, R1)), IP_1)

    round2_keys = single_round(bytes(np.packbits(middle)), ciphertext, _last_round=True)

    return round1_keys, round2_keys# }}}

