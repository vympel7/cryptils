from cryptils.implementations import *
from cryptils.utils import *
from itertools import product
from functools import reduce

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

def invert_permuted_choice2(key_parts, choices):# {{{
    key_parts = np.array([key_part[c] for key_part, c in zip(key_parts, choices)]).flatten()

    inverted_choices = np.zeros((56,), dtype=np.uint8)
    inverted_choices.fill(2)

    for i in range(56):
        if PC2_1[i] != 0:
            inverted_choices[i] = key_parts[PC2_1[i] - 1]

    return inverted_choices# }}}

def invert_permuted_choice1(CD):# {{{
    inverted_choices = np.zeros((64,), dtype=np.uint8)
    inverted_choices.fill(2)

    for i in range(63):
        if PC1_1[i] != 0:
            inverted_choices[i] = CD[PC1_1[i] - 1]

    return inverted_choices# }}}

def one_round(plaintext, ciphertext):# {{{
    plaintext_block = to_bits(plaintext)
    ciphertext_block = to_bits(ciphertext)

    if ciphertext_block.size != DES_BLOCK_SIZE or plaintext_block.size != DES_BLOCK_SIZE:
        raise ValueError('Ciphertext and plaintext should be exactly one DES block')

    permuted_plaintext = block_permute(plaintext_block, IP)
    permuted_ciphertext = block_permute(ciphertext_block, IP)

    L0, R0 = np.split(permuted_plaintext, 2)
    L1, R1 = np.split(permuted_ciphertext, 2)

    function_output = L0 ^ L1

    anti_permuted_output = block_permute(function_output, P_1)

    round_key_parts = np.empty((8, 4, 6), dtype=np.uint8)

    for i in np.arange(0, anti_permuted_output.size, 4):
        bits = anti_permuted_output[i:i+4]
        pre_images = substitution_pre_images(bits[0] * 8 + bits[1] * 4 + bits[2] * 2 + bits[3], DES_Sboxes[i // 4])

        expanded = block_permute(R0, E)

        round_key_parts[i // 4] = pre_images ^ expanded[6 * i // 4:6 * (i + 4) // 4]

    pchoices = np.fromiter(product(*([[0, 1, 2, 3]] * 8), repeat=1), dtype=np.dtype((np.uint8, 8)), count=4**8, like=np.empty((4**8, 8)))

    round_keys = np.array([round_key_parts[np.arange(8), choices].flatten() for choices in pchoices])

    return round_keys# }}}

    ''' Finding the actual 64 (56) bits key
    max_choices = 256**1

    for choices in pchoices:
        inverted_choices = invert_permuted_choice2(round_key_parts, choices=choices)

        C1, D1 = inverted_choices[:28], inverted_choices[28:]

        C0 = np.roll(C1, shifts[0])
        D0 = np.roll(D1, shifts[0])

        CD = np.concatenate((C0, D0))

        key_bits = invert_permuted_choice1(CD)

        bits_bruteforce = product(*([[0, 1]] * 8), repeat=1)

        bits_bruteforce = np.fromiter(bits_bruteforce, dtype=np.dtype((np.uint8, 8)), count=256, like=np.empty((256, 8)))

        keys = np.tile(key_bits, 256).reshape((256, 64))

        twos = np.argwhere(keys == 2)[:, 1].reshape((256, 16))
        twos = twos[(twos + 1) % 8 != 0].reshape((256, 8))

        np.put_along_axis(keys, twos, bits_bruteforce, 1)

        for i in np.arange(256):
            for j in np.arange(0, 64, 8):
                keys[i][j+7] = reduce(lambda x, y: x ^ y, keys[i][j:j+7]) ^ 1

        keys = np.apply_along_axis(np.packbits, 1, keys)

        max_choices -= 1
        if max_choices == 0:
            break
    '''

