from cryptils.implementations import *
from cryptils.utils import *

def substitution_pre_images(image, sbox):
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

    return pre_images

def invert_permuted_choice2(key_parts):
    inverted_choices = np.zeros((4, 56), dtype=np.uint8)
    inverted_choices.fill(2)

    for i in range(56):
        if PC2_1[i] != 0:
            x = (PC2_1[i] - 1) // 8
            y = (PC2_1[i] - 1) % 6
            inverted_choices[:, PC2_1[i] - 1] = key_parts[x][:, y]

    return inverted_choices

def invert_permuted_choice1(CDs):
    inverted_choices = np.zeros((4, 64), dtype=np.uint8)
    inverted_choices.fill(2)

    for i in range(64):
        if PC1_1[i] != 0:
            x = PC1_1[i] - 1
            inverted_choices[:, PC1_1[i] - 1] = CDs[:, x]

    return inverted_choices


def one_round(plaintext, ciphertext):
    plaintext_block = to_bits(plaintext)
    ciphertext_block = to_bits(ciphertext)

    if ciphertext_block.size != DES_BLOCK_SIZE or plaintext_block.size != DES_BLOCK_SIZE:
        raise ValueError('Ciphertext and plaintext should be exactly one DES block')

    permuted_plaintext = block_permute(plaintext_block, IP)
    permuted_ciphertext = block_permute(ciphertext_block, IP)

    L0, R0 = permuted_plaintext[:DES_BLOCK_SIZE // 2], permuted_plaintext[DES_BLOCK_SIZE // 2:]
    L1, R1 = permuted_ciphertext[:DES_BLOCK_SIZE // 2], permuted_ciphertext[DES_BLOCK_SIZE // 2:]

    function_output = L0 ^ L1

    anti_permuted_output = block_permute(function_output, P_1)

    round_key_parts = np.zeros((8, 4, 6), dtype=np.uint8)

    for i in np.arange(0, anti_permuted_output.size, 4):
        bits = anti_permuted_output[i:i+4]
        pre_images = substitution_pre_images(bits[0] * 8 + bits[1] * 4 + bits[2] * 2 + bits[3], DES_Sboxes[i // 4])

        expanded = block_permute(R0, E)

        round_key_parts[i // 4] = pre_images ^ expanded[6 * i // 4:6 * (i + 1) // 4]

    inverted_choices = invert_permuted_choice2(round_key_parts)

    C1s, D1s = inverted_choices[:, :28], inverted_choices[:, 28:]

    C0s = np.apply_along_axis(lambda arr: np.roll(arr, shifts[0]), 1, C1s)
    D0s = np.apply_along_axis(lambda arr: np.roll(arr, shifts[0]), 1, D1s)

    CDs = np.concatenate((C0s, D0s), 1)

    keys = invert_permuted_choice1(CDs)
    assert list(keys[0]).count(2) == 17 # (one too many?)
    # CHECK INVERSE PERMUTED CHOICES

    print(keys)

