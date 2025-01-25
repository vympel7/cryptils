def chosen_prefix(encrypt_msg, alphabet, length = 32, blank_char = b'#', print_partial = False, known = b''):
    if not isinstance(alphabet, (bytes, bytearray)):
        alphabet = alphabet.encode()

    blank = blank_char * (length - 1) 
    blank_cts = {}
    for i in range(len(known), length):
        enc = encrypt_msg(blank.removesuffix(blank_char * i))
        blank_cts[i + 1] = enc[:length]

    if known != b'':
        blank = blank[:-len(known)]

    plaintext = blank + blank_char + known
    for i in range(len(known), len(plaintext)):
        for char in alphabet:
            enc = encrypt_msg(plaintext[1:] + char.to_bytes(1))
            if enc[:length] == blank_cts[i + 1]:
                plaintext = plaintext[1:] + char.to_bytes(1)
                break
        else:
            raise ValueError(f'No suitable characters found')

        if print_partial:
            print(f'Partial plaintext: {plaintext}')

    return plaintext
