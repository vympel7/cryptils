def _shift_char_over_alphabet(char, alphabet, times):
    return char if char not in alphabet else alphabet[(alphabet.index(char) + times) % len(alphabet)]

def _shift_str_over_alphabet(msg, alphabet, times):
    joiner = '' if isinstance(msg, str) else b''
    return joiner.join(_shift_char_over_alphabet(msg[i], alphabet, times) for i in range(len(msg)))


# alphabets is either a string (or bytestring) or a 2D array of "sub alphabets"
def bruteforce(encoded, alphabets):
    if not isinstance(alphabets, (list, tuple, set)):
        alphabets = (alphabets,)

    decs = {}
    ll = max(map(len, alphabets))
    for t in range(ll):
        decs[t] = '' if isinstance(encoded[0], str) else b''

    for j in range(len(encoded)):
        if not any([encoded[j] in alphabet for alphabet in alphabets]):
            for t in range(ll):
                decs[t] += encoded[j]

        for alphabet in alphabets:
            if encoded[j] in alphabet:
                for t in range(ll):
                    decs[t] += _shift_char_over_alphabet(encoded[j], alphabet, t)

    return decs
