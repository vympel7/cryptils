from cryptils.cryptils.AES.ecb import *
from pwn import *
import string


def test_chosen_prefix():
    def enc(msg):
        io.sendlineafter(b'encrypt:', msg)
        return bytes.fromhex(io.recvline().rstrip().decode()[39:])

    io = remote('padding.challs.cyberchallenge.it', 9030)
    assert chosen_prefix(enc, string.printable, print_partial = True, known = b'CCIT{r3m3mb3r_th3_') == chosen_prefix(enc, string.printable, print_partial = True)

if __name__ == '__main__':
    test_chosen_prefix()
