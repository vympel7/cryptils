from cryptils.cryptils.AES.cbc import *
from pwn import *


def test_recover_IV():
    def enc(msg):
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b': ', msg.hex().encode())
        io.recvuntil(b': ')
        return bytes.fromhex(io.recvline().strip().decode())
    
    def dec(msg):
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b': ', msg.hex().encode())
        io.recvuntil(b': ')
        return bytes.fromhex(io.recvline().strip().decode())

    io = remote('privateiv.challs.olicyber.it', 10021)
    print(recover_IV(enc, dec))

if __name__ == '__main__':
    test_recover_IV()
