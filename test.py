from cryptils.AES.CBC import *
from pwn import *

io = None

def enc(msg):
    global io
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', msg.hex().encode())
    io.recvuntil(b': ')
    return bytes.fromhex(io.recvline().strip().decode())

def dec(msg):
    global io
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', msg.hex().encode())
    io.recvuntil(b': ')
    return bytes.fromhex(io.recvline().strip().decode())


if __name__ == '__main__':
    io = remote('privateiv.challs.olicyber.it', 10021)
    key = recover_IV(enc, dec)
    print(key.decode())
