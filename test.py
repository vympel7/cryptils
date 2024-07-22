from cryptils.AES.CBC import CBC

def enc(io, msg):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', msg.hex().encode()); io.recvuntil(b': ')
    return bytes.fromhex(io.recvline().strip().decode())

def dec(io, msg):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', msg.hex().encode()); io.recvuntil(b': ')
    return bytes.fromhex(io.recvline().strip().decode())

cbc = CBC('privateiv.challs.olicyber.it', 10021)
key = cbc.key_equals_iv(enc, dec)
print(key.decode())
