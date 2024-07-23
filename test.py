from cryptils.AES.CBC import CBC
from cryptils.interact import Interact

io = None

def enc(msg):
    global io
    io.sla(b'> ', b'1')
    io.sla(b': ', msg.hex().encode()); io.ru(b': ')
    return bytes.fromhex(io.rl().strip().decode())

def dec(msg):
    global io
    io.sla(b'> ', b'2')
    io.sla(b': ', msg.hex().encode()); io.ru(b': ')
    return bytes.fromhex(io.rl().strip().decode())


if __name__ == '__main__':
    io = Interact('privateiv.challs.olicyber.it', 10021)
    io.connect()
    cbc = CBC()
    key = cbc.key_equals_iv(enc, dec)
    print(key.decode())
