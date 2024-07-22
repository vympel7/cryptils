from pwn import remote, process
import os

class Interact(object):# {{{
    def __init__(self, target: str, port: int = None) -> None:
        self.target = target
        self.port = port
        self.io = None

    def connected(self) -> bool:
        return self.io is not None and self.io.connected()

    def connect(self) -> bool:
        if self.connected():
            self.close()

        if os.path.isfile(self.target):
            self.io = process(self.target)
        elif self.port is not None:
            self.io = remote(self.target, self.port)

        return self.connected()

    def close(self) -> None:
        if self.connected():
            self.io.close()

        self.io = None

    def sl(self, data: str | bytes) -> None:
        if not self.connected():
            raise EOFError('Not connected to any tube')

        if isinstance(data, str):
            data = data.encode()

        self.io.sendline(data)

    def sla(self, after: str | bytes, data: str | bytes) -> None:
        if not self.connected():
            raise EOFError('Not connected to any tube')

        if isinstance(after, str):
            after = after.encode()

        if isinstance(data, str):
            data = data.encode()

        self.io.sendlineafter(after, data)

    def rl(self, strip: bool = True) -> bytes:
        if not self.connected():
            raise EOFError('Not connected to any tube')

        received = self.io.recvline()
        return received.strip() if strip else received


    def ru(self, until: str | bytes, strip: bool = True) -> bytes:
        if not self.connected():
            raise EOFError('Not connected to any tube')

        if isinstance(until, str):
            until = until.encode()

        received = self.io.recvuntil(until)
        return received.strip() if strip else received
# }}}
