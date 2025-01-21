import hashlib
import hmac
import struct
from functools import partial
from io import BufferedReader, BytesIO
from typing import Union


def pbkdf2_ms(passphrase: bytes, salt: bytes,
              keylen: int, iterations: int, digest: str='sha1') -> bytes:
    """Implementation of PBKDF2 that allows specifying digest algorithm.
    Returns the corresponding expanded key which is keylen long.

    Note: This is not real pbkdf2, but instead a slight modification of it.
    Seems like Microsoft tried to implement pbkdf2 but got the xoring wrong.

    https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py
    """
    buff = b""
    i = 1
    while len(buff) < keylen:
        U = salt + struct.pack("!L", i)
        i += 1
        derived = bytearray(hmac.new(passphrase, U,
                                     digestmod=partial(hashlib.new, name=digest)).digest())
        for r in range(iterations - 1):
            actual = bytearray(hmac.new(passphrase, derived,
                                        digestmod=partial(hashlib.new, name=digest)).digest())
            derived = bytearray([x ^ y for (x, y) in zip(derived, actual)])
        buff += derived
    return bytes(buff[:keylen])


def readstruct(pattern: str, io: Union[BytesIO, BufferedReader]):
    return struct.unpack(pattern, io.read(struct.calcsize(pattern)))[0]
