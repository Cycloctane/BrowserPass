import struct
from io import BufferedReader, BytesIO
from typing import Union

from .pbkdf2 import pbkdf2_ms

def readstruct(pattern: str, io: Union[BytesIO, BufferedReader]):
    return struct.unpack(pattern, io.read(struct.calcsize(pattern)))[0]
