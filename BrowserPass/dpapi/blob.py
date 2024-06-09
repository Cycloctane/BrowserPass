from functools import partial
from io import BytesIO
from uuid import UUID
import hashlib
from hashlib import sha1
from Crypto.Util.Padding import unpad
import hmac

from .utils import readstruct
from .crypto_support import ENCRYPT_METHODS, HASH_METHODS

BLOCK_SIZE = 16

class DPAPIBlob():
    masterkey_guid: str
    descryption: str
    encrypt_method: int
    encrypt_blocksize: int
    salt: bytes
    hash_method: int
    hash_blocksize: int
    cipher: bytes

    def __init__(self, blob_bytes: bytes) -> None:
        with BytesIO(blob_bytes) as f:
            readstruct_ = partial(readstruct, io=f)
            self.masterkey_guid = str(UUID(bytes_le=readstruct_("<24x16s")))
            descryption_length: int = readstruct_("<4xL")
            self.descryption = readstruct_(f"{descryption_length}s").decode('utf-16le')
            self.encrypt_method = readstruct_("<L")
            self.encrypt_blocksize = readstruct_("<L")
            salt_length: int = readstruct_("<L")
            self.salt = readstruct_(f"{salt_length}s")
            self.hash_method = readstruct_(f"<{readstruct_('<L')}xL")
            self.hash_blocksize = readstruct_("<L")
            cipher_length: int = readstruct_(f"<{readstruct_('<L')}xL")
            self.cipher = readstruct_(f"{cipher_length}s")

    def decrypt(self, master_key: bytes) -> bytes:
        if self.encrypt_method not in ENCRYPT_METHODS or self.hash_method not in HASH_METHODS:
            raise Exception(f"Unsupported Algorithm \"{hex(self.encrypt_method)}\" \"{hex(self.hash_method)}\"")
        master_key_ = sha1(master_key).digest()
        session_key = hmac.new(master_key_, self.salt,
                               digestmod=partial(hashlib.new,
                                                 name=HASH_METHODS[self.hash_method])).digest()[:32]
        aes = ENCRYPT_METHODS[self.encrypt_method](session_key, iv=b"\x00"*16)
        return unpad(aes.decrypt(self.cipher), block_size=BLOCK_SIZE)
