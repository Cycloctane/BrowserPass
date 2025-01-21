import hmac
import struct
from functools import partial
from hashlib import sha1
from io import BytesIO

from .crypto_support import ENCRYPT_METHODS, HASH_METHODS
from .utils import pbkdf2_ms, readstruct


def passwordSHA1(password: str) -> bytes:
    return sha1(password.encode("utf-16le")).digest()


def sidSHA1HMAC(hashed_password: bytes, sid: str) -> bytes:
    encoded_sid = (sid+"\x00").encode("utf-16le")
    return hmac.new(hashed_password, encoded_sid, sha1).digest()


class MasterKey():
    version: int
    salt: bytes
    rounds: int
    hash_method: int
    encrypt_method: int
    cipher: bytes

    def __init__(self, blob: bytes) -> None:
        with BytesIO(blob) as f:
            readstruct_ = partial(readstruct, io=f)
            self.version = readstruct_("<L")
            self.salt = readstruct_("16s")
            self.rounds = readstruct_("<L")
            self.hash_method = readstruct_("<L")
            self.encrypt_method = readstruct_("<L")
            self.cipher = readstruct_(f"{len(blob)-struct.calcsize('<L16s3L')}s")

    def decrypt(self, password_hash: bytes, sid: str) -> bytes:
        if self.encrypt_method not in ENCRYPT_METHODS or self.hash_method not in HASH_METHODS:
            raise Exception(f"Unsupported Algorithm \"{self.encrypt_method}\" \"{self.hash_method}\"")
        key_ = pbkdf2_ms(sidSHA1HMAC(password_hash, sid), self.salt, 48, self.rounds,
                         digest=HASH_METHODS[self.hash_method])
        key = key_[:32]
        iv = key_[32:]
        aes = ENCRYPT_METHODS[self.encrypt_method](key, iv=iv)
        return aes.decrypt(self.cipher)[-64:]

    def decrypt_with_passwd(self, password: str, sid: str) -> bytes:
        return self.decrypt(passwordSHA1(password), sid)


class MasterKeyFile():
    version: int
    guid: str
    masterkey_length: int
    backupkey_length: int
    credhist_length: int
    domainkey_length: int

    masterkey_blob: bytes
    backupkey_blob: bytes
    credhist_blob: bytes
    domainkey_blob: bytes

    def __init__(self, file_path: str) -> None:
        with open(file_path, "rb") as f:
            readstruct_ = partial(readstruct, io=f)
            self.version = readstruct_("<L")
            if self.version != 2:
                raise Exception("Unsupported Masterkey")
            self.guid = readstruct_("8x 72s").decode("utf-16le")
            self.masterkey_length = readstruct_("<12x Q")
            self.backupkey_length = readstruct_("<Q")
            self.credhist_length = readstruct_("<Q")
            self.domainkey_length = readstruct_("<Q")

            self.masterkey_blob = readstruct_(f"{self.masterkey_length}s")
            self.backupkey_blob = readstruct_(f"{self.backupkey_length}s")
            self.credhist_blob = readstruct_(f"{self.credhist_length}s")
            self.domainkey_blob = readstruct_(f"{self.domainkey_length}s")
