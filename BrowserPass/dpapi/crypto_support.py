from functools import partial
from Crypto.Cipher import AES, DES3


ENCRYPT_METHODS: dict[int, partial] = {
    0x6610: partial(AES.new, mode=AES.MODE_CBC),
    0x6603: partial(DES3.new, mode=DES3.MODE_CBC)
}


HASH_METHODS: dict[int, str] = {
    0x800e: "sha512",
    0x8004: "sha1"
}
