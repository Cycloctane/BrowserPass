import csv
import sqlite3
from abc import abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from os import path
from typing import ClassVar, Optional

from Crypto.Cipher import AES


@dataclass
class ChromiumEncryptedData():
    ciphertxt: bytes = field(repr=False)
    iv: bytes = field(repr=False)
    tag: bytes = field(repr=False)
    decrypted: bool = field(default=False, init=False)
    cleartxt: Optional[str] = field(default=None, init=False)

    def decrypt(self, key: bytes) -> None:
        if self.decrypted: return
        cipher = AES.new(key, AES.MODE_GCM, nonce=self.iv)
        try:
            self.cleartxt = cipher.decrypt_and_verify(self.ciphertxt, self.tag).decode()
        except (ValueError): return # decryption failed
        self.decrypted = True

    def dump_as_dict(self) -> dict:
        output = asdict(self)
        output.pop('ciphertxt')
        output.pop('iv')
        output.pop('tag')
        return output

    def dump_undecrypted(self) -> None:
        print("Ciphertext:", self.ciphertxt.hex())
        print("iv:", self.iv.hex())
        print("GCM tag:", self.tag.hex())

    @abstractmethod
    def dump(self) -> None: ...


@dataclass
class LoginData(ChromiumEncryptedData):
    origin_url: str
    username_value: Optional[str] = None

    def dump(self) -> None:
        print("Origin URL:", self.origin_url)
        print("Username:", self.username_value)
        print("Decrypted:", self.decrypted)
        if self.decrypted: print("Password:", self.cleartxt)
        else: self.dump_undecrypted()


@dataclass
class CookieData(ChromiumEncryptedData):
    host_key: str
    name: str
    path: str

    def dump(self) -> None:
        print("Host Key:", self.host_key)
        print("Path:", self.path)
        print("Cookie Name:", self.name)
        print("Decrypted:", self.decrypted)
        if self.decrypted: print("Cookie Value:", self.cleartxt)
        else: self.dump_undecrypted()


class ChromiumDB():
    data: list[ChromiumEncryptedData]
    data_tag: ClassVar[str] = "chromium_secrets"

    @abstractmethod
    def __init__(self, sqlite_path: str) -> None: ...

    def decrypt_all(self, key: bytes) -> None:
        for i in self.data:
            i.decrypt(key)

    def get_decrypted(self) -> list[ChromiumEncryptedData]:
        return [i for i in self.data if i.decrypted]

    def dump_all(self) -> None:
        print(f"\nDecrypted: {len([i for i in self.data if i.decrypted])}/{len(self.data)}\n")
        print("-"*32)
        for i in self.data:
            i.dump()
            print("-"*32)

    def write_csv(self, file_path: str) -> None:
        if len(self.data) == 0: return
        file_name = f"{self.data_tag}_{datetime.now().strftime('%b_%d_%H_%M_%S')}.csv"
        with open(path.join(file_path, file_name),
                  'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.data[0].dump_as_dict().keys())
            writer.writeheader()
            for i in self.data:
                writer.writerow(i.dump_as_dict())


class PasswdDB(ChromiumDB):
    data_tag = "chormium_passwords"

    def __init__(self, sqlite_path: str) -> None:
        conn = sqlite3.connect(sqlite_path)
        cur = conn.cursor()
        result = cur.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()
        conn.close()
        self.data = []
        for i in result:
            passwd_blob: bytes = i[2]
            if passwd_blob[:3] != b"v10": continue
            url: str = i[0]
            username_value: str = i[1]
            iv = passwd_blob[3:15]
            passwd_ciphertxt = passwd_blob[15:-16]
            passwd_tag = passwd_blob[-16:]
            self.data.append(LoginData(passwd_ciphertxt, iv, passwd_tag, url, username_value))


class CookieDB(ChromiumDB):
    data_tag = "chormium_cookies"

    def __init__(self, sqlite_path: str) -> None:
        conn = sqlite3.connect(sqlite_path)
        cur = conn.cursor()
        result = cur.execute("SELECT host_key, path, name, encrypted_value FROM cookies").fetchall()
        conn.close()
        self.data = []
        for i in result:
            cookie_blob: bytes = i[3]
            if cookie_blob[:3] != b"v10": continue
            host_key: str = i[0]
            path: str = i[1]
            name: str = i[2]
            iv = cookie_blob[3:15]
            ciphertxt = cookie_blob[15:-16]
            tag = cookie_blob[-16:]
            self.data.append(CookieData(ciphertxt, iv, tag, host_key, name, path))
