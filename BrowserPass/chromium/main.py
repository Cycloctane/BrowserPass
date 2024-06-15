from base64 import b64decode
import json

from .models import PasswdDB, CookieDB
from ..dpapi import decrypt_dpapi


def parse_LocalState(file_path: str) -> bytes:
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.loads(f.read())
    return b64decode(data['os_crypt']['encrypted_key'])


def decrypt_passwd(LocalState_path: str, LoginData_path: str, masterkey_dir: str,
                   user_password: str, user_sid: str):
    decrypted_key = decrypt_dpapi(parse_LocalState(LocalState_path), masterkey_dir,
                                  user_password, user_sid, blob_offset=5)
    passwd_db = PasswdDB(LoginData_path)
    passwd_db.decrypt_all(decrypted_key)
    return passwd_db


def decrypt_cookie(LocalState_path: str, Cookie_path: str, masterkey_dir: str,
                   user_password: str, user_sid: str):
    decrypted_key = decrypt_dpapi(parse_LocalState(LocalState_path), masterkey_dir,
                                  user_password, user_sid, blob_offset=5)
    cookie_db = CookieDB(Cookie_path)
    cookie_db.decrypt_all(decrypted_key)
    return cookie_db
