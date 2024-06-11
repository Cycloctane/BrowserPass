from os import path

from .blob import DPAPIBlob
from .masterkey import MasterKeyFile, MasterKey


def decrypt_dpapi(blob_bytes: bytes, masterkey_dir: str,
                  user_password: str, user_sid: str, blob_offset: int=0) -> bytes:
    assert blob_offset>=0
    blob = DPAPIBlob(blob_bytes[blob_offset:])
    mk_guid = blob.masterkey_guid
    if not path.exists(path.join(masterkey_dir, mk_guid)):
        raise FileNotFoundError(f"Cannot find masterkey file for {mk_guid}.")
    masterkey_file = MasterKeyFile(path.join(masterkey_dir, mk_guid))
    masterkey = MasterKey(masterkey_file.masterkey_blob)
    decrypted_masterkey = masterkey.decrypt_with_passwd(user_password, user_sid)
    return blob.decrypt(decrypted_masterkey)
