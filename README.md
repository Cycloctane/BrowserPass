## BrowserPass

Decrypt browser passwords and cookies offline with DPAPI masterkey file.

Currently only supports Chromium. Tested on Google Chrome, Opera and MS Edge(Chromium).

Works with masterkey and Chromium user data from standalone win7 and win10 with local account. Note that Microsoft Accounts use random generated password for DPAPI. It is not possible to use logon password to decrypt secrets from Microsoft Accounts.

### Usage

Use `python -m BrowserPass` or run `python ./run.py`

Files needed for decrypt Chromium secrets:

- user sid and password: `S-1-xxxxxxxx`
- user Master Key files (directory): `%AppData%\Microsoft\Protect\S-1-xxxxxxxx`. It may contains multiple key files. So the whole directory is needed to find the right key.
- chromium user data:
  - Local State: `%path_to_browser_appdata%\User Data\Local State`.
  - Cookies sqlite database (for cookies decryption): `%path_to_browser_appdata%\User Data\Default\Cookies`.
  - Login Data sqlite3 database (for passwords decryption): `%path_to_browser_appdata%\User Data\Default\Login Data`.

```bash
python -m BrowserPass chromium --sid $windows_sid --masterkey_dir $path_to_masterkey_dir --localstate_path $path_to_localstate_file --cookie_path $path_to_cookie_file --logindata_path $path_to_logindata_file -p $password
```

If password is not specific by `-p`, it will be asked interactively.

### Example

Decrypt all cookies and passwords:

```bash
python -m BrowserPass chromium --sid S-1-xxxxxxxx --masterkey_dir ./S-1-xxxxxxxx/ --localstate_path ./Local\ State --cookie_path ./Cookies --logindata_path ./Login\ Data
```

testing: decrypt raw DPAPI blob from file.

```bash
python -m BrowserPass dpapi --sid S-1-xxxxxxxx --masterkey_path ./S-1-xxxxxxxx --blob blob.dat
```
