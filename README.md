# BrowserPass

Decrypt browser passwords and cookies offline with DPAPI masterkey file.

Currently supports Chromium and Windows credentials(IE passwords). Tested on Google Chrome, Opera and MS Edge.

Works with masterkey and Chromium user data from standalone win7 and win10 with local account. Note that Microsoft Accounts use random generated password for DPAPI. It is not possible to decrypt secrets from Microsoft Accounts only using logon password.

## Usage

Use `python -m BrowserPass` or run `python ./run.py`

### Chromium

Required files:

- user sid and password: `S-1-xxxxxxxx`
- user Master Key files (directory): `%AppData%\Microsoft\Protect\S-1-xxxxxxxx`. It may contains multiple key files. So the whole directory is needed.
- Chromium user data:
  - Local State: `%path_to_browser_appdata%\User Data\Local State`.
  - Cookies sqlite database (for cookies decryption): `%path_to_browser_appdata%\User Data\Default\Cookies`.
  - Login Data sqlite database (for passwords decryption): `%path_to_browser_appdata%\User Data\Default\Login Data`.

```bash
python -m BrowserPass chromium --sid $windows_sid -p $password\
  --masterkey_dir $path_to_masterkey_dir\
  --localstate_path $path_to_localstate_file\
  --cookie_path $path_to_cookie_file\
  --logindata_path $path_to_logindata_file
```

If password is not specific by `-p`, it will be asked interactively.

## Example

Decrypt all cookies and passwords from Chromium User Data:

```bash
python -m BrowserPass chromium\
  --sid S-1-xxxxxxxx\
  --masterkey_dir ./S-1-xxxxxxxx/\
  --localstate_path ./Local\ State\
  --cookie_path ./Cookies\
  --logindata_path ./Login\ Data
```

testing: decrypt raw DPAPI blob file. Output to stdout.

```bash
python -m BrowserPass dpapi --sid S-1-xxxxxxxx --masterkey_path ./S-1-xxxxxxxx\
  --blob blob.dat --offset 5
```

set `--offset=12` to decrypt Windows Credentials files from `%AppData%\Microsoft\Credentials`

```bash
python -m BrowserPass dpapi --sid S-1-xxxxxxxx --masterkey_path ./S-1-xxxxxxxx\
  --blob ./C1xxxxxxxx --offset 12
```
