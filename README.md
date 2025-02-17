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

set `--csv=$dirpath` to write results to csv files and save to specified directory.

```bash
python -m BrowserPass chromium --sid $windows_sid -p $password\
  --masterkey_dir $path_to_masterkey_dir\
  --localstate_path $path_to_localstate_file\
  --cookie_path $path_to_cookie_file\
  --logindata_path $path_to_logindata_file
  --csv $dirpath
```

## Examples

Decrypt all cookies and passwords from Chromium User Data:

```bash
python -m BrowserPass chromium\
  --sid S-1-xxxxxxxx\
  --masterkey_dir ./S-1-xxxxxxxx/\
  --localstate_path ./Local\ State\
  --cookie_path ./Cookies\
  --logindata_path ./Login\ Data
```

Save the csv files to current working directory.

```bash
python -m BrowserPass chromium\
  --sid S-1-xxxxxxxx\
  --masterkey_dir ./S-1-xxxxxxxx/\
  --localstate_path ./Local\ State\
  --cookie_path ./Cookies\
  --logindata_path ./Login\ Data
  --csv .
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

## LICENSE

This project is licensed under the GNU General Public License v3.0. 

```
BrowserPass - Browser Password Decryptor
Copyright (C) 2024 Cycloctane

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
