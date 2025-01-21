import argparse
import getpass
from operator import methodcaller
from sys import stdout

from . import chromium
from .dpapi import decrypt_dpapi


def args_reader() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="BrowserPass",
                                     description="Decrypt browsers passwords and cookies offline.")

    subparser = parser.add_subparsers(dest='command')

    dpapi_parser = subparser.add_parser('dpapi',
                                        description="Read  DPAPI blob from file and decrypt. Output to stdout.")
    dpapi_parser.add_argument('--sid', '-s', metavar='S-1-...', required=True,
                              help="user sid")
    dpapi_parser.add_argument('--password', '-p', metavar='password', required=False,
                              help="user password")
    dpapi_parser.add_argument('--masterkey_dir', '-m', required=True,
                              help="path to directory that contains DPAPI masterkey file")
    dpapi_parser.add_argument('--blob', '-b', required=True, dest='blob_path',
                              help="path to blob file")
    dpapi_parser.add_argument('--offset', required=False, dest='offset', default=0, type=int,
                              help="read offset")

    chromium_parser = subparser.add_parser('chromium',
                                           description="Decrypt Choromium browser secrets.")
    chromium_parser.add_argument('--sid', '-s', metavar='S-1-...', required=True,
                                 help="user sid")
    chromium_parser.add_argument('--password', '-p', metavar='password', required=False,
                                 help="user password")
    chromium_parser.add_argument('--masterkey_dir', '-m', required=True,
                                 help="path to directory that contains DPAPI masterkey file")
    chromium_parser.add_argument('--localstate_path', required=True,
                                 help="path to Chromium Local State file")
    chromium_parser.add_argument('--cookie_path', required=False,
                                 help="path to Chromium Cookie file")
    chromium_parser.add_argument('--logindata_path', required=False,
                                 help="path to Chromium Login Data file")
    chromium_parser.add_argument('--csv', required=False,
                                 help="csv file output dir path")
    args = parser.parse_args()
    return args


def args_handler(args: argparse.Namespace) -> None:
    if args.command == 'chromium':
        if args.cookie_path is None and args.logindata_path is None:
            print("Please specific path to Chromium Cookie or Login Data")
            return
        passwd = getpass.getpass("password: ") if args.password is None else args.password
        method = methodcaller('dump_all') if args.csv is None else methodcaller('write_csv', args.csv)
        if args.cookie_path is not None:
            method(chromium.decrypt_cookie(args.localstate_path, args.cookie_path,
                                           args.masterkey_dir, passwd, args.sid))
        if args.logindata_path is not None:
            method(chromium.decrypt_passwd(args.localstate_path, args.logindata_path,
                                           args.masterkey_dir, passwd, args.sid))
    elif args.command == 'dpapi':
        with open(args.blob_path, 'rb') as f:
            data = f.read()
        passwd = getpass.getpass("password: ") if args.password is None else args.password
        stdout.buffer.write(
            decrypt_dpapi(data, args.masterkey_dir, passwd, args.sid, blob_offset=args.offset))
