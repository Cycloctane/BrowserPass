
# Modified (for JtR) by Dhiru Kholia in December, 2014.
# Modified (for JtR) by Jean-Christophe Delaunay
# <jean-christophe.delaunay at synacktiv.com> in 2017
# to support further options and JtR new hash format
#
# This file is part of DPAPIck
# Windows DPAPI decryption & forensic toolkit
#
# Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.
# This document is the property of Cassidian SAS, it may not be copied or
# circulated without prior licence
#
# Author: Jean-Michel Picod <jmichel.p@gmail.com>
#
# This program is distributed under GPLv3 licence (see LICENCE.txt)

import hashlib
import hmac
import struct


def pbkdf2_ms(passphrase, salt, keylen, iterations, digest='sha1'):
    """Implementation of PBKDF2 that allows specifying digest algorithm.

    Returns the corresponding expanded key which is keylen long.

    Note: This is not real pbkdf2, but instead a slight modification of it.
    Seems like Microsoft tried to implement pbkdf2 but got the xoring wrong.
    """
    buff = b""
    i = 1
    while len(buff) < keylen:
        U = salt + struct.pack("!L", i)
        i += 1
        derived = bytearray(hmac.new(passphrase, U, digestmod=lambda: hashlib.new(digest)).digest())
        for r in range(iterations - 1):
            actual = bytearray(hmac.new(passphrase, derived, digestmod=lambda: hashlib.new(digest)).digest())
            derived = bytearray([x ^ y for (x, y) in zip(derived, actual)])
        buff += derived
    return bytes(buff[:keylen])
