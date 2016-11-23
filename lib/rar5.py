#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
import struct
import sys
import time
import zlib
import re

# The SFX has a current limit of 1MB
MAX_SIGNATURE_SCAN = (1000 ** 2)

# Archive Versions
RAR_FORMATS = {
    0: '1.5',
    1: '5.0',
}

class BadRarFile(RuntimeError):
    pass


def read_byte(stream):
    return struct.unpack_from('<B', stream)


def read_long(stream):
    return struct.unpack_from('<L', stream)


def read_vint(stream):
    total = 0
    continue_mask = 0x80

    # vints have a max of 10 bytes
    for index in range(0, 10):
        byte = read_byte(stream)
        total += (byte << (index * 7))
        if not byte & continue_mask:
            break

    return total


class RarInfo(object):
    pass


class RarFile(object):
    def __init__(self, path_or_stream):
        if isinstance(path_or_stream, str):
            self.fp = open(path_or_stream, 'rb')
        elif isinstance(path_or_stream, file):
            self.fp = path_or_stream
        else:
            raise TypeError('File or path to file requried')
        self.fp.seek(0)
        self.archive_version = 0
        self.header_start = 0

        self.archive_size = 0
        self.archive_files = []
        self.archive_passworded = False

        self.scan_for_rar_signature()

    def __del__(self):
        if self.fp:
            self.fp.close()

    def read_at_offset(self, offest, count):
        self.fp.seek(offest)
        return self.fp.read(count)

    def scan_for_rar_signature(self):
        base_signature = b'\x52\x61\x72\x21\x1a\x07'
        buf = self.fp.read(MAX_SIGNATURE_SCAN)
        results = re.search(base_signature, buf)
        if results:
            if self.read_at_offset(results.end(), 1) == b'\x01':
                self.archive_version = 1
                self.header_start = results.start() + 8
            else:
                self.archive_version = 0
                self.header_start = results.start() + 7
        else:
            raise BadRarFile('Signature was not detected in file')

        return self.header_start

    def read_headers(self):
        pass
