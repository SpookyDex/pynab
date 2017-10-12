#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
import struct
import sys
import time
import zlib
import re
import io

# The SFX has a current limit of 1MB
MAX_SIGNATURE_SCAN = (1000 ** 2)

# Archive Versions
RAR_FORMATS = {
    0: '4.0',
    1: '5.0',
}

# Header Types
HEADER_TYPES = {
    0: {
        114: 'mark',
        115: 'main',
        116: 'file',
        117: 'old-comment',
        118: 'old-auth-info',
        119: 'old-sub-block',
        120: 'old-recovery-record',
        121: 'old-sign',
        122: 'service',
        123: 'end'
    },
    1: {
        0: 'mark',
        1: 'main',
        2: 'file',
        3: 'service',
        4: 'encryption',
        5: 'end'
    },
}

# Header Flag Masks
HEADER_FLAG_MASKS = {
    'extra_area': 0x0001,
    'data_area': 0x0002,
    'skip_unknown': 0x0004,
    'data_continues_prev': 0x0008,
    'data_continues_next': 0x0010,
    'depends_on_prev': 0x0020,
    'preserve_child': 0x0040,
}


class BadRarFile(RuntimeError):
    pass


class CorruptedRarFile(RuntimeError):
    pass


def read_bytes(stream, count):
    return ''.join(range(0, count).map(lambda _: struct.unpack_from('<c', stream)))


def read_u8(stream):
    return struct.unpack_from('<B', stream)


def read_u32(stream):
    return struct.unpack_from('<L', stream)


def read_u64(stream):
    return struct.unpack_from('<Q', stream)


def read_vint(stream):
    total = 0
    continue_mask = 0x80

    # vints have a max of 10 bytes
    for index in range(0, 10):
        byte = read_u8(stream)
        continue_on = ((byte & continue_mask) > 0)
        if index == 9:
            byte &= 0x01
        else:
            byte &= ~continue_mask
        total += (byte << (index * 7))
        if not continue_on:
            break

    return total


class RarInfo(object):
    def __init__(self):
        pass


class RarBlock(object):
    def __init__(self, data_buffer, rar_version):
        self.data_buffer = io.BytesIO(data_buffer)
        self.process_data()
        self.rar_version = rar_version

    def process_data(self):
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

        self.find_file_size()
        self.scan_for_rar_signature()

    def __del__(self):
        if self.fp:
            self.fp.close()

    def find_file_size(self):
        self.fp.seek(0, 2)
        self.file_bytes = self.fp.tell()

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

    def blocks(self):
        while self.fp.tell() < self.file_bytes:
            block_start = self.fp.tell()
            crc32 = read_u32(self.fp)
            header_size = read_vint(self.fp)
            header_type = read_vint(self.fp)
            header_flags = self.parse_flags(read_vint(self.fp))

            if 'data_area' in header_flags:
                data_area_size = read_vint(self.fp)

            if 'extra_area' in header_flags:
                extra_area_size = read_vint(self.fp)

            seek_bytes = block_start


    def parse_flags(flags):
        present_flags = []
        for name, mask in HEADER_FLAG_MASKS.items():
            if flags & mask:
                present_flags.append(name)
        return present_flags
