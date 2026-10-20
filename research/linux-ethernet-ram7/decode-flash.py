#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode one complete C80FLASH UART backup; reject loss or corruption."""
import argparse
import base64
import binascii
import hashlib
import os
from pathlib import Path
import re
import sys
import zlib

FLASH_SIZE = 0x400000
BEGIN = 'C80FLASH BEGIN 00400000'
DATA = re.compile(r'F ([0-9a-f]{8}) ([A-Za-z0-9+/=]{4,64}) ([0-9a-f]{8})')
END = re.compile(r'C80FLASH END 00400000 ([0-9a-f]{8})')


def decode(lines):
    result = bytearray()
    started = finished = False
    for number, raw in enumerate(lines, 1):
        line = raw.rstrip('\r\n')
        if line == BEGIN:
            if started:
                raise ValueError(f'line {number}: multiple backups in log')
            started = True
            continue
        if not started or finished:
            continue
        if not line:
            continue
        trailer = END.fullmatch(line)
        if trailer:
            if len(result) != FLASH_SIZE:
                raise ValueError(f'line {number}: incomplete flash ({len(result)} bytes)')
            if zlib.crc32(result) != int(trailer[1], 16):
                raise ValueError(f'line {number}: full-flash CRC mismatch')
            finished = True
            continue
        match = DATA.fullmatch(line)
        if not match:
            raise ValueError(f'line {number}: unexpected or damaged backup line')
        offset, encoded, expected_crc = match.groups()
        if int(offset, 16) != len(result):
            raise ValueError(f'line {number}: missing, repeated, or reordered data')
        try:
            block = base64.b64decode(encoded, validate=True)
        except binascii.Error as error:
            raise ValueError(f'line {number}: invalid base64') from error
        if base64.b64encode(block).decode() != encoded:
            raise ValueError(f'line {number}: noncanonical base64')
        if len(block) != min(48, FLASH_SIZE - len(result)) or not block:
            raise ValueError(f'line {number}: invalid block length')
        if zlib.crc32(block) != int(expected_crc, 16):
            raise ValueError(f'line {number}: block CRC mismatch')
        result.extend(block)
    if not finished:
        raise ValueError('no complete C80FLASH backup with valid footer found')
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.log.open(encoding='utf-8-sig', errors='strict') as handle:
            data = decode(handle)
        # Exclusive creation: never overwrite an existing backup; owner-only access.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
    except (OSError, UnicodeError, ValueError) as error:
        print(f'Backup rejected: {error}', file=sys.stderr)
        return 1
    print(f'Validated {len(data)} bytes; CRC32={zlib.crc32(data):08x}; SHA256={hashlib.sha256(data).hexdigest()}')
    print(f'Saved: {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
