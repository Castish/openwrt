#!/usr/bin/env python3
"""Generate a C80SCRIPT1 file with exact lengths/CRCs; Python standard library."""
import argparse
from pathlib import Path
import re
import zlib

def make(pairs, entries):
    loads, lines = [], ['C80SCRIPT1', '# All numeric fields are hexadecimal.']
    for address_text, path_text in pairs:
        address = int(address_text, 16)
        path = Path(path_text)
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,95}', path.name) or path.name in ('.', '..'):
            raise ValueError('Use a simple ASCII basename of 1..95 characters')
        data = path.read_bytes()
        end = address + len(data)
        if address % 4 or not data or address < 0x40200000 or end > 0x41c00000:
            raise ValueError('Payload must fit aligned permitted RAM')
        for start, stop in [(0x40280000, 0x40290000), (0x40a00000, 0x40a10000), *loads]:
            if address < stop and start < end:
                raise ValueError('Payload overlaps a reserved interval or another load')
        loads.append((address, end))
        lines.append(f'load {address:08x} {path.name} {len(data):08x} {zlib.crc32(data):08x}')
    for entry_text in entries:
        entry = int(entry_text, 16)
        if entry not in [start for start, _ in loads]:
            raise ValueError('go requires the exact base of a preceding load')
        lines.append(f'go {entry:08x}')
    if len(loads) + len(entries) > 16:
        raise ValueError('At most 16 steps')
    lines.append('end')
    script = '\n'.join(lines) + '\n'
    if len(script.encode('ascii')) > 4096:
        raise ValueError('Script exceeds 4096 bytes')
    return script

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pairs', nargs='+', help='ADDRESS FILE [ADDRESS FILE ...]; addresses are hex')
    parser.add_argument('--go', action='append', default=[], metavar='ADDRESS')
    parser.add_argument('--output', '-o', type=Path, default=Path('c80-start.txt'))
    parser.add_argument('--force', action='store_true', help='Replace an existing script')
    args = parser.parse_args()
    if len(args.pairs) % 2:
        parser.error('Expected ADDRESS FILE pairs')
    try:
        script = make(list(zip(args.pairs[::2], args.pairs[1::2])), args.go)
        with args.output.open('w' if args.force else 'x', encoding='ascii', newline='\n') as output:
            output.write(script)
    except (OSError, ValueError) as error:
        parser.exit(1, f'{error}\n')
    print(script, end='')

if __name__ == '__main__':
    main()
