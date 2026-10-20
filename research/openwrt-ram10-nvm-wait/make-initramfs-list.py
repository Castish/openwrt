#!/usr/bin/env python3
"""Create a deterministic root-owned CPIO description without host root access."""
from pathlib import Path
import os
import stat

base = Path(__file__).resolve().parent
root = base / 'rootfs'
lines = []
for path in sorted(root.rglob('*')):
    name = '/' + str(path.relative_to(root))
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if path.is_symlink():
        lines.append(f'slink {name} {os.readlink(path)} {mode:o} 0 0')
    elif path.is_dir():
        lines.append(f'dir {name} {mode:o} 0 0')
    elif path.is_file():
        lines.append(f'file {name} {path} {mode:o} 0 0')
    else:
        raise ValueError(f'Unexpected input type: {path}')
assert not (root / 'dev/console').exists()
lines += ['nod /dev/console 600 0 0 c 5 1', 'nod /dev/null 666 0 0 c 1 3',
          'nod /dev/zero 666 0 0 c 1 5', 'nod /dev/tty 666 0 0 c 5 0',
          'nod /dev/random 666 0 0 c 1 8', 'nod /dev/urandom 666 0 0 c 1 9']
(base / 'initramfs.list').write_text('\n'.join(lines) + '\n')
print(f'Root-owned CPIO list: {len(lines)} entries.')
