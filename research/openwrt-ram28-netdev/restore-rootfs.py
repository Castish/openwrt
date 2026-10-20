#!/usr/bin/env python3
"""Restore this release's RAM rootfs without host root or device creation."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import stat
import tempfile
from cpio_tools import entries

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--verify', action='store_true')
args = parser.parse_args()
archive = root / 'rootfs.cpio.gz'
manifest = json.loads((root / 'rootfs-inputs.json').read_text())
assert hashlib.sha256(archive.read_bytes()).hexdigest() == manifest['archive_sha256']
records = entries(gzip.decompress(archive.read_bytes()))

def restore(destination):
    destination.mkdir(exist_ok=False)
    for name, (mode, uid, gid, major, minor, data) in records.items():
        if not name:
            assert stat.S_ISDIR(mode)
            continue
        assert not name.startswith('/') and '..' not in Path(name).parts
        path = destination / name
        assert path.parent.resolve().is_relative_to(destination.resolve())
        assert uid == gid == 0
        if stat.S_ISDIR(mode):
            path.mkdir(exist_ok=True)
        elif stat.S_ISREG(mode):
            path.write_bytes(data)
        elif stat.S_ISLNK(mode):
            target = data[:-1] if data.endswith(b'\0') else data
            assert b'\0' not in target
            path.symlink_to(target.decode())
        else:
            expected = {'dev/console': (5, 1), 'dev/null': (1, 3),
                        'dev/zero': (1, 5), 'dev/tty': (5, 0),
                        'dev/random': (1, 8), 'dev/urandom': (1, 9)}
            assert stat.S_ISCHR(mode) and expected.get(name) == (major, minor)
            continue  # make-initramfs-list.py recreates these six descriptions.
        if not path.is_symlink():
            path.chmod(stat.S_IMODE(mode))

def describe(directory):
    result = {}
    for path in directory.rglob('*'):
        name = str(path.relative_to(directory))
        mode = path.lstat().st_mode
        if path.is_symlink():
            result[name] = ('link', os.readlink(path))
        elif path.is_dir():
            result[name] = ('dir', stat.S_IMODE(mode))
        else:
            result[name] = ('file', stat.S_IMODE(mode), hashlib.sha256(path.read_bytes()).hexdigest())
    return result

if args.verify:
    with tempfile.TemporaryDirectory(prefix='c80-ram28-rootfs-') as tmp:
        fresh = Path(tmp) / 'rootfs'
        restore(fresh)
        assert describe(fresh) == describe(root / 'rootfs')
        count = len(describe(fresh))
    result = {'passed': True, 'entries_compared': count,
              'archive_sha256': manifest['archive_sha256'],
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'no_host_privilege_or_mknod_required': True}
    (root / 'evidence/rootfs-restore-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
else:
    restore(root / 'rootfs')
    print('Restored exact RAM rootfs; no host device nodes were created.')
