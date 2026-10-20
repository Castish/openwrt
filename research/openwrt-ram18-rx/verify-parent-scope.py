#!/usr/bin/env python3
"""Verify that the new kernel changes only two MCU sources from issued RAM17.
Check the full source tree/rootfs and every recorded parent package member.
"""
from pathlib import Path
import difflib, filecmp, hashlib, json

r = Path(__file__).resolve().parent
p = r.parent / 'openwrt-ram17-watch'
manifest = json.loads((p / 'package-manifest.json').read_text())
for row in manifest['files']:
    f = p / row['file']
    assert f.stat().st_size == row['bytes']
    assert hashlib.sha256(f.read_bytes()).hexdigest() == row['sha256'], row['file']
archive = p / 'c80-openwrt-ram17-watch.zip'
assert hashlib.sha256(archive.read_bytes()).hexdigest() == '239fcc7645ed2ce5b1be3b8e1de67fb413ccef06ed479dc4de7b2da7850348a3'

def compare(a, b):
    x = {str(f.relative_to(a)): f for f in a.rglob('*') if f.is_symlink() or not f.is_dir()}
    y = {str(f.relative_to(b)): f for f in b.rglob('*') if f.is_symlink() or not f.is_dir()}
    assert x.keys() == y.keys()
    different = []
    for name, old in x.items():
        new = y[name]
        if old.is_symlink() or new.is_symlink():
            assert old.is_symlink() and new.is_symlink() and old.readlink() == new.readlink()
        elif not filecmp.cmp(old, new, shallow=False):
            different.append(name)
    return sorted(different), len(x)

changed, count = compare(p/'linux-6.12.113', r/'linux-6.12.113')
assert changed == ['drivers/soc/mediatek/c80_mcu_core.h', 'drivers/soc/mediatek/c80_mcu_transport.c'], changed
root_changed, root_count = compare(p/'rootfs', r/'rootfs')
assert not root_changed
patch = ''
for name in ('c80_mcu_core.h', 'c80_mcu_transport.c'):
    assert (r/'linux-6.12.113/drivers/soc/mediatek'/name).read_bytes() == (r/name).read_bytes()
    patch += ''.join(difflib.unified_diff((p/name).read_text().splitlines(True),
                    (r/name).read_text().splitlines(True), fromfile='a/'+name, tofile='b/'+name))
patch += ''.join(difflib.unified_diff((p/'mt7626-archer-c80-v1-emi.dts').read_text().splitlines(True),(r/'mt7626-archer-c80-v1-emi.dts').read_text().splitlines(True),fromfile='a/mt7626-archer-c80-v1-emi.dts',tofile='b/mt7626-archer-c80-v1-emi.dts'))
(r/'ram17-to-ram18.patch').write_text(patch)
result = {'passed': True, 'parent': p.name, 'changed_Linux_files': changed,
          'source_tree_files_compared': count, 'rootfs_entries_compared': root_count,
          'rootfs_byte_identical_to_parent': True, 'all_issued_parent_manifest_members_unchanged': True,
          'parent_ZIP_SHA256': hashlib.sha256(archive.read_bytes()).hexdigest()}
(r/'evidence/ram17-change-scope.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result))
