#!/usr/bin/env python3
"""Check byte-for-byte parent userspace and the four supplied OEM additions."""
from pathlib import Path
import hashlib
import json
import os
import stat
import zlib

root=Path(__file__).resolve().parent
def inventory(directory):
    return {str(p.relative_to(directory)):
        ('link',os.readlink(p)) if p.is_symlink() else
        ('dir',stat.S_IMODE(p.stat().st_mode)) if p.is_dir() else
        ('file',stat.S_IMODE(p.stat().st_mode),hashlib.sha256(p.read_bytes()).hexdigest())
        for p in directory.rglob('*')}

a=inventory(root.parent/'openwrt-ram1/rootfs');b=inventory(root/'rootfs')
assert all(b[k]==v for k,v in a.items())
names=('test_mcu.bin','test_wifi.bin','WIFI_RAM_CODE_iemi.bin','WIFI_RAM_CODE_demi.bin')
extras=sorted(set(b)-set(a))
assert set(extras)=={'lib/firmware/c80'}|{'lib/firmware/c80/'+n for n in names},extras
records=[]
for name in names:
    p=root/'rootfs/lib/firmware/c80'/name;data=p.read_bytes()
    assert data==(root.parent/'firmware-ru-240812/minifs/fw/mtk'/name).read_bytes()
    records.append({'file':str(p.relative_to(root)),'bytes':len(data),
        'sha256':hashlib.sha256(data).hexdigest(),'crc32':f'{zlib.crc32(data):08x}'})
(root/'FIRMWARE-SOURCES.json').write_text(json.dumps({
    'origin':'User-supplied official Archer C80(RU)_V1_240812.zip/minifs/fw/mtk; compared to installed TPOS image',
    'files':records,'OEM_licenses_unchanged':True,'calibration_included':False},indent=2)+'\n')
(root/'evidence/rootfs-scope.json').write_text(json.dumps({
    'parent_userspace_byte_identical':True,'parent_entries':len(a),
    'added_paths':extras,'files':records},indent=2)+'\n')
print('Parent userspace unchanged; only four firmware files and their directory added.')
