#!/usr/bin/env python3
"""Check every current host rootfs entry against the exact kernel CPIO."""
from pathlib import Path
import gzip,hashlib,json,os,stat
from cpio_tools import entries
r=Path(__file__).resolve().parent;root=r/'rootfs';cp=entries((r/'build/usr/initramfs_data.cpio').read_bytes());seen=set()
for p in root.rglob('*'):
 name=str(p.relative_to(root));mode=p.lstat().st_mode;row=cp[name];seen.add(name)
 assert stat.S_IFMT(mode)==stat.S_IFMT(row[0]) and stat.S_IMODE(mode)==stat.S_IMODE(row[0]),name
 assert row[1]==row[2]==0
 if p.is_symlink():assert row[5].rstrip(b'\0').decode()==os.readlink(p),name
 elif p.is_file():assert row[5]==p.read_bytes(),name
assert set(cp)-seen=={'dev/console','dev/null','dev/zero','dev/tty','dev/random','dev/urandom'}
result={'passed':True,'host_entries_compared':len(seen),'kernel_CPIO_entries':len(cp),'all_modes_contents_links_match':True,'source_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(r/'evidence/rootfs-scope.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
