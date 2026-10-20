#!/usr/bin/env python3
"""Freeze a RAM-only verification issue, excluding private OEM/sector buffers."""
from pathlib import Path
import hashlib,json,zipfile
R=Path(__file__).resolve().parent;Z=R/'c80-autoboot-v1.zip';assert not Z.exists()
assert json.loads((R/'evidence/artifact-verification.json').read_text())['passed']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
names=set()
for p in R.iterdir():
 if not p.is_file() or p.name in ['STATUS.md','package-manifest.json','bundle-result.json']:continue
 if p.suffix in ['.py','.sh','.c','.S','.ld','.ps1','.md','.json','.log'] or p.name in ['c80-autoboot.bin','c80-autoboot.elf','c80-autoboot.uImage','c80-script-runner.bin','c80-ram-probe.bin','c80-start.txt','c80-start-openwrt.txt','disassembly.txt','elf-inspection.txt','symbols.txt']:names.add(p.name)
for folder in ['evidence','runner-source']:
 for p in (R/folder).rglob('*'):
  if p.is_file():names.add(str(p.relative_to(R)))
assert not any(n.startswith('private/') or 'full-flash' in n or n.endswith('-zImage') or n.endswith('.dtb') for n in names)
rows=[{'file':n,'bytes':(R/n).stat().st_size,'sha256':sha(R/n)} for n in sorted(names)]
(R/'SHA256SUMS').write_text(''.join(f"{x['sha256']}  {x['file']}\n" for x in rows))
rows.append({'file':'SHA256SUMS','bytes':(R/'SHA256SUMS').stat().st_size,'sha256':sha(R/'SHA256SUMS')})
manifest={'release':'C80 AutoTFTP v1 RAM verification candidate','permanently_installed':False,'physical_wrapper_tested':False,'all_issued_members_frozen':True,'files':rows}
(R/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
with zipfile.ZipFile(Z,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for name in sorted({x['file'] for x in rows}|{'package-manifest.json'}):z.write(R/name,'c80-autoboot-v1/'+name)
with zipfile.ZipFile(Z) as z:
 assert z.testzip() is None
 for x in rows:assert hashlib.sha256(z.read('c80-autoboot-v1/'+x['file'])).hexdigest()==x['sha256']
result={'archive':str(Z),'bytes':Z.stat().st_size,'sha256':sha(Z),'ZIP_files':len(rows)+1,'frozen_manifest_members':len(rows),'RAM_test_only':True,'physical_wrapper_tested':False,'permanent_autoboot_installed':False}
(R/'bundle-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
