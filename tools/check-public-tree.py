#!/usr/bin/env python3
"""Check the allowlisted source publication and original source hashes.

This is a distribution-content check, not a repository vulnerability scan.
Build outputs and per-device inputs belong outside the public Git history.
"""
from pathlib import Path
import hashlib,json,re,subprocess,sys
R=Path(__file__).resolve().parent.parent
forbidden_suffix={'.bin','.cpio','.zip','.apk','.elf','.o','.dtb','.gz','.xz','.zst','.log','.pem','.key','.pub'}
forbidden_dirs={'private','downloads','rootfs','build','build-qemu','linux-6.12.113','__pycache__'}
private_header=re.compile(rb'-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----')
access_token=re.compile(rb'gh[pousr]_[A-Za-z0-9_]{24,}')
catalog=json.loads((R/'docs/source-catalog.json').read_text())['source_snapshots']
checked=0;source_bytes=0
for item in catalog:
 folder=R/item['snapshot_path'];manifest=json.loads((folder/'SOURCE-MANIFEST.json').read_text())
 assert len(manifest['files'])==item['source_files']
 for row in manifest['files']:
  data=(folder/row['file']).read_bytes()
  assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['original_source_sha256'],str(folder/row['file'])
  checked+=1;source_bytes+=len(data)
files=[]
for folder in [R/'research',R/'docs',R/'tools']:
 files.extend(p for p in folder.rglob('*') if p.is_file())
files.extend(p for p in R.iterdir() if p.is_file())
for p in files:
 relative=p.relative_to(R);data=p.read_bytes()
 assert not p.is_symlink() and p.stat().st_size<2_000_000,str(relative)
 assert not (set(relative.parts)&forbidden_dirs) and not any(x.startswith('hardware-') for x in relative.parts),str(relative)
 assert p.suffix not in forbidden_suffix and p.name not in {'shadow','.env','id_rsa','id_ed25519'},str(relative)
 assert b'\0' not in data and not private_header.search(data) and not access_token.search(data),str(relative)
 assert not re.search(r'(?:^|/)(?:dropbear_.*_host_key|c80-auth\.cpio)$',str(relative)),str(relative)
print(json.dumps({'passed':True,'source_snapshots':len(catalog),'original_sources_verified':checked,
 'source_bytes':source_bytes,'public_text_files_checked':len(files),
 'private_inputs_binary_images_runtime_keys_raw_hardware_logs_included':False},indent=2))
