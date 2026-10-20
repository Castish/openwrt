#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only checks of the config overlay, RAM layout and frozen parent releases."""
from pathlib import Path
import hashlib, importlib.util, json, stat, struct, zipfile, zlib

R=Path(__file__).resolve().parent
P=R.parent/'openwrt-ram31-scheduler'
spec=importlib.util.spec_from_file_location('cpio_tools_readonly',P/'cpio_tools.py')
cpio_tools=importlib.util.module_from_spec(spec);spec.loader.exec_module(cpio_tools)
sha=lambda b:hashlib.sha256(b).hexdigest()

def fdt_props(data):
 magic,total,off_struct,off_strings,off_reserve,version,last_version,bootcpu,strings_size,struct_size=struct.unpack_from('>10I',data)
 assert magic==0xd00dfeed and total==len(data)
 pos=off_struct;end=pos+struct_size;stack=[];props={}
 while pos<end:
  token=struct.unpack_from('>I',data,pos)[0];pos+=4
  if token==1:
   stop=data.index(0,pos);stack.append(data[pos:stop].decode());pos=(stop+4)&~3
  elif token==2:stack.pop()
  elif token==3:
   size,noff=struct.unpack_from('>2I',data,pos);pos+=8
   name_start=off_strings+noff;name_end=data.index(0,name_start)
   key=('/'+'/'.join(stack[1:]),data[name_start:name_end].decode())
   assert key not in props;props[key]=data[pos:pos+size];pos=(pos+size+3)&~3
  elif token==4:pass
  elif token==9:break
  else:raise AssertionError(token)
 assert not stack
 reserve=[]
 while True:
  address,size=struct.unpack_from('>2Q',data,off_reserve);off_reserve+=16
  if not (address or size):break
  reserve.append((address,size))
 return props,reserve,(version,last_version,bootcpu)

newcpio=(R/'c80-auth.cpio').read_bytes()
assert len(newcpio)==4096
overlay=cpio_tools.entries(newcpio)
expected={'etc','etc/dropbear','etc/shadow'}|{'etc/dropbear/dropbear_'+k+'_host_key' for k in ['ed25519','ecdsa','rsa']}
assert set(overlay)==expected
for name,(mode,uid,gid,major,minor,data) in overlay.items():
 assert uid==gid==major==minor==0
 if name in ['etc','etc/dropbear']:
  assert mode==stat.S_IFDIR|({'etc':0o755,'etc/dropbear':0o700}[name]) and not data
 else:assert mode==stat.S_IFREG|0o600
 assert 'authorized_keys' not in name
actual_rootfs=cpio_tools.entries((P/'build/usr/initramfs_data.cpio').read_bytes())
shadow=overlay['etc/shadow'][5].decode().splitlines()
oldshadow=actual_rootfs['etc/shadow'][5].decode().splitlines()
assert len(shadow)==len(oldshadow)
for before,after in zip(oldshadow,shadow):
 a=before.split(':');b=after.split(':')
 if a[0]=='root':
  assert a[0]==b[0] and a[2:]==b[2:] and b[1].startswith('$6$') and a[1]!=b[1]
 else:assert a==b
assert actual_rootfs['etc/passwd'][5].startswith(b'root:x:0:0:')
config=actual_rootfs['etc/config/dropbear'][5]
assert b"PasswordAuth 'on'" in config and b"RootPasswordAuth 'on'" in config

before,reserve,header=fdt_props((P/'c80-openwrt-ram31-scheduler.dtb').read_bytes())
after,newreserve,newheader=fdt_props((R/'c80-openwrt-ram31-auth.dtb').read_bytes())
extra={('/chosen','linux,initrd-start'):struct.pack('>I',0x40c00000),('/chosen','linux,initrd-end'):struct.pack('>I',0x40c01000)}
assert not (set(before)&set(extra))
assert after==before|extra and reserve==newreserve and header==newheader
for name in ['c80-openwrt-ram31-scheduler-zImage','c80-openwrt-ram31-handoff.bin']:
 assert (R/name).read_bytes()==(P/name).read_bytes()
# Both linked kernels end below40c; decompressor input/stack/heap are at410+
# on hardware and in run-qemu-auth.sh. Loading QEMU zImage at its default low
# address would relocate it across40c, so the test deliberately mirrors hardware.
kernel_end=0x40200000+int(next(x.split()[0] for x in (P/'build/System.map').read_text().splitlines() if x.endswith(' _end')),16)-0xc0000000
assert kernel_end<0x40c00000
assert b'CONFIG_BLK_DEV_INITRD=y' in (P/'build/.config').read_bytes()
assert b'CONFIG_INITRAMFS_FORCE=y' not in (P/'build/.config').read_bytes()
lines=(R/'c80-start.txt').read_text().splitlines()
assert lines[0]=='C80SCRIPT1' and len((R/'c80-start.txt').read_bytes())<=4096
loads=[];go=None
for line in lines[1:]:
 if not line or line.startswith('#'):continue
 fields=line.split()
 if fields[0]=='load':
  assert len(fields)==5
  start=int(fields[1],16);payload=(R/fields[2]).read_bytes();size=int(fields[3],16)
  assert size==len(payload) and int(fields[4],16)==zlib.crc32(payload)
  end=start+size;assert 0x40200000<=start<end<=0x41c00000
  for a,b in [(0x40280000,0x40290000),(0x40a00000,0x40a10000)]+[(a,b) for a,b,n in loads]:assert end<=a or start>=b
  loads.append((start,end,fields[2]))
 elif fields[0]=='go':assert len(fields)==2;go=int(fields[1],16)
 else:assert fields==['end']
assert len(loads)==4 and go==0x40e00000
assert (0x40c00000,0x40c01000,'c80-auth.cpio') in loads
frozen=[]
for folder,archive,digest in [
 ('openwrt-ram31-scheduler','c80-openwrt-ram31-scheduler.zip','805cd14bac690f3d4945c48d1cbd99ef09b8a7fcb74fe2e95fe997dd6f041479'),
 ('uboot-native-netboot-v1','c80-uboot-native-netboot-v1.zip','ebd3bd541cdf2cd400b55320e7ce8539ef11bc8f22caa55d2890159d1d0956cd')]:
 parent=R.parent/folder;manifest=json.loads((parent/'package-manifest.json').read_text())
 archive_path=parent/archive
 if not archive_path.exists():
  candidates=list(parent.glob('*.zip'));assert len(candidates)==1;archive_path=candidates[0]
 assert sha(archive_path.read_bytes())==digest
 with zipfile.ZipFile(archive_path) as z:
  members=z.namelist()
  prefix=next(n[:-len('package-manifest.json')] for n in members if n.count('/')==1 and n.endswith('/package-manifest.json'))
  for row in manifest['files']:
   data=(parent/row['file']).read_bytes();assert len(data)==row['bytes'] and sha(data)==row['sha256'],row['file']
   assert z.read(prefix+row['file'])==data
 frozen.append({'release':folder,'unchanged_local_and_ZIP_members':len(manifest['files']),'ZIP_SHA256':digest})
report={'passed':True,'external_initramfs_bytes':len(newcpio),'external_initramfs_sha256':sha(newcpio),
 'CPIO_scope':'root shadow password field and three private server host keys; no client authorized_keys',
 'DTB_scope':'only /chosen/linux,initrd-start and linux,initrd-end; all hardware/memory properties unchanged',
 'hardware_kernel_and_handoff_byte_identical_to_RAM31':True,'linked_hardware_kernel_end':hex(kernel_end),
 'manifest_loads':len(loads),'manifest_memory_ranges_valid':True,'no_flash_or_bootloader_writes':True,
 'frozen_parents':frozen,'hardware_tested':False}
(R/'evidence/scope-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
