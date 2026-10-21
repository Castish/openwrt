#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Repair the RAM39 helper in an external initramfs, preserving issued images."""
from pathlib import Path
import hashlib,importlib.util,json,re,shutil,stat,struct,subprocess,zlib
R=Path(__file__).resolve().parent;P=R.parent/'openwrt-ram39-gtk-init'
assert not (R/'c80-openwrt-ram39-helper-fix1.zip').exists(),'Issued archive is immutable'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
spec=importlib.util.spec_from_file_location('parent_cpio',P/'cpio_tools.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
manifest=json.loads((P/'package-manifest.json').read_text())['files']
for row in manifest:
 p=P/row['file'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['file']
assert sha(P/'c80-openwrt-ram39-gtk-init.zip')=='9389077729a0970d32b940e60f37e9a194a5e213d119aab195d6503f8735a22c'
release=(P/'build/include/config/kernel.release').read_text().strip()
assert release==json.loads((P/'PROVENANCE.json').read_text())['kernel']=='6.12.113-c80-openwrt-ram39-gtk-init'
old=(P/'rootfs/usr/sbin/c80-wifi').read_text()
wrong=re.search(r'\[ "\$\(uname -r\)" = \'([^\']+)\' \]',old).group(1)
assert wrong=='6.12.113-c80-openwrt-ram39-bmc-profile' and old.count(wrong)==1
fixed=old.replace(wrong,release);(R/'c80-wifi').write_text(fixed);(R/'c80-wifi').chmod(0o755)
subprocess.run(['sh','-n',str(R/'c80-wifi')],check=True)
saved=c.entries((P/'c80-auth.cpio').read_bytes());overlay=dict(saved)
for name in ['usr','usr/sbin']:overlay[name]=(stat.S_IFDIR|0o755,0,0,0,0,b'')
overlay['usr/sbin/c80-wifi']=(stat.S_IFREG|0o755,0,0,0,0,fixed.encode())
overlay['etc/c80-helper-fix']=(stat.S_IFREG|0o644,0,0,0,0,b'ram39-helper-fix1\n')
def record(ino,name,entry):
 mode,uid,gid,major,minor,data=entry;name=name.encode()+b'\0'
 fields=[ino,mode,uid,gid,2 if stat.S_ISDIR(mode) else 1,0,len(data),0,0,major,minor,len(name),0]
 raw=b'070701'+''.join(f'{v:08x}' for v in fields).encode()+name
 raw+=bytes(-len(raw)%4);raw+=data;raw+=bytes(-len(raw)%4);return raw
raw=b''.join(record(i,n,e) for i,(n,e) in enumerate(overlay.items(),1))
raw+=record(len(overlay)+1,'TRAILER!!!',(0,0,0,0,0,b''));raw+=bytes(-len(raw)%4096)
(R/'c80-auth-helper-fix1.cpio').write_bytes(raw);assert c.entries(raw)==overlay
for name,data in saved.items():assert overlay[name]==data
end=0x40d00000+len(raw);assert 0x40d00000<end<0x40e00000
dts='''// SPDX-License-Identifier: MIT
/dts-v1/;
/plugin/;
/ { fragment@0 { target-path = "/chosen"; __overlay__ {
    linux,initrd-start = <0x40d00000>;
    linux,initrd-end = <0x%08x>;
}; }; };
'''%end
(R/'auth-helper.dtso').write_text(dts)
dtc=P/'build-qemu/scripts/dtc/dtc';fdtoverlay=P/'build-qemu/scripts/dtc/fdtoverlay'
subprocess.run([str(dtc),'-@','-I','dts','-O','dtb','-o',str(R/'auth-helper.dtbo'),str(R/'auth-helper.dtso')],check=True)
for source,out in [('c80-openwrt-ram39-gtk-init.dtb','c80-openwrt-ram39-helper-fix1.dtb'),('qemu-auth.dtb','qemu-auth-helper-fix1.dtb')]:
 subprocess.run([str(fdtoverlay),'-i',str(P/source),'-o',str(R/out),str(R/'auth-helper.dtbo')],check=True)
def properties(data):
 h=struct.unpack_from('>10I',data);assert h[0]==0xd00dfeed and h[1]==len(data)
 pos=h[2];strings=data[h[3]:h[3]+h[8]];stack=[];out={}
 while True:
  token=struct.unpack_from('>I',data,pos)[0];pos+=4
  if token==1:
   n=data.index(b'\0',pos);stack.append(data[pos:n].decode());pos=(n+4)&~3
  elif token==2:stack.pop()
  elif token==3:
   size,off=struct.unpack_from('>II',data,pos);pos+=8
   name=strings[off:strings.index(b'\0',off)].decode();out[('/'.join(stack),name)]=data[pos:pos+size];pos=(pos+size+3)&~3
  elif token==4:pass
  elif token==9:return out
  else:raise AssertionError(token)
for source,out in [('c80-openwrt-ram39-gtk-init.dtb','c80-openwrt-ram39-helper-fix1.dtb'),('qemu-auth.dtb','qemu-auth-helper-fix1.dtb')]:
 a=properties((P/source).read_bytes());b=properties((R/out).read_bytes())
 a[('/chosen','linux,initrd-end')]=struct.pack('>I',end);assert a==b
for name in ['c80-openwrt-ram39-gtk-init-zImage','c80-openwrt-ram39-handoff.bin']:shutil.copy2(P/name,R/name)
lines=['C80SCRIPT1','# RAM39 helper fix1: unchanged kernel; corrected helper in personal initramfs.'];loads=[]
for addr,name in [('41000000','c80-openwrt-ram39-gtk-init-zImage'),('40f00000','c80-openwrt-ram39-helper-fix1.dtb'),('40e00000','c80-openwrt-ram39-handoff.bin'),('40d00000','c80-auth-helper-fix1.cpio')]:
 data=(R/name).read_bytes();crc=f'{zlib.crc32(data):08x}';lines.append(f'load {addr} {name} {len(data):08x} {crc}')
 loads.append({'address':addr,'file':name,'bytes':len(data),'crc32':crc,'sha256':sha(R/name)})
lines+=['go 40e00000','end'];(R/'c80-start.txt').write_text('\n'.join(lines)+'\n')
(R/'private').mkdir(exist_ok=True);(R/'evidence').mkdir(exist_ok=True)
run=(P/'run-qemu-auth.sh').read_text().replace('auth_parent="$auth_root"','auth_parent="$auth_root/../openwrt-ram39-gtk-init"').replace('"$auth_root/qemu-auth.dtb"','"$auth_root/qemu-auth-helper-fix1.dtb"').replace('"$auth_root/qemu-bootshim.bin"','"$auth_parent/qemu-bootshim.bin"').replace('"$auth_root/c80-auth.cpio"','"$auth_root/c80-auth-helper-fix1.cpio"')
(R/'run-qemu-auth.sh').write_text(run)
result={'passed':True,'release':'RAM39 helper guard fix1','kernel_release':release,'faulty_helper_expected_release':wrong,'helper_sha256':sha(R/'c80-wifi'),'one_helper_string_changed':True,'parent_frozen_members_verified':len(manifest),'parent_kernel_unchanged':True,'parent_handoff_unchanged':True,'parent_driver_and_built_in_rootfs_unchanged':True,'CPIO_bytes':len(raw),'CPIO_entries':len(overlay),'parent_auth_entries_preserved':len(saved),'all_personal_keys_and_shadow_preserved':True,'FDT_only_initrd_end_changed':True,'initrd_start':'40d00000','initrd_end':f'{end:08x}','load_files':loads,'parent_native_cases_inherited_by_identical_kernel':3753,'parent_QEMU_checks_not_rerun':43,'physical_AP_start_hardware_tested':False,'build_source_sha256':sha(Path(__file__))}
(R/'PROVENANCE.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
