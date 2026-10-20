#!/usr/bin/env python3
"""Prepare the QEMU-only peer; the router CPIO never includes this helper."""
from pathlib import Path
import hashlib,json,os,subprocess
r=Path(__file__).resolve().parent
cross=r.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-gcc'
env=dict(os.environ)
env['LD_LIBRARY_PATH']=str(r.parent/'linux-bringup/tools/usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','')
out=r/'artifacts/c80-net-selftest';out.parent.mkdir(exist_ok=True)
cmd=[str(cross),'-mcpu=cortex-a7','-marm','-mfloat-abi=soft','-Os','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pie','-no-pie','-nostdlib','-static','-Wl,--build-id=none','-Wl,-e,_start',str(r/'verify-linux-network.c'),'-lgcc','-o',str(out)]
subprocess.run(cmd,env=env,check=True);out.chmod(0o755)
subprocess.run(['python3',str(r/'make-initramfs-list.py')],check=True)
(r/'initramfs-qemu.list').write_text((r/'initramfs.list').read_text()+f'file /usr/sbin/c80-net-selftest {out} 755 0 0\n')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(r/'evidence/qemu-peer-build.json').write_text(json.dumps({'source_sha256':sha(r/'verify-linux-network.c'),'ABI_header_sha256':sha(r/'linux-test-abi.h'),'binary_sha256':sha(out),'command':cmd,'in_router_CPIO':False},indent=2)+'\n')
print('QEMU-only peer compiled; separate538+1-entry CPIO prepared.')
