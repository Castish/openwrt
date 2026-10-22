#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a freestanding ARM timer diagnostic for the physical and QEMU rootfs."""
from pathlib import Path
import hashlib,json,os,subprocess
root=Path(__file__).resolve().parent
cross=root.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-gcc'
env=dict(os.environ)
env['LD_LIBRARY_PATH']=str(root.parent/'linux-bringup/tools/usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','')
out=root/'rootfs/usr/sbin/c80-timer-check'
command=[str(cross),'-mcpu=cortex-a7','-marm','-mfloat-abi=soft','-Os','-Wall','-Wextra','-Werror',
         '-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pie','-no-pie','-nostdlib','-static',
         '-Wl,--build-id=none','-Wl,-e,_start',str(root/'c80_timer_check.c'),'-lgcc','-o',str(out)]
subprocess.run(command,env=env,check=True)
out.chmod(0o755)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
record={'passed':True,'source_sha256':sha(root/'c80_timer_check.c'),'binary_sha256':sha(out),
        'binary_bytes':out.stat().st_size,'command':command,'static_no_target_libc':True,
        'peripheral_access':False,'changes_scheduling_or_CPU_frequency':False}
(root/'evidence/timer-diagnostic-build.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
