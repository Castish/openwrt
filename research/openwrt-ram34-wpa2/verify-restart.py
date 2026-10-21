#!/usr/bin/env python3
"""Run actual OEM and compiled Linux ARM restart code against synthetic MMIO.

No physical reset, clocks, peripheral state, firmware or power rails emulated.
OEM source is private and not packaged. Linux vmlinux stays in the cloud build.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import struct
import subprocess
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A7,UC_ARM_REG_R0,UC_ARM_REG_LR,
    UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_CPSR)

root=Path(__file__).resolve().parent
private=root.parent/'uboot-script-research/factory-uboot-private.bin'
oem=private.read_bytes()
assert hashlib.sha256(oem).hexdigest()=='e333ac5679f4e1e76906caee06518b16a424da8e64a660f3d924e2dcff05c9ad'
elf=(root/'build/vmlinux').read_bytes()
env=dict(os.environ)
env['LD_LIBRARY_PATH']=str(root.parent/'linux-bringup/tools/usr/lib/x86_64-linux-gnu')
nm=subprocess.check_output([str(root.parent/'linux-bringup/tools/usr/bin/arm-linux-gnueabi-nm'),
    '-n',str(root/'build/vmlinux')],env=env,text=True)
symbols={s:int(a,16) for a,t,s in (line.split() for line in nm.splitlines() if len(line.split())==3)}

def run(kind,mode,accept=1):
    cpu=Uc(UC_ARCH_ARM,UC_MODE_ARM);cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    cpu.reg_write(UC_ARM_REG_CPSR,0xd3)
    cpu.mem_map(0x41000000,0x20000)
    stop=0x4101f000;dummy_delay=0x4101e000
    cpu.reg_write(UC_ARM_REG_SP,0x4101d000);cpu.reg_write(UC_ARM_REG_LR,stop)
    writes=[];delays=[];logs=[];accepted=False;returned=False
    if kind=='OEM':
        cpu.mem_map(0x41e00000,0x30000);cpu.mem_write(0x41e00000,oem)
        start=0x41e00600;base=0x10212000
        delay_functions={0x41e010a0};log_functions={0x41e04b7c}
    else:
        header=struct.unpack_from('<16sHHIIIIIHHHHHH',elf)
        cpu.mem_map(0xc0000000,0x1000000)
        for n in range(header[10]):
            p=struct.unpack_from('<8I',elf,header[5]+n*header[9])
            # Alternate vector sections share a high VA; this scoped callback
            # cannot enter them. Map only its ordinary kernel segments.
            if p[0]!=1 or not 0xc0000000<=p[2]<0xc1000000: continue
            assert p[2]+p[5]<=0xc1000000
            cpu.mem_write(p[2],elf[p[1]:p[1]+p[4]])
        base=0xf1000000;start=symbols['c80_restart']
        # Actual ARM32 struct sys_off_data: mode,cb_data,cmd,device.
        cpu.mem_write(0x41000000,struct.pack('<4I',0,base,0,0))
        cpu.reg_write(UC_ARM_REG_R0,0x41000000)
        cpu.mem_write(symbols['arm_delay_ops'],struct.pack('<3I',*([dummy_delay]*3)))
        delay_functions={dummy_delay};log_functions={symbols['_printk']}
    def rd(uc,off,size,unused):
        assert off==0 and size==4,(kind,off,size)
        return mode
    def wr(uc,off,size,value,unused):
        nonlocal accepted
        assert size==4 and off in (0,8,0x14),(kind,off,size,value)
        writes.append((off,value))
        if off==0x14 and accept and sum(x[0]==0x14 for x in writes)==accept:
            accepted=True;uc.emu_stop()
    cpu.mmio_map(base,4096,rd,None,wr,None)
    def hook(uc,pc,size,unused):
        nonlocal returned
        if pc==stop: returned=True;uc.emu_stop()
        elif pc in delay_functions|log_functions:
            (delays if pc in delay_functions else logs).append(uc.reg_read(UC_ARM_REG_R0))
            uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif kind=='Linux' and pc==symbols['arm_heavy_mb']:
            # Interconnect drain/cache effects are not emulated.
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(start,stop+4,count=100000)
    expected_mode=(mode if kind=='OEM' else mode&~8)|4|0x22000000
    assert writes[:2]==[(8,0x1971),(0,expected_mode)],(kind,writes)
    triggers=[x for x in writes[2:]]
    assert all(x==(0x14,0x1209) for x in triggers)
    if accept: assert accepted and not returned and len(triggers)==accept
    else:
        assert kind=='Linux' and returned and not accepted and len(triggers)==100
        assert cpu.reg_read(UC_ARM_REG_R0)==0 and len(logs)==1
    assert delays
    return {'code':kind,'initial_mode':hex(mode),'reset_acceptance_modeled_after_writes':accept,
        'writes':[(hex(a),hex(b)) for a,b in writes],
        'delay_calls_modeled':len(delays),'fallback_returned':returned,'passed':True}

cases=[run('OEM',m) for m in (0,8,0x100)]
cases += [run('Linux',m) for m in (0,8,0x100)]
cases += [run('Linux',8,3),run('Linux',0,0)]
report={'scope':__doc__,'cases':cases,'passed':True,'cases_passed':len(cases),
    'factory_uboot_sha256':hashlib.sha256(oem).hexdigest(),
    'Linux_vmlinux_sha256':hashlib.sha256(elf).hexdigest(),
    'restart_symbol':hex(symbols['c80_restart']),
    'hardware_tested':False,'cold_power_cycle_equivalence_proven':False,
    'MMIO_reset_acceptance_and_delay_services_synthetic':True}
(root/'evidence/restart-result.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'Actual ARM restart code passed {len(cases)} cases:3 OEM +5 Linux; hardware reset untested.')
