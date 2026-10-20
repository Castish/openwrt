#!/usr/bin/env python3
"""Execute OEM local-image validation (including native MD5) and normal bootm.
Flash reads, console/cache/CPU shutdown and LZMA in bootm are modeled. The
separate native-LZMA test executes the original decoder on the patched U-Boot.
TPOS entry is observed, not a full stock firmware hardware boot.
"""
from pathlib import Path
import hashlib,json,lzma,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import *
R=Path(__file__).resolve().parent
factory=(R.parent/'uboot-script-research/factory-uboot-private.bin').read_bytes()
raw=(R/'private/normal-uboot-patched.bin').read_bytes()
original=(R.parent/'flash-full-20261017/c80-full-flash.bin').read_bytes()
firmware=(R/'c80-uboot-native-firmware.bin').read_bytes()
flash=original[:0x25000]+firmware+original[0x3e8000:]
rows=[]
def put(c,a,v):c.mem_write(a,struct.pack('<I',v))
def finish(c,v):c.reg_write(UC_ARM_REG_R0,v&0xffffffff);c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
def machine(base,data):
 c=Uc(UC_ARCH_ARM,UC_MODE_ARM);c.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
 c.mem_map(0x40000000,0x2000000);c.mem_write(base,data);c.mem_map(0x30000000,0x400000);c.mem_write(0x30000000,flash)
 c.reg_write(UC_ARM_REG_CPSR,0x600001d3);c.reg_write(UC_ARM_REG_R9,0x41e7bf2c)
 c.reg_write(UC_ARM_REG_SP,0x41d7e000);c.reg_write(UC_ARM_REG_LR,0x41d7f000);return c
for name,damaged in [('actual-native-factory-MD5-accepts-repacked-IMG0',False),('actual-native-factory-MD5-rejects-damage',True)]:
 c=machine(0x41e00000,factory)
 if damaged:c.mem_write(0x30035000,bytes([flash[0x35000]^1]))
 def validation(c,pc,n,_):
  if pc==0x41e11730:
   src,dst,length=[c.reg_read(x) for x in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
   assert (src,dst,length)==(0x30000000,0x40200000,0x400000)
   c.mem_write(dst,bytes(c.mem_read(src,length)));finish(c,0)
  elif pc==0x41e04b7c:finish(c,0)
  elif pc==0x41e18d2c:
   dst,src,length=[c.reg_read(x) for x in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
   c.mem_write(dst,bytes(c.mem_read(src,length)));finish(c,dst)
  elif pc==0x41e18cd0:
   dst,value,length=[c.reg_read(x) for x in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
   c.mem_write(dst,bytes([value&255])*length);finish(c,dst)
  elif pc==0x41e18d98:
   a,b,length=[c.reg_read(x) for x in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
   finish(c,0 if bytes(c.mem_read(a,length))==bytes(c.mem_read(b,length)) else 1)
 for pc in [0x41e11730,0x41e04b7c,0x41e18d2c,0x41e18cd0,0x41e18d98]:c.hook_add(UC_HOOK_CODE,validation,begin=pc,end=pc)
 c.emu_start(0x41e1520c,0x41d7f000,timeout=60_000_000,count=200_000_000)
 assert c.reg_read(UC_ARM_REG_PC)==0x41d7f000,hex(c.reg_read(UC_ARM_REG_PC))
 expected=0xffffffff if damaged else 0;assert c.reg_read(UC_ARM_REG_R0)==expected
 rows.append({'case':name,'passed':True,'result':expected,'native_MD5_executed':True});print('PASS '+name,flush=True)
# Execute the ORIGINAL installed normal bootm on the new component offsets.
c=machine(0x41c00000,raw);argv=0x40800000
c.mem_write(argv+64,b'bootm\0');c.mem_write(argv+80,b'30025000\0');put(c,argv,argv+64);put(c,argv+4,argv+80)
for reg,value in [(UC_ARM_REG_R0,0x41c2c578),(UC_ARM_REG_R1,0),(UC_ARM_REG_R2,2),(UC_ARM_REG_R3,argv)]:c.reg_write(reg,value)
transfers=[];cache=[]
def bootm(c,pc,n,_):
 if pc==0x41c04658:finish(c,0)
 elif pc==0x41c1e708:
  assert bytes(c.mem_read(c.reg_read(UC_ARM_REG_R0),9))==b'30025000\0';finish(c,0x30025000)
 elif pc==0x41c1c2c4:
  dst,outptr,src,length=[c.reg_read(x) for x in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]
  off,size=struct.unpack_from('>II',firmware,0x50)
  assert (dst,src,length)==(0x40205000,0x30025000+off,size)
  packed=bytes(c.mem_read(src,length));plain=lzma.decompress(packed,format=lzma.FORMAT_ALONE)
  assert hashlib.sha256(plain).hexdigest()==hashlib.sha256((R.parent/'flash-full-20261017/installed/components/tpos.bin').read_bytes()).hexdigest()
  c.mem_write(dst,plain);put(c,outptr,len(plain));transfers.append({'source':hex(src),'bytes':length,'destination':hex(dst),'output_bytes':len(plain)});finish(c,0)
 elif pc==0x41c00508:cache.append([c.reg_read(UC_ARM_REG_R0),c.reg_read(UC_ARM_REG_R1)]);finish(c,0)
 elif pc==0x41c005c4:finish(c,0)
for pc in [0x41c04658,0x41c1e708,0x41c1c2c4,0x41c00508,0x41c005c4]:c.hook_add(UC_HOOK_CODE,bootm,begin=pc,end=pc)
c.emu_start(0x41c023a4,0x40205000,timeout=20_000_000,count=1000000)
assert c.reg_read(UC_ARM_REG_PC)==0x40205000 and len(transfers)==1 and len(cache)==1
rows.append({'case':'original-normal-bootm-loads-identical-TPOS-from-shifted-slot','passed':True,'transfers':transfers,'cache_services':cache,'stock_OS_entry_observed':True});print('PASS original-normal-bootm-shifted-slot',flush=True)
report={'passed':True,'cases_passed':len(rows),'scope':__doc__,'cases':rows,'firmware_sha256':hashlib.sha256(firmware).hexdigest(),'hardware_tested':False}
(R/'evidence/oem-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
