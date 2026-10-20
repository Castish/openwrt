#!/usr/bin/env python3
"""Execute actual installer ARM; NOR driver calls and streaming CRC accelerated.
Native CRC instructions are separately checked against zlib. Flash-controller
IO is synthetic; no physical erase/program/readback has been exercised.
"""
from pathlib import Path
import hashlib,json,struct,zlib
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ
from unicorn.arm_const import *
R=Path(__file__).resolve().parent;B=0x41f7d000;ENTRY=0x40290000
blob=(R/'c80-uboot-install.bin').read_bytes();oem=(R.parent/'uboot-script-research/factory-uboot-private.bin').read_bytes()
original=(R.parent/'flash-full-20261017/c80-full-flash.bin').read_bytes()
newfw=(R/'c80-uboot-native-firmware.bin').read_bytes();oldfw=(R/'c80-uboot-stock-firmware.bin').read_bytes()
modified=original[:0x25000]+newfw+original[0x3e8000:]
CHANGED=json.loads((R/'evidence/firmware.json').read_text())['changed_4KiB_sectors']
rows=[]
def put(c,a,v):c.mem_write(a,struct.pack('<I',v))
def done(c,v):c.reg_write(UC_ARM_REG_R0,v&0xffffffff);c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
def machine():
 c=Uc(UC_ARCH_ARM,UC_MODE_ARM);c.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
 c.mem_map(0x40000000,0x2000000);c.mem_write(ENTRY,blob);c.mem_write(B,oem)
 c.reg_write(UC_ARM_REG_CPSR,0x600001d3);return c
# Native streaming CRC runs unhooked, including chaining across4KiB blocks.
for data in [b'',b'123456789',bytes(range(256)),newfw[:8192]]:
 c=machine();c.mem_write(0x41000000,data);c.reg_write(UC_ARM_REG_SP,0x41e70000);c.reg_write(UC_ARM_REG_LR,0x41e71000)
 for reg,v in [(UC_ARM_REG_R0,0xffffffff),(UC_ARM_REG_R1,0x41000000),(UC_ARM_REG_R2,len(data))]:c.reg_write(reg,v)
 c.emu_start(ENTRY+0xc8,0x41e71000,count=1000000)
 assert c.reg_read(UC_ARM_REG_PC)==0x41e71000
 assert c.reg_read(UC_ARM_REG_R0)^0xffffffff==zlib.crc32(data)
 rows.append({'case':f'native-CRC-{len(data)}-bytes','passed':True})

def run(name,*,op=None,current=original,source=newfw,corrupt_source=False,chip=0x400000,
 corrupt_profile=False,caller=B+0x2774,read_fail=None,erase_fail=False,write_fail=False,
 short_write=False,readback_bad=False,expected=0,expect_writes=None):
 c=machine();flash=bytearray(current);c.mem_write(0x41000000,source)
 if corrupt_source:c.mem_write(0x41000009,bytes([source[9]^1]))
 c.mem_map(0x30000000,0x400000);c.mem_write(0x30000000,current);c.mem_protect(0x30000000,0x400000,UC_PROT_READ)
 sh,nor=0x41e60000,0x41e61000;put(c,B+0x2a914,sh);put(c,sh,nor);put(c,nor+16,chip)
 if corrupt_profile:c.mem_write(B+0x6288,bytes([oem[0x6288]^1]))
 argv=0x40800000;c.mem_write(argv+64,b'40290000\0');put(c,argv,argv+64)
 if op is not None:c.mem_write(argv+96,op.encode()+b'\0');put(c,argv+4,argv+96)
 c.reg_write(UC_ARM_REG_R0,1 if op is None else 2);c.reg_write(UC_ARM_REG_R1,argv)
 sp=0x41e7afd8;gd=0x41e7bf2c;c.reg_write(UC_ARM_REG_SP,sp);c.reg_write(UC_ARM_REG_LR,caller);c.reg_write(UC_ARM_REG_R9,gd)
 saved={reg:0x40010000+i for i,reg in enumerate([UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R10,UC_ARM_REG_R11])}
 for reg,v in saved.items():c.reg_write(reg,v)
 out=bytearray();erases=[];writes=[];reads=0;corrupted=False
 def rd(c,a,n,_):return 0x20
 def wr(c,a,n,v,_):out.append(v&255)
 c.mmio_map(0x11002000,4096,rd,None,wr,None)
 def hook(c,pc,n,_):
  nonlocal reads,corrupted
  if pc==ENTRY+0xc8:
   crc,p,length=[c.reg_read(x) for x in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
   data=bytes(c.mem_read(p,length));done(c,zlib.crc32(data,crc^0xffffffff)^0xffffffff);return
  if ENTRY<=pc<ENTRY+len(blob):
   insn=struct.unpack('<I',c.mem_read(pc,4))[0];assert insn&0xffff0fff==0xee100f10
   c.reg_write(UC_ARM_REG_R0+((insn>>12)&15),0x410fc073);c.reg_write(UC_ARM_REG_PC,pc+4);return
  assert c.reg_read(UC_ARM_REG_R9)==gd
  a,length=[c.reg_read(x) for x in [UC_ARM_REG_R0,UC_ARM_REG_R1]]
  assert length==4096 and a%4096==0 and 0<=a<=0x3ff000
  if pc==B+0x60e4:
   reads+=1
   if reads==read_fail:done(c,0x55);return
   dst=c.reg_read(UC_ARM_REG_R3);assert dst==0x40b00000
   data=bytes(flash[a:a+length])
   if readback_bad and writes and not corrupted:
    data=bytes([data[0]^1])+data[1:];corrupted=True
   c.mem_write(dst,data);put(c,c.reg_read(UC_ARM_REG_R2),length);done(c,0)
  elif pc==B+0x63b0:
   assert 0x25000<=a<a+length<=0x3e8000;erases.append(a)
   if erase_fail:done(c,0x55);return
   flash[a:a+length]=b'\xff'*length;done(c,0)
  elif pc==B+0x6288:
   assert 0x25000<=a<a+length<=0x3e8000;writes.append(a)
   if write_fail:done(c,0x55);return
   data=bytes(c.mem_read(c.reg_read(UC_ARM_REG_R3),length));assert all((x&y)==y for x,y in zip(flash[a:a+length],data))
   flash[a:a+length]=data;put(c,c.reg_read(UC_ARM_REG_R2),length-1 if short_write else length);done(c,0)
  else:raise AssertionError(hex(pc))
 # Hook only service entry PCs, not the millions of native compare instructions.
 pcs=[ENTRY+0xc8,B+0x60e4,B+0x6288,B+0x63b0]
 for i in range(0,len(blob)-3,4):
  if struct.unpack_from('<I',blob,i)[0]&0xffff0fff==0xee100f10:pcs.append(ENTRY+i)
 for pc in pcs:c.hook_add(UC_HOOK_CODE,hook,begin=pc,end=pc)
 c.emu_start(ENTRY,caller,timeout=60_000_000,count=200_000_000)
 assert c.reg_read(UC_ARM_REG_PC)==caller,(name,hex(c.reg_read(UC_ARM_REG_PC)),out)
 assert c.reg_read(UC_ARM_REG_R0)==expected,(name,c.reg_read(UC_ARM_REG_R0),out)
 assert c.reg_read(UC_ARM_REG_SP)==sp and c.reg_read(UC_ARM_REG_R9)==gd
 for reg,v in saved.items():assert c.reg_read(reg)==v
 if expect_writes is not None:assert len(writes)==expect_writes,(name,len(writes),out)
 if expected==0 and op in ('i','r'):
  assert flash[0x25000:0x3e8000]==source
  if writes:assert writes[-1]==0x25000,'header must be committed last'
 assert flash[:0x25000]==current[:0x25000] and flash[0x3e8000:]==current[0x3e8000:]
 rows.append({'case':name,'passed':True,'result':expected,'reads':reads,'erase_calls':len(erases),'write_calls':len(writes),'last_write':hex(writes[-1]) if writes else None,'factory_and_tail_preserved':True,'console':out.decode(errors='replace')})
 print('PASS '+name,flush=True)
run('dry-run-no-write',expect_writes=0)
run('install-all-changed-sectors-header-last',op='i',expect_writes=CHANGED)
run('already-installed-zero-write',op='i',current=modified,expect_writes=0)
run('rollback-all-changed-sectors',op='r',current=modified,source=oldfw,expect_writes=CHANGED)
partial=bytearray(modified);partial[0x26000:0x27000]=b'\xff'*4096
run('rollback-interrupted-sector',op='r',current=bytes(partial),source=oldfw,expect_writes=CHANGED)
run('wrong-source-CRC',op='i',corrupt_source=True,expected=14,expect_writes=0)
run('wrong-preimage',op='i',current=bytes(partial),expected=18,expect_writes=0)
run('wrong-chip-size',op='i',chip=0x800000,expected=13,expect_writes=0)
run('wrong-native-profile',op='i',corrupt_profile=True,expected=11,expect_writes=0)
run('wrong-caller',op='i',caller=B+0x2778,expected=10,expect_writes=0)
run('invalid-operation',op='install',expected=12,expect_writes=0)
run('rollback-refuses-new-payload',op='r',expected=14,expect_writes=0)
run('preflight-read-failure',op='i',read_fail=1,expected=15,expect_writes=0)
run('erase-failure-stop',op='i',erase_fail=True,expected=22,expect_writes=0)
run('program-failure-stop',op='i',write_fail=True,expected=23,expect_writes=1)
run('program-short-count-stop',op='i',short_write=True,expected=23,expect_writes=1)
run('readback-mismatch-stop',op='i',readback_bad=True,expected=24,expect_writes=1)
report={'passed':True,'cases_passed':len(rows),'scope':__doc__,'installer_sha256':hashlib.sha256(blob).hexdigest(),'CRC_native_vectors_passed':4,'cases':rows,'hardware_programmed':False,'native_NOR_calls_modeled':True}
(R/'evidence/installer-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'PASS {len(rows)} installer cases; physical NOR IO not tested.')
