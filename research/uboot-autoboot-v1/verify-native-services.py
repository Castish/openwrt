#!/usr/bin/env python3
"""Actual OEM TFTP timeout/retry and NOR erase-mode selection; synthetic IO.
No Ethernet, physical timers, SPI commands or flash programming are performed.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import *
R=Path(__file__).resolve().parent;B=0x41e00000
oem=(R.parent/'uboot-script-research/factory-uboot-private.bin').read_bytes()
assert hashlib.sha256(oem).hexdigest()=='e333ac5679f4e1e76906caee06518b16a424da8e64a660f3d924e2dcff05c9ad'
def machine():
 c=Uc(UC_ARCH_ARM,UC_MODE_ARM);c.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
 c.mem_map(0x40000000,0x2000000);c.mem_write(B,oem);c.reg_write(UC_ARM_REG_CPSR,0x600001d3)
 c.reg_write(UC_ARM_REG_R9,0x41ef0000);return c
def put(c,a,v):c.mem_write(a,struct.pack('<I',v))
def get(c,a):return struct.unpack('<I',c.mem_read(a,4))[0]
def string(c,a):return bytes(c.mem_read(a,100)).split(b'\0',1)[0].decode()
def finish(c,v):c.reg_write(UC_ARM_REG_R0,v);c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
def invoke(c,fn,r0=0,r1=0):
 c.reg_write(UC_ARM_REG_SP,0x4101f000);c.reg_write(UC_ARM_REG_LR,0x4101f800)
 c.reg_write(UC_ARM_REG_R0,r0);c.reg_write(UC_ARM_REG_R1,r1)
 c.emu_start(fn,0x4101f800,timeout=5_000_000,count=1_000_000)
 assert c.reg_read(UC_ARM_REG_PC)==0x4101f800
 assert c.reg_read(UC_ARM_REG_SP)==0x4101f000
 return c.reg_read(UC_ARM_REG_R0)
cases=[]
# Execute native TftpStart, with only external OS/net services replaced.
c=machine();timeouts=[];sends=[];halts=[];env_reads=[]
c.mem_write(B+0x5b2c8,b'c80-start.txt\0')
put(c,B+0x5b13c,0x0300a8c0)
def net(c,pc,n,_):
 off=pc-B
 if off==0x4624:
  key=string(c,c.reg_read(UC_ARM_REG_R0));env_reads.append(key)
  value={'tftptimeout':b'1000\0','netretry':b'no\0'}.get(key)
  if value:c.mem_write(0x41010000,value);finish(c,0x41010000)
  else:finish(c,0)
 elif off in (0x4b1c,0x4b4c,0x4b7c):finish(c,0)
 elif off==0x1150:finish(c,0)
 elif off==0x1ad4c:
  c.mem_write(0x41011000,b'mtk_eth\0');finish(c,0x41011000)
 elif off==0x1af70:
  timeouts.append([c.reg_read(UC_ARM_REG_R0),hex(c.reg_read(UC_ARM_REG_R1))]);finish(c,0)
 elif off==0x1af40:finish(c,0)
 elif off==0x1bd7c:sends.append(1);finish(c,0)
 elif off==0x1aac8:halts.append(1);finish(c,0)
c.hook_add(UC_HOOK_CODE,net)
invoke(c,B+0x1c344,3)
assert get(c,B+0x29ef4)==1000 and get(c,B+0x29ee8)==10
assert get(c,B+0x721d8)==0 and timeouts[-1]==[1000,hex(B+0x1c2bc)]
cases.append({'case':'native-TftpStart-timeout1000-limit10','passed':True,'environment_reads':list(env_reads),'scheduled':list(timeouts)})
for i in range(1,12):
 invoke(c,B+0x1c2bc)
 assert get(c,B+0x721d8)==i
 if i<=10:assert len(halts)==0 and timeouts[-1][0]==1000
 else:assert len(halts)==1 and get(c,B+0x5b148)==3 and env_reads[-1]=='netretry'
 cases.append({'case':f'native-TftpTimeout-{i}','passed':True,'count':i,'halts':len(halts),'network_state':get(c,B+0x5b148)})
assert len(sends)==11 # initial RRQ plus10 retries, then native NetStartAgain/no exits.
# Execute the physical build's mtk_nor_erase on every planned4KiB sector.
# Only the final flash-controller callbacks are modeled, never invoked on HW.
plan=json.loads((R/'evidence/flash-plan.json').read_text());assert plan['passed']
for row in plan['sectors']:
 for injected in [0,0x55]:
  c=machine();calls=[];sh,nor,ops=0x41010000,0x41011000,0x41012000
  mode_fn,erase_fn=0x41013000,0x41013004
  put(c,B+0x2a914,sh);put(c,sh,nor);put(c,sh+4,ops);put(c,nor+16,0x400000)
  put(c,ops+0x24,mode_fn);put(c,ops+0x34,erase_fn)
  def flash(c,pc,n,_):
   if pc==mode_fn:
    assert c.reg_read(UC_ARM_REG_R0)==sh
    calls.append(['mode',c.reg_read(UC_ARM_REG_R1)]);finish(c,0)
   elif pc==erase_fn:
    assert c.reg_read(UC_ARM_REG_R0)==sh
    a,n=[c.reg_read(x) for x in [UC_ARM_REG_R1,UC_ARM_REG_R2]]
    calls.append(['erase',a,n]);assert 0x25000<=a<a+n<=0x3e8000
    finish(c,injected)
  c.hook_add(UC_HOOK_CODE,flash);a=int(row['offset'],16)
  assert invoke(c,B+0x63b0,a,4096)==injected
  assert calls==[['mode',0],['erase',a,4096]],calls
  cases.append({'case':f'native-4K-erase-{a:x}-rc{injected:x}','passed':True,'controller_callbacks':calls,'return':injected})
report={'passed':True,'cases_passed':len(cases),'scope':__doc__,'cases':cases,
 'TFTP_timeout_ms':1000,'TFTP_max_retries':10,'initial_request_plus_retries':11,
 'netretry_no_calls_native_halt_and_sets_FAIL':True,'total_wall_time_bound_measured':False,
 'all_planned_erases_4KiB_and_inside_FIRMWARE':True,'NOR_controller_operations_executed':False,
 'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(R/'evidence/native-services-result.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'PASS:{len(cases)} native OEM service cases; TFTP retry stops and all18 sectors use4KiB erase, IO synthetic.')
