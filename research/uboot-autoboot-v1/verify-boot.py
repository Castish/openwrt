#!/usr/bin/env python3
"""Execute actual wrapper/runner/native go+jmpaddr ARM with modeled TFTP/cache.
Original stock uImage is decompressed with Python LZMA for the native jmpaddr
service. Its transfer overwrites the wrapper. Stock OS entry is observed,
not executed. No hardware networking, NOR writes or cache coherency emulated.
"""
from pathlib import Path
import hashlib,json,lzma,struct,zlib
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ
from unicorn.arm_const import *
R=Path(__file__).resolve().parent
oem=(R.parent/'uboot-script-research/factory-uboot-private.bin').read_bytes()
assert hashlib.sha256(oem).hexdigest()=='e333ac5679f4e1e76906caee06518b16a424da8e64a660f3d924e2dcff05c9ad'
stock=(R.parent/'flash-full-20261017/installed/components/normal-uboot.uImage').read_bytes()
assert len(stock)==64370 and zlib.crc32(stock)==0x969b0bf3
boot=(R/'c80-autoboot.bin').read_bytes();runner=(R/'c80-script-runner.bin').read_bytes();probe=(R/'c80-ram-probe.bin').read_bytes()
script=f'C80SCRIPT1\nload 40270000 c80-ram-probe.bin {len(probe):x} {zlib.crc32(probe):08x}\ngo 40270000\nend\n'.encode()
profile=json.loads((R/'loader-profile.json').read_text())
cases=[]
def run(name,*,loader=0x41f7d000,entry_mode='go',address=0x41c00000,caller=None,
        gd=0x41e7bf2c,sp=0x41e7afd8,midr=0x410fc073,cpsr=0x600001d3,
        fallback='primary',manifest=script,files=None,tftp_fail=None,
        corrupt_profile=None,set_fail=None,bad_env=None,corrupt_runner=False,
        stock_returns=False,expected='stock'):
 cpu=Uc(UC_ARCH_ARM,UC_MODE_ARM);cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
 cpu.mem_map(0x40000000,0x2000000);cpu.mem_write(address,boot);cpu.mem_write(loader,oem)
 # Actual U-Boot relocation adjusts these command data pointers. Native
 # PC-relative go/jmpaddr code is used without modifying instructions.
 for c in profile['commands']+[{'entry_offset':'0x29f94','name_offset':'0x2383b','function_offset':'0x2650','name':'jmpaddr','maxargs':8,'repeatable':1}]:
  off,txt,fn=[int(c[k],16) for k in ('entry_offset','name_offset','function_offset')]
  cpu.mem_write(loader+off,struct.pack('<5I',loader+txt,c['maxargs'],c['repeatable'],loader+fn,0))
 if corrupt_profile is not None:
  at=loader+corrupt_profile;cpu.mem_write(at,bytes([cpu.mem_read(at,1)[0]^1]))
 flash=bytearray(0x400000)
 if fallback=='primary':flash[0x25080:0x25080+len(stock)]=stock
 elif fallback=='saved':flash[0x3d0000:0x3d0000+len(stock)]=stock
 elif fallback=='corrupt':flash[0x25080:0x25080+len(stock)]=stock;flash[0x250c0]^=1
 elif fallback!='none':raise AssertionError(fallback)
 cpu.mem_map(0x30000000,0x400000);cpu.mem_write(0x30000000,bytes(flash));cpu.mem_protect(0x30000000,0x400000,UC_PROT_READ)
 environment={};transfers={'c80-start.txt':manifest,'c80-ram-probe.bin':probe} if files is None else {'c80-start.txt':manifest,**files}
 out=bytearray();calls=[];cache=[];decompressed=[];probe_runs=0;returned=False;stock_entered=False;injected=False
 caller=caller if caller is not None else loader+(0x2774 if entry_mode=='go' else 0x2700)
 preserved=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
 saved={reg:0x45000000+i*0x100 for i,reg in enumerate(preserved)};saved[UC_ARM_REG_R9]=gd
 cpu.reg_write(UC_ARM_REG_CPSR,cpsr)
 for reg,v in saved.items():cpu.reg_write(reg,v)
 cpu.reg_write(UC_ARM_REG_SP,sp);cpu.reg_write(UC_ARM_REG_LR,caller)
 def string(p,limit=200):
  b=bytes(cpu.mem_read(p,limit));assert b'\0' in b,hex(p);return b.split(b'\0',1)[0].decode()
 def finish(v):cpu.reg_write(UC_ARM_REG_R0,v&0xffffffff);cpu.reg_write(UC_ARM_REG_PC,cpu.reg_read(UC_ARM_REG_LR))
 def rd(uc,off,size,_):assert off==0x14 and size==4;return 0x20
 def wr(uc,off,size,v,_):assert off==0 and size==4;out.append(v&255)
 cpu.mmio_map(0x11002000,4096,rd,None,wr,None)
 def code(uc,pc,size,_):
  nonlocal probe_runs,returned,stock_entered
  if pc==caller and uc.reg_read(UC_ARM_REG_SP)==sp:
   returned=True;uc.emu_stop();return
  if pc==0x41c00000 and decompressed:
   stock_entered=True
   if stock_returns:finish(0)
   else:uc.emu_stop()
   return
  if address<=pc<address+len(boot) or 0x40280000<=pc<0x40280000+len(runner):
   insn=struct.unpack('<I',uc.mem_read(pc,4))[0]
   if insn&0xffff0fff==0xee100f10:
    reg=(insn>>12)&15;uc.reg_write(UC_ARM_REG_R0+reg,midr);uc.reg_write(UC_ARM_REG_PC,pc+4)
   return
  if pc==0x40270000 and 'GO 40270000' in out.decode(errors='replace'):probe_runs+=1
  off=pc-loader
  if off==0x19980:
   assert uc.reg_read(UC_ARM_REG_R2)==16;finish(int(string(uc.reg_read(UC_ARM_REG_R0)),16));return
  if off in (0x4b7c,0x4b4c):finish(0);return
  if off==0x18d2c:
   a,b,n=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
   assert n==64;uc.mem_write(a,bytes(uc.mem_read(b,n)));finish(a);return
  if off==0x11058:
   dst,outptr,source,n=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
   assert n==len(stock)-64 and bytes(uc.mem_read(source,n))==stock[64:]
   plain=lzma.decompress(stock[64:],format=lzma.FORMAT_ALONE);assert dst==0x41c00000
   uc.mem_write(dst,plain);uc.mem_write(outptr,struct.pack('<I',len(plain)));decompressed.append(source-64);finish(0);return
  if off==0x0508:
   a,n=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1)];cache.append([a,n]);finish(0);return
  if off==0x4624:
   key=string(uc.reg_read(UC_ARM_REG_R0));v=environment.get(key)
   if v is None:finish(0);return
   if key==bad_env:v='WRONG'
   ptr=loader+0x74000;uc.mem_write(ptr,v.encode()+b'\0');finish(ptr);return
  if off not in (0x41e0,0x37ec,0x272c,0x2650):return
  assert uc.reg_read(UC_ARM_REG_R9)==gd
  if off==0x2650:
   assert uc.reg_read(UC_ARM_REG_SP)==sp,'tail call did not release wrapper frame'
   for reg,v in saved.items():assert uc.reg_read(reg)==v,'tail call lost caller register'
  n=uc.reg_read(UC_ARM_REG_R2);a=uc.reg_read(UC_ARM_REG_R3)
  args=[string(struct.unpack('<I',uc.mem_read(a+4*i,4))[0]) for i in range(n)]
  calls.append(args)
  expected_table={0x41e0:0x29ff8,0x37ec:0x2a020,0x272c:0x29f58,0x2650:0x29f94}[off]
  assert uc.reg_read(UC_ARM_REG_R0)==loader+expected_table and uc.reg_read(UC_ARM_REG_R1)==0
  if off==0x41e0:
   assert args[0]=='setenv' and n==3
   if args[1]==set_fail:finish(1)
   else:environment[args[1]]=args[2];finish(0)
  elif off==0x37ec:
   assert environment['autostart']=='no' and environment['netretry']=='no' and environment['tftptimeout']=='1000'
   assert environment['ipaddr']=='192.168.0.1' and environment['serverip']=='192.168.0.3'
   if args[2]==tftp_fail or transfers.get(args[2]) is None:finish(1);return
   data=transfers[args[2]];uc.mem_write(int(args[1],16),data);environment['filesize']=f'{len(data):x}';finish(0)
  # Native go and jmpaddr execute their actual ARM instructions.
 def write(uc,access,a,n,v,_):
  nonlocal injected
  assert not 0x30000000<=a<0x30400000,'NOR write attempted'
  if corrupt_runner and not injected and a<=0x40280000+len(runner)-1<a+n:
   injected=True;uc.mem_write(0x40280000,b'\xff')
 cpu.hook_add(UC_HOOK_CODE,code);cpu.hook_add(UC_HOOK_MEM_WRITE,write)
 cpu.emu_start(address,0xffffffff,timeout=60_000_000,count=20_000_000)
 assert cpu.reg_read(UC_ARM_REG_SP)==sp if returned else stock_entered,(name,hex(cpu.reg_read(UC_ARM_REG_PC)),out)
 # At stock entry native jmpaddr owns a live frame and may use r4/r5. The
 # wrapper's restored caller state is checked at the tail-call boundary;
 # returned paths additionally must restore it all the way to the caller.
 assert cpu.reg_read(UC_ARM_REG_R9)==gd
 if returned:
  for reg,v in saved.items():assert cpu.reg_read(reg)==v,(name,reg,hex(cpu.reg_read(reg)),hex(v))
 if expected=='stock':
  assert stock_entered and decompressed==[0x30025080 if fallback=='primary' else 0x303d0000],(name,calls,out)
  assert bytes(cpu.mem_read(0x41c00000,4))!=boot[:4],'fallback must overwrite wrapper'
 elif isinstance(expected,int):assert returned and cpu.reg_read(UC_ARM_REG_R0)==expected and not decompressed,(name,out)
 if stock_returns:assert returned
 should_probe=expected=='stock' and manifest==script and files is None and not tftp_fail and not corrupt_runner and not set_fail and not bad_env
 assert probe_runs==int(should_probe),(name,probe_runs,out.decode(errors='replace'))
 row={'case':name,'passed':True,'entry_mode':entry_mode,'loader_base':hex(loader),'fallback':fallback,'stock_entry_observed':stock_entered,'stock_return_without_wrapper_execution':stock_returns and returned,'probe_runs':probe_runs,'console':out.decode(errors='replace'),'calls':calls,'cache_services':cache,'NOR_writes':0}
 cases.append(row);print('PASS '+name,flush=True)
 return row
run('native-go-runner-real-probe-and-stock-overwrite')
run('native-jmpaddr-entry-real-probe-and-stock-overwrite',entry_mode='jmpaddr')
run('link-base-native-entry',loader=0x41e00000,entry_mode='jmpaddr')
run('verified-saved-stock-fallback',fallback='saved')
run('stock-return-tailcall-safe',stock_returns=True)
run('missing-script',manifest=None)
run('payload-TFTP-failure',tftp_fail='c80-ram-probe.bin')
run('CRC-failure',files={'c80-ram-probe.bin':probe[:-1]+bytes([probe[-1]^1])})
run('bad-script-no-payload-entry',manifest=b'not-a-script\n')
run('empty-scenario-falls-back',manifest=b'C80SCRIPT1\nend\n')
run('missing-fallback-refuses',fallback='none',expected=12)
run('corrupt-fallback-refuses',fallback='corrupt',expected=12)
run('runner-copy-corruption-falls-back',corrupt_runner=True)
for key in ['autostart','ipaddr','serverip','netretry','tftptimeout']:
 run('setenv-failure-'+key,set_fail=key)
 run('setenv-readback-'+key,bad_env=key)
for off in [0x271c,0x272c,0x37ec,0x41e0,0x4624,0x2650,0x508,0x29f58,0x29ff8,0x29f94,0x2a020]:
 run(f'factory-profile-refusal-{off:x}',corrupt_profile=off,expected=11)
run('wrong-entry-address',address=0x41c10000,expected=2)
run('wrong-caller',caller=0x41f7f778,expected=10)
run('wrong-GD',gd=0x41000000,expected=10)
run('wrong-stack',sp=0x41000000,expected=10)
run('wrong-CPU',midr=0x410fc075,expected=10)
run('wrong-mode',cpsr=0x600000d3,expected=10)
result={'passed':True,'cases_passed':len(cases),'cases':cases,'scope':__doc__,'hardware_tested':False,'wrapper_sha256':hashlib.sha256(boot).hexdigest(),'runner_sha256':hashlib.sha256(runner).hexdigest(),'native_oem_go_and_jmpaddr_executed':True,'original_stock_image_not_packaged':True,'NOR_writes':0}
(R/'evidence/boot-verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(f'PASS {len(cases)} actual ARM boot-wrapper cases; hardware networking/flash/cache unmodeled.')
