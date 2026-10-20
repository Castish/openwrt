#!/usr/bin/env python3
"""Execute patched ORIGINAL U-Boot vector+embedded code and native factory go.
Networking is modeled; real RAM probe executes. The real RAM31 manifest is
parsed and its handoff entry reached, with only its large kernel CRC accelerated. Stock reset entry is reached,
not a full board power-on. No hardware NOR, Ethernet or cache validation.
"""
from pathlib import Path
import hashlib,json,struct,zlib
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ
from unicorn.arm_const import *
R=Path(__file__).resolve().parent
stock=(R.parent/'flash-full-20261017/installed/components/normal-uboot.bin').read_bytes()
raw=(R/'private/normal-uboot-patched.bin').read_bytes()
assert raw[4:len(stock)]==stock[4:] and raw[:4]!=stock[:4]
oem=(R.parent/'uboot-script-research/factory-uboot-private.bin').read_bytes()
probe=(R.parent/'ram-probe/c80-ram-probe.bin').read_bytes()
script=f'C80SCRIPT1\nload 40270000 c80-ram-probe.bin {len(probe):x} {zlib.crc32(probe):08x}\ngo 40270000\nend\n'.encode()
CRC_ADDRESS=int(next(x.split()[0] for x in (R/'symbols.txt').read_text().splitlines() if x.endswith(' crc32')),16)
commands=[(0x29f58,0x23858,8,1,0x272c),(0x29ff8,0x23fc5,8,0,0x41e0),(0x2a020,0x23d2b,3,1,0x37ec)]
rows=[]
def run(name,*,base=0x41f7d000,manifest=script,files=None,tftp_fail=None,
 set_fail=None,bad_env=None,corrupt=None,gd=0x41e7bf2c,sp=0x41e7af80,
 caller=None,midr=0x410fc073,cpsr=0x600001d3,uart_ready=True,app_stays=False,expected_probe=0,application_pc=0x40270000,large_crc=False):
 c=Uc(UC_ARCH_ARM,UC_MODE_ARM);c.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
 c.mem_map(0x40000000,0x2000000);c.mem_write(0x41c00000,raw);c.mem_write(base,oem)
 for off,txt,mx,rp,fn in commands:c.mem_write(base+off,struct.pack('<5I',base+txt,mx,rp,base+fn,0))
 if corrupt is not None:c.mem_write(base+corrupt,bytes([c.mem_read(base+corrupt,1)[0]^1]))
 flash=(R.parent/'flash-full-20261017/c80-full-flash.bin').read_bytes()
 c.mem_map(0x30000000,0x400000);c.mem_write(0x30000000,flash);c.mem_protect(0x30000000,0x400000,UC_PROT_READ)
 c.reg_write(UC_ARM_REG_CPSR,cpsr)
 regs=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_LR]
 saved={x:0x45000000+256*i for i,x in enumerate(regs)}
 saved[UC_ARM_REG_R9]=gd;saved[UC_ARM_REG_LR]=base+0x2700 if caller is None else caller
 for reg,value in saved.items():c.reg_write(reg,value)
 c.reg_write(UC_ARM_REG_SP,sp)
 env={};out=bytearray();calls=[];probe_runs=0;fallback=False;application=False
 transfers={'c80-start.txt':manifest,'c80-ram-probe.bin':probe}
 if files is not None:transfers.update(files)
 def string(p):
  b=bytes(c.mem_read(p,128));assert b'\0' in b;return b.split(b'\0',1)[0].decode()
 def finish(v):c.reg_write(UC_ARM_REG_R0,v&0xffffffff);c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
 def rd(c,a,n,_):assert a==0x14 and n==4;return 0x20 if uart_ready else 0
 def wr(c,a,n,v,_):assert a==0 and n==4;out.append(v&255)
 c.mmio_map(0x11002000,4096,rd,None,wr,None)
 def hook(c,pc,n,_):
  nonlocal probe_runs,fallback,application
  if pc==0x41c00044:
   fallback=True
   assert c.reg_read(UC_ARM_REG_SP)==sp
   for reg,v in saved.items():assert c.reg_read(reg)==v,(name,reg,hex(c.reg_read(reg)),hex(v))
   c.emu_stop();return
  if pc==CRC_ADDRESS and large_crc and c.reg_read(UC_ARM_REG_R1)>=0x100000:
   address=c.reg_read(UC_ARM_REG_R0);length=c.reg_read(UC_ARM_REG_R1)
   finish(zlib.crc32(bytes(c.mem_read(address,length))));return
  if 0x41c2f850<=pc<0x41c00000+len(raw):
   insn=struct.unpack('<I',c.mem_read(pc,4))[0]
   if insn&0xffff0fff==0xee100f10:
    reg=(insn>>12)&15;c.reg_write(UC_ARM_REG_R0+reg,midr);c.reg_write(UC_ARM_REG_PC,pc+4)
   return
  if pc==application_pc:
   probe_runs+=1
   if app_stays:application=True;c.emu_stop();return
  off=pc-base
  if off==0x19980:finish(int(string(c.reg_read(UC_ARM_REG_R0)),16));return
  if off in (0x4b7c,0x4b4c):finish(0);return
  if off==0x4624:
   key=string(c.reg_read(UC_ARM_REG_R0));v=env.get(key)
   if v is None:finish(0);return
   if key==bad_env:v='WRONG'
   ptr=base+0x74000;c.mem_write(ptr,v.encode()+b'\0');finish(ptr);return
  if off not in (0x41e0,0x37ec,0x272c):return
  assert c.reg_read(UC_ARM_REG_R9)==gd
  argc=c.reg_read(UC_ARM_REG_R2);argv=c.reg_read(UC_ARM_REG_R3)
  args=[string(struct.unpack('<I',c.mem_read(argv+4*i,4))[0]) for i in range(argc)];calls.append(args)
  table={0x41e0:0x29ff8,0x37ec:0x2a020,0x272c:0x29f58}[off]
  assert c.reg_read(UC_ARM_REG_R0)==base+table and c.reg_read(UC_ARM_REG_R1)==0
  if off==0x41e0:
   if args[1]==set_fail:finish(1)
   else:env[args[1]]=args[2];finish(0)
  elif off==0x37ec:
   assert env=={**env,'autostart':'no','netretry':'no','tftptimeout':'1000','ipaddr':'192.168.0.1','serverip':'192.168.0.3'}
   data=transfers.get(args[2])
   if data is None or args[2]==tftp_fail:finish(1);return
   c.mem_write(int(args[1],16),data);env['filesize']=f'{len(data):x}';finish(0)
  # Actual native do_go executes. No separate runner or wrapper is mapped.
 def write(c,access,a,n,v,_):assert not 0x30000000<=a<0x30400000,'NOR write'
 c.hook_add(UC_HOOK_CODE,hook);c.hook_add(UC_HOOK_MEM_WRITE,write)
 c.emu_start(0x41c00000,0xffffffff,timeout=20_000_000,count=15_000_000)
 assert application if app_stays else fallback,(name,hex(c.reg_read(UC_ARM_REG_PC)),out)
 assert probe_runs==expected_probe,(name,probe_runs,out)
 if expected_probe and not app_stays:assert b'C80 RAM probe v1: ARM code executed' in out
 assert bytes(c.mem_read(0x41c00004,len(stock)-4))==stock[4:]
 rows.append({'case':name,'passed':True,'probe_entries':probe_runs,'original_stock_reset_reached':fallback,'application_entered':application,'factory_base':hex(base),'native_commands':calls,'console':out.decode(errors='replace'),'flash_writes':0,'large_payload_CRC_accelerated':large_crc})
 print('PASS '+name,flush=True)
run('actual-patched-vector-embedded-parser-native-go-real-probe',expected_probe=1)
run('automatic-nonreturning-application',app_stays=True,expected_probe=1)
run('factory-link-base',base=0x41e00000,expected_probe=1)
run('file-missing-stock-reset',manifest=None)
run('payload-missing-stock-reset',tftp_fail='c80-ram-probe.bin')
run('CRC-error-no-entry',files={'c80-ram-probe.bin':probe[:-1]+bytes([probe[-1]^1])})
run('length-error-no-entry',files={'c80-ram-probe.bin':probe+b'x'})
for name,data in [
 ('bad-header',b'bad\n'),('empty-file',b''),('large-file',b'#'*4097),
 ('missing-end',b'C80SCRIPT1\n'),('empty-plan',b'C80SCRIPT1\nend\n'),
 ('go-not-loaded',b'C80SCRIPT1\ngo 40270000\nend\n'),
 ('flash-address',b'C80SCRIPT1\nload 30025000 x.bin 4 0\nend\n'),
 ('loader-overlap',b'C80SCRIPT1\nload 41c00000 x.bin 4 0\nend\n'),
 ('script-overlap',b'C80SCRIPT1\nload 40a00000 x.bin 4 0\nend\n'),
 ('overflow',b'C80SCRIPT1\nload 40200000 x.bin ffffffff 0\nend\n'),
 ('trailing-command',b'C80SCRIPT1\nend\ngo 40270000\n'),
 ('malformed-go',script.replace(b'go 40270000',b'go 40270000 8c 2ffcedfc'))]:run(name,manifest=data)
ram31files={name:(R/name).read_bytes() for name in ['c80-openwrt-ram31-scheduler-zImage','c80-openwrt-ram31-scheduler.dtb','c80-openwrt-ram31-handoff.bin']}
run('real-RAM31-manifest-three-files-to-real-handoff-entry',manifest=(R/'c80-start.txt').read_bytes(),files=ram31files,app_stays=True,expected_probe=1,application_pc=0x40e00000,large_crc=True)
for key in ['autostart','ipaddr','serverip','netretry','tftptimeout']:
 run('setenv-failure-'+key,set_fail=key);run('setenv-readback-'+key,bad_env=key)
for off in [0x271c,0x272c,0x37ec,0x41e0,0x4624,0x29f58,0x29ff8,0x2a020]:run(f'bad-factory-profile-{off:x}',corrupt=off)
run('unexpected-caller-stock-reset',caller=0x41f7f778)
run('invalid-GD-stock-reset',gd=0x41000000)
run('invalid-stack-stock-reset',sp=0x41000000)
run('wrong-CPU-stock-reset',midr=0x410fc075)
run('wrong-mode-stock-reset',cpsr=0x600000d3)
run('UART-TX-stuck-stock-reset',uart_ready=False)
report={'passed':True,'cases_passed':len(rows),'scope':__doc__,'patched_raw_sha256':hashlib.sha256(raw).hexdigest(),'standalone_runner_used':False,'original_OEM_prefix_preserved_except_reset_branch':True,'cases':rows,'hardware_tested':False}
(R/'evidence/boot-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'PASS {len(rows)} native U-Boot patched-entry cases.')
