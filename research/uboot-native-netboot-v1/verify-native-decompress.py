from pathlib import Path
import struct,lzma,json,hashlib
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import *
r=Path(__file__).resolve().parent;b=(r.parent/'uboot-script-research/factory-uboot-private.bin').read_bytes();data=(r/'c80-uboot-native.uImage').read_bytes()[64:]
c=Uc(UC_ARCH_ARM,UC_MODE_ARM);c.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7);c.mem_map(0x40000000,0x2000000);c.mem_write(0x41e00000,b);c.mem_write(0x41000000,data);alloc=[]
stop=0x4141f800
c.reg_write(UC_ARM_REG_CPSR,0x600001d3);c.reg_write(UC_ARM_REG_SP,0x4141f000);c.reg_write(UC_ARM_REG_LR,stop)
for reg,v in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3],[0x41c00000,0x41410000,0x41000000,len(data)]):c.reg_write(reg,v)
def done(v):c.reg_write(UC_ARM_REG_R0,v);c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
def hook(c,pc,size,_):
 if pc==0x41e053ac:
  n=c.reg_read(UC_ARM_REG_R0);p=0x41800000+sum((x+15)&~15 for x in alloc);alloc.append(n);assert p+n<0x41b00000;done(p)
 elif pc==0x41e0517c:done(0)
 elif pc in [0x41e04b4c,0x41e04b7c]:done(0)
c.hook_add(UC_HOOK_CODE,hook);c.emu_start(0x41e11058,stop,timeout=60_000_000,count=100_000_000)
assert c.reg_read(UC_ARM_REG_PC)==stop
assert c.reg_read(UC_ARM_REG_R0)==0,hex(c.reg_read(UC_ARM_REG_R0))
plain=(r/'private/normal-uboot-patched.bin').read_bytes();actual=bytes(c.mem_read(0x41c00000,len(plain)));assert plain==actual
assert struct.unpack('<I',c.mem_read(0x41410000,4))[0]==len(plain)
report={'passed':True,'actual_native_LZMA_function':'41e11058','decompressed_bytes':len(plain),'malloc_services_synthetic':True,'allocations':alloc,'output_sha256':hashlib.sha256(actual).hexdigest(),'known_LZMA_uncompressed_size_header':True,'hardware_cache_or_boot_not_emulated':True}
(r/'evidence/native-decompress-result.json').write_text(json.dumps(report,indent=2)+'\n');print(report)
