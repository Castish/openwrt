#!/usr/bin/env python3
"""Reproduce the symptom with an explicit stale-code/fresh-data model.

This is a constructed split-view model, not a hardware cache simulation or
proof of the installed bootloader's cache state. Does not alter either payload.
"""
from pathlib import Path
import hashlib,json
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_CPSR,UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_R0
root=Path(__file__).resolve().parent
old=(root/'../ram-probe/c80-ram-probe.bin').read_bytes()
new=(root/'c80-readonly-diag.bin').read_bytes()
# First probe's function occupies 0x00..0x47; its literal is at 0x48.
# Preserve its instruction view and replace the literal/message with new data.
assert old[0x48:0x4c]==bytes.fromhex('00 20 00 11')
model=old[:0x48]+new[0x48:]
bad_uart=int.from_bytes(new[0x48:0x4c],'little')
assert bad_uart==0xee110f10
address=0x40200000;stop=0x41f00000
cpu=Uc(UC_ARCH_ARM,UC_MODE_ARM)
cpu.mem_map(address,4096);cpu.mem_write(address,model)
cpu.mem_protect(address,4096,UC_PROT_READ|UC_PROT_EXEC)
cpu.mem_map(stop,4096,UC_PROT_READ|UC_PROT_EXEC)
reads=0
output=[]
def read_wrong_uart(uc,offset,size,data):
 global reads
 assert offset==(bad_uart&0xfff)+0x14 and size==4
 reads+=1
 return 0
def unexpected_write(uc,offset,size,value,data):
 output.append(value)
cpu.mmio_map(bad_uart&~0xfff,4096,read_wrong_uart,None,unexpected_write,None)
cpu.reg_write(UC_ARM_REG_CPSR,0xd3);cpu.reg_write(UC_ARM_REG_LR,stop)
cpu.emu_start(address,stop,count=8_000_000)
assert cpu.reg_read(UC_ARM_REG_PC)==stop
assert cpu.reg_read(UC_ARM_REG_R0)==1 and not output and reads==1_000_000
report={'scope':'Constructed stale first-probe instruction view plus fresh diagnostic literal/data; not proof of hardware cache behavior','old_payload_sha256':hashlib.sha256(old).hexdigest(),'new_payload_sha256':hashlib.sha256(new).hexdigest(),'old_uart_literal_offset':'0x48','value_at_same_offset_in_new_payload':hex(bad_uart),'modeled_wrong_uart_status_address':hex(bad_uart+0x14),'modeled_result':{'return_code':1,'output_bytes':0,'polls':reads},'hardware_root_cause_status':'hypothesis pending readback/new-address test'}
(root/'stale-instructions-model.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
