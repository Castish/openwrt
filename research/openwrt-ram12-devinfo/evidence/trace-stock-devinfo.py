#!/usr/bin/env python3
"""Execute exact OEM MT7626 DEVINFO builder/header, binding and callbacks.
Synthetic MAC, OS/send/completion services and response events. No MCU/RF.
Own analysis code: SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
    UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R10,
    UC_ARM_REG_PC,UC_ARM_REG_R11)
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'firmware-download/trace-stock-download.py'
if not BASE.exists():BASE=ROOT/'trace-stock-download.py'
ns={'__file__':str(BASE)}
exec(compile(BASE.read_text().split('\ncases=[]')[0],str(BASE),'exec'),ns)
Model=ns['Model'];A,H,MSG,SKB,DATA,OUT,STACK=(ns[x] for x in ('A','H','MSG','SKB','DATA','OUT','STACK'))
MAC=0x41c1a000;PUBLIC_MAC=bytes.fromhex('525400123456')

class DevModel(Model):
 def __init__(self):
  super().__init__();self.logs=[];self.cpu.mem_write(MAC,PUBLIC_MAC)
  self.put(H+0xb80+0x24,0x402a3634)
 def code(self,uc,pc,size,opaque):
  r0,r1,r2,r3=[uc.reg_read(x) for x in ns['REGS']]
  if pc==0x4033c0b8:
   assert r2==6 and 0x41e00000<=r0<r0+6<=0x41e10000 and r1==MAC
   uc.mem_write(r0,bytes(uc.mem_read(r1,6)));self.finish(r0)
  elif pc==0x402618d4:
   super().code(uc,0x402aaf44,size,opaque)
   self.calls[-1]['attributes_hex']=bytes(uc.mem_read(MSG,24)).hex()
  elif pc==0x4033b7cc:
   self.logs.append((r0,r1,r2,r3));self.finish(0)
  else:super().code(uc,pc,size,opaque)

cases=[];packets=[]
for own,band,active,features,seq in ((0,0,1,1,14),(0,0,0,1,15),(2,1,1,1,1),(0,0,1,0,5),(0,0,1,3,6)):
 m=DevModel();m.put(STACK,active);m.put(STACK+4,features)
 assert m.invoke(0x402edd44,A,own,MAC,band)==0 and len(m.calls)==1
 call=m.calls[0];body=bytes.fromhex(call['body_hex'])
 # The exact TPOS header has zero second byte even for band1. The band is
 # carried in the active TLV; do not import a newer SDK's header field.
 expected=struct.pack('<BBHB3x',own,0,features&1,1)
 if features&1:expected+=struct.pack('<HHBB',0,12,active,band)+PUBLIC_MAC
 assert body==expected and call['cid']==0xed and call['callback']=='0x402ecc4c'
 assert int.from_bytes(bytes.fromhex(call['attributes_hex'])[6:8],'little')==16
 m.cpu.mem_write(MSG+22,bytes([seq]));m.invoke(0x4026249c,MSG,SKB)
 packet=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)))
 assert len(packet)==64+len(body) and packet[38]==0 and packet[41]==0x2a and packet[43]==1
 packets.append(dict(call,name=f'devinfo-{own}-{band}-{active}-{features}-seq{seq}',packet_hex=packet.hex(),sequence=seq))
 cases.append({'case':f'actual-builder-header-{own}-{band}-{active}-{features}','packet_bytes':len(packet),'response_body_bytes':16})

# Execute the actual EEPROM-MAC assembly. Only the lower word-read service
# is synthetic; address offsets and byte assembly are original instructions.
m=DevModel();word_reads=[];m.cpu.reg_write(UC_ARM_REG_R4,A)
m.cpu.reg_write(UC_ARM_REG_R11,STACK+0x80)
def source_mac(uc,pc,size,opaque):
 if pc==0x402aaf8c:
  off=uc.reg_read(UC_ARM_REG_R1);dst=uc.reg_read(UC_ARM_REG_R2)
  assert uc.reg_read(UC_ARM_REG_R0)==A and off in (4,6,8)
  uc.mem_write(dst,PUBLIC_MAC[off-4:off-2]);word_reads.append(off);m.finish(0)
 elif pc==0x402e53d4:uc.reg_write(UC_ARM_REG_PC,ns['RETURN'])
m.cpu.hook_add(UC_HOOK_CODE,source_mac);m.invoke(0x402e5350)
assert word_reads==[4,6,8] and bytes(m.cpu.mem_read(A+0x1e2000+0x215,6))==PUBLIC_MAC
cases.append({'case':'actual-EEPROM-MAC-word-offsets-and-assembly','EEPROM_offsets':word_reads,'output_bytes':6,'word_read_service_synthetic':True})

# Execute the board's actual function-pointer assignment and public wrapper.
m=DevModel()
def binding(uc,pc,size,opaque):
 if pc==0x40309f00:uc.reg_write(UC_ARM_REG_PC,ns['RETURN'])
m.put(H+0xb80+0x24,0)
m.cpu.hook_add(UC_HOOK_CODE,binding);m.cpu.reg_write(UC_ARM_REG_R4,H+0xb80)
m.invoke(0x40309ef8)
assert m.get(H+0xb80+0x24)==0x402a3634
cases.append({'case':'actual-MT7626-archops-binding','offset':'0x24','wrapper':'0x402a3634'})
for active in (0,1):
 m=DevModel();m.put(STACK,active);m.put(STACK+4,1)
 assert m.invoke(0x4029f878,A,0,MAC,0)==0 and len(m.calls)==1
 assert bytes.fromhex(m.calls[0]['body_hex'])==struct.pack('<BBHB3xHHBB',0,0,1,1,0,12,active,0)+PUBLIC_MAC
 cases.append({'case':f'actual-AsicDevInfoUpdate-wrapper-{active}','active':active})

for extension in (0,0x2a):
 for status in (0,1,0x80000000):
  m=DevModel();m.put(SKB+12,DATA);m.put(MSG+16,0x402ecc4c)
  m.cpu.mem_write(MSG+6,struct.pack('<H',16))
  body=struct.pack('<B3xIBxH4x',0x2a,status,0,1)
  event=struct.pack('<HHBBBBB3x',28,0xe000,0xed,14,0,0,extension)+body
  m.cpu.mem_write(DATA,event);seen=[]
  def dispatch(uc,pc,size,opaque):
   if pc==0x402ecc4c:seen.append((uc.reg_read(UC_ARM_REG_R1),uc.reg_read(UC_ARM_REG_R2)))
   if pc==0x40264120:uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,ns['RETURN'])
  m.cpu.hook_add(UC_HOOK_CODE,dispatch)
  for reg,value in ((UC_ARM_REG_R5,MSG),(UC_ARM_REG_R6,DATA),(UC_ARM_REG_R10,SKB)):m.cpu.reg_write(reg,value)
  m.invoke(0x402637b4)
  assert seen==[(DATA+12,16)] and len(m.logs)==(1 if status else 0)
  cases.append({'case':f'actual-response-dispatch-{extension:02x}-status{status:08x}','status_offset':4,'response_body_bytes':16,'surrounding_OS_completion_skipped':True})

# Execute the real wait-selector instructions, stopping at the synthetic OS
# millisecond conversion. Zero attrs.wait uses6000; explicit60000 is retained.
for supplied,expected in ((0,6000),(60000,60000)):
 m=DevModel();m.cpu.mem_write(MSG+8,struct.pack('<H',supplied));m.cpu.reg_write(UC_ARM_REG_R4,MSG);waits=[]
 def wait_selector(uc,pc,size,opaque):
  if pc==0x4033da98:
   waits.append(uc.reg_read(UC_ARM_REG_R0));uc.reg_write(UC_ARM_REG_PC,ns['RETURN'])
 m.cpu.hook_add(UC_HOOK_CODE,wait_selector);m.invoke(0x40261b80)
 assert waits==[expected]
 cases.append({'case':f'actual-OEM-wait-default-{supplied}','selected_wait_ms':expected,'OS_conversion_and_wait_not_executed':True})

m=DevModel();m.alloc_fail=True;m.put(STACK,1);m.put(STACK+4,1)
assert m.invoke(0x402edd44,A,0,MAC,0)==3 and not m.calls
cases.append({'case':'actual-allocation-failure-no-send'})
report={'scope':__doc__,'source_sha256':ns['SHA'],'cases_passed':len(cases),'cases':cases,'packets':packets,
 'public_synthetic_MAC_hex':PUBLIC_MAC.hex(),'builder':'0x402edd44','ASIC_wrapper':'0x4029f878','board_wrapper':'0x402a3634','callback':'0x402ecc4c',
 'command_extension':'2a','expected_event_body_bytes':16,'limits':['No private MAC or EEPROM included','No MCU/RF/OS/physical transport execution','Band0/OwnMac0 is the proposed narrow experiment; other encoded arguments are synthetic model cases only','OEM callback only logs status; Linux additionally validates echo/OwnMac/count and bounds']}
(ROOT/'stock-devinfo-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'packet_bytes':[len(bytes.fromhex(x['packet_hex'])) for x in packets],'hardware_tested':False}))
