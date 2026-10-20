#!/usr/bin/env python3
"""Exact MT7626 OEM DMA scheduler callback and mapper; synthetic IO services.
No firmware, DMA engine or RF execution. Private image is not packaged.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn.arm_const import *
R=Path(__file__).resolve().parent
p=R.parent/'wifi-bringup/management-tx/trace-stock-management.py'
ns={'__file__':str(p),'__name__':'library'};exec(compile(p.read_text(),str(p),'exec'),ns)
M=ns['LowerModel'];A,H,STACK,RETURN=[ns[n] for n in ('A','H','STACK','RETURN')]
offsets=[0x601c,0x6010,0x6008,0x6020,0x6024,0x6028,0x6030,0x6034,0x605c,0x60d0,0x60d4,0x60d8,0x60dc,0x60b0,0x60b4]
values=[0x00080001,0xffc80000,0x70068037,0x08000040,0x08000040,0x08000040,0x08000040,0x00400040,0x00200020,0x42104210,0x42104210,0x00050005,0,0x6012345f,0xedcba987]
class Scheduler(M):
 def __init__(self,old=0,qm=0):
  super().__init__();ns['chip_caps'](self);self.old=old;self.qm=qm;self.reads=[];self.writes=[]
  self.cpu.mem_write(H+0x810+0x168,bytes([qm]))
 def code(self,uc,pc,size,o):
  if pc==0x4031bdec:
   a=[uc.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
   assert a[0]==H and a[1]==0x601c and STACK-256<=a[2]<STACK
   self.put(a[2],self.old);self.reads.append(a[1]);self.finish(0)
  elif pc==0x4031be2c:
   a=[uc.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
   assert a[0]==H and a[1] in offsets;self.writes.append(a[1:]);self.finish(0)
  else:super().code(uc,pc,size,o)
rows=[]
m=Scheduler();assert m.get(0x40681eac+0x164)==0x40308c4c
rows.append({'case':'actual-mt7626-chip-ops-binding','callback':'40308c4c','ops_offset':'164','binding_load':'40309e04','binding_store':'40309e08','literal':'4030a338'})
for qm in (0,2,1,3,255):
 for old in ((0,0xffffffff,0xa55aa55a,0x12345678,0x80000000) if qm in (0,2) else (0xa55aa55a,)):
  m=Scheduler(old,qm);assert m.invoke(0x40308c4c,A)==1 and m.reads==[0x601c]
  expected=list(zip(offsets,values));expected[0]=(0x601c,(old&~0x0fff0fff)|0x00080001)
  if qm not in (0,2):expected=expected[:9]
  assert m.writes==[list(x) for x in expected],m.writes
  rows.append({'case':f'actual-OEM-scheduler-qm{qm}-packet{old:08x}','QM':qm,'PKT_MAX_SIZE_before':old,'entry':'40308c4c','return':1,'IO_calls':m.writes})
m=Scheduler();mapped=[]
for off in offsets:
 m.put(STACK+0x80,0x5000a000+off-0x6000)
 assert m.invoke(0x4031bb30,A,STACK+0x80)==1
 assert m.get(STACK+0x80)==off
 mapped.append([0x5000a000+off-0x6000,0x18000000+off])
rows.append({'case':'actual-OEM-mapper-all15-DMASHDL-registers','entry':'4031bb30','mapping':mapped})
assert len(rows)==15
oracle=b''.join(struct.pack('<II',0x18000000+o,v) for o,v in zip(offsets,values))
(R/'stock-scheduler-oracle.bin').write_bytes(oracle)
vectors=[]
for row in rows:
 if 'IO_calls' in row and row['QM'] in (0,2):
  vectors.append(struct.pack('<III',row['QM'],row['PKT_MAX_SIZE_before'],len(row['IO_calls']))+
                 b''.join(struct.pack('<II',0x18000000+a,v) for a,v in row['IO_calls']))
(R/'stock-scheduler-vectors.bin').write_bytes(b''.join(vectors))
report={'passed':True,'cases_passed':len(rows),'OEM_image_sha256':'efdf45c9767bad9b30c93383ee2f5b99a38f5bc2441064e327b026097030fd95','verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'oracle_sha256':hashlib.sha256(oracle).hexdigest(),'callback':'40308c4c','cases':rows,'hardware_DMA_firmware_RF_emulated':False,'IO_services_synthetic':True,'writes_are_configuration_not_packet_completion':True,'profile':'Exact OEM generic-QM0/2, including skip group3,64/2048 group quotas,64 group5 and32 group15; do not copy the differing neighbor-chip loop.'}
(R/'evidence/stock-scheduler-result.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS:15 actual OEM scheduler cases; binding, QM branches, RMW and15physical mappings verified. Hardware IO is synthetic.')
