#!/usr/bin/env python3
"""Actual OEM ARM RX descriptor refill, index wrap and CPU-index publisher.
Allocator/unmap/OS locking and coherent/DMA effects synthetic. No MCU/RF.
Own analysis code: SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'mac-init/trace-stock-devinfo.py'
if not BASE.exists():BASE=ROOT/'trace-stock-devinfo.py'
ns={'__file__':str(BASE)};exec(compile(BASE.read_text().split('\ncases=[]')[0],str(BASE),'exec'),ns)
DevModel=ns['DevModel'];A,H,MSG,SKB,DATA,OUT,STACK=(ns[x] for x in ('A','H','MSG','SKB','DATA','OUT','STACK'))
RETURN=ns['ns']['RETURN'];HIF=ns['ns']['HIF']
RINGS=0x41c07000;CELLS=0x41c0a000;DESC=0x41c16000;OLD=0x41c13000;NEW=0x41c14000
class RXModel(DevModel):
 def __init__(self,idx=0,size=64,queue=0,done=True,capacity=1536):
  super().__init__();self.services=[];self.writes=[];self.descriptor_at_publish=None
  self.ring=RINGS+96*queue;self.cell=CELLS+40*idx;self.idx=idx;self.size=size;self.queue=queue;self.capacity=capacity
  self.put(A+0xa7fc4,RINGS);self.put(H+0xb80+0x168,0x402f3d64);self.put(A+0x2ff444,4)
  self.put(A,HIF+0x2000);self.put(HIF+0x2010,1);self.put(HIF+0x7c,0x18000000)
  self.put(self.ring+12,idx);self.put(self.ring+20,CELLS);self.put(self.ring+44,(idx-1)%size);self.put(self.ring+48,0x4408+queue*16)
  self.cpu.mem_write(self.ring+16,struct.pack('<H',size));self.cpu.mem_write(self.ring+38,struct.pack('<H',capacity))
  self.put(self.cell+4,DESC);self.put(self.cell+12,OLD);self.put(self.cell+24,capacity);self.put(self.cell+32,0x41420000)
  self.cpu.mem_write(DESC,struct.pack('<IIII',0x41420000,(0x80000000 if done else 0)|0x40000000|(116<<16),0,0))
  self.invoke(0x402f54ac,H)
  def rd(uc,off,n,opaque):raise AssertionError(('unexpected MMIO read',off,n))
  def wr(uc,off,n,value,opaque):
   assert off==0x408+queue*16 and n==4
   self.writes.append(value);self.descriptor_at_publish=bytes(uc.mem_read(DESC,16)).hex()
  self.cpu.mmio_map(0x18004000,0x1000,rd,None,wr,None)
 def code(self,uc,pc,size,opaque):
  r0,r1,r2,r3=[uc.reg_read(x) for x in ns['ns']['REGS']]
  if pc==0x4033b150:
   assert (r0,r1,r2,r3)==(self.ring,1,0 if self.queue==0 else 2,self.capacity)
   sp=uc.reg_read(UC_ARM_REG_SP);self.put(self.get(sp),0x41c17000);self.put(self.get(sp+4),0x41422000)
   self.services.append('allocate-replacement-buffer');self.finish(NEW)
  elif pc==0x4033b2c0:
   assert (r0,r1,r2,r3)==(A,0x41420000,self.capacity,2)
   self.services.append('unmap-old-buffer');self.finish(0)
  else:super().code(uc,pc,size,opaque)
 def receive(self):return self.invoke(0x402a09ac,A,OUT,OUT+4,self.queue)
 def publish(self):
  def stop(uc,pc,n,o):
   if pc==0x402b2644:uc.reg_write(UC_ARM_REG_PC,RETURN)
  self.cpu.reg_write(UC_ARM_REG_R5,self.ring);self.cpu.reg_write(UC_ARM_REG_R7,A+0x33c000)
  hook=self.cpu.hook_add(UC_HOOK_CODE,stop);self.invoke(0x402b2620);self.cpu.hook_del(hook)
cases=[]
for queue in (0,1):
 for size,indices in ((64,(0,1,58,59,62,63)),(512,(0,58,59,510,511))):
  for idx in indices:
   m=RXModel(idx,size,queue);assert m.receive()==OLD
   want=struct.pack('<4I',0x41422000,0x40000000|(1536<<16),0,0)
   assert bytes(m.cpu.mem_read(DESC,16))==want
   assert m.get(m.ring+12)==(idx+1)%size and m.get(m.ring+44)==idx
   assert int.from_bytes(m.cpu.mem_read(m.ring+40,2),'little')==1
   assert m.get(OUT+4)==1 and m.cpu.mem_read(OUT,1)==b'\x00'
   assert m.services==['allocate-replacement-buffer','unmap-old-buffer'] and not m.writes
   m.publish();assert m.writes==[idx] and m.descriptor_at_publish==want.hex()
   assert int.from_bytes(m.cpu.mem_read(m.ring+40,2),'little')==0
   cases.append({'case':f'actual-refill-publish-q{queue}-size{size}-index{idx}','descriptor_after':want.hex(),'next':(idx+1)%size,'CPU_index_published':idx,'DONE_clear_before_publish':True,'LS0_preserved':True})
for queue in (0,1):
 m=RXModel(queue=queue,done=False);before=bytes(m.cpu.mem_read(DESC,16));assert m.receive()==0 and not m.services
 assert bytes(m.cpu.mem_read(DESC,16))==before and m.get(m.ring+12)==0
 m.publish();assert not m.writes
 cases.append({'case':f'actual-not-DONE-q{queue}-no-refill-no-publish'})
for capacity in (64,1536,3840):
 m=RXModel(capacity=capacity);assert m.receive()==OLD
 assert m.get(DESC+4)==0x40000000|(capacity<<16);m.publish();assert m.writes==[0]
 cases.append({'case':f'actual-capacity-{capacity}','capacity_restored':capacity})
m=RXModel();m.cpu.reg_write(UC_ARM_REG_R4,H+0xb80)
def bind(uc,pc,n,o):
 if pc==0x4030a0e0:uc.reg_write(UC_ARM_REG_PC,RETURN)
m.cpu.hook_add(UC_HOOK_CODE,bind);m.put(H+0xb80+0x168,0);m.invoke(0x4030a0d4)
assert m.get(H+0xb80+0x168)==0x402f3d64
cases.append({'case':'actual-MT7626-RX-archops-binding','wrapper':'402a09ac','callback':'402f3d64'})
report={'scope':__doc__,'source_sha256':ns['ns']['SHA'],'cases_passed':len(cases),'cases':cases,'ASIC_wrapper':'402a09ac','RX_callback':'402f3d64','refill':'402f3f6c..402f402c','publisher_prefix':'402b2620..402b2644','CPU_offsets':['4408','4418'],'limits':['Host allocator/unmap/locks/context and DMA/MMIO services synthetic;not real RX/MCU/RF','Factory swaps a new OS buffer;bounded diagnostic may reuse same coherent buffer after processing because it keeps no packet pointer','Factory preserves LS0 and clears DONE after resetting capacity;CPU index references consumed slot','No evidence59-packet boundary itself causes RAM16/17 WPDMA disable;RX recycling is a required lifecycle fix and hardware test remains necessary']}
(ROOT/'stock-rx-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'descriptor_1536':'41422000/46000000/0/0','CPU_publisher':'402b2620'}))
