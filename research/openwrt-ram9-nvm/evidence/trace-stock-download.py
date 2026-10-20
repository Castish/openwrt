#!/usr/bin/env python3
"""Scoped OEM ARM patch parser/loader/builders with synthetic host services.
No MCU, radio, OS or physical DMA execution. Service interception and generated
responses are explicit; exact ARM-produced packet bytes are retained as oracles.
Own analysis code: SPDX-License-Identifier: MIT.
"""
import hashlib,json,struct,zlib
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import UC_CPU_ARM_CORTEX_A7,UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_CPSR
ROOT=Path(__file__).resolve().parent
RESEARCH=ROOT.parent.parent
PROGRAM=(RESEARCH/'firmware-ru-240812/main-program.bin').read_bytes()
SHA='efdf45c9767bad9b30c93383ee2f5b99a38f5bc2441064e327b026097030fd95'
assert hashlib.sha256(PROGRAM).hexdigest()==SHA
PATCH=(RESEARCH/'firmware-ru-240812/minifs/fw/mtk/mt7626_patch_e1_hdr.bin').read_bytes()
A,H,HIF,FW,MSG,SKB,DATA,OUT,OBJECT,STACK,RETURN=0x40800000,0x40d00000,0x40e00000,0x41b00000,0x41c00000,0x41c01000,0x41c04000,0x41c18000,0x41c19000,0x41e0f000,0x41ef0000
CAP=H+0x810
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)
class Model:
 def __init__(self,sem=2,fail_cid=None,fail_nth=1):
  self.cpu=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.cpu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
  for addr,size in ((0x40200000,0x500000),(A,0x400000),(H,0x10000),(HIF,0x10000),(FW,0x10000),(MSG,0x20000),(0x41e00000,0x10000),(RETURN,0x1000)):
   self.cpu.mem_map(addr,size)
  self.cpu.mem_write(0x40205000,PROGRAM);self.cpu.mem_write(FW,PATCH)
  self.put(A+0x33c5e8,H);self.put(A+0xa9d40,0x7626);self.put(H+0x1fdc,HIF)
  self.cpu.mem_write(CAP+0x18,b'\x02');self.cpu.mem_write(CAP+0x128,b'\x40')
  self.cpu.mem_write(CAP+0x162,struct.pack('<H',0xf800));self.put(CAP+0x120,0x1c000)
  self.put(CAP+0x118,1) # synthetic source selection: use supplied in-memory blob
  self.put(A+0x33c200,FW);self.put(A+0x33c204,len(PATCH))
  self.sem=sem;self.fail_cid=fail_cid;self.fail_nth=fail_nth;self.seen={};self.calls=[];self.returned=False;self.alloc_fail=False
  self.cpu.hook_add(UC_HOOK_CODE,self.code)
 def put(self,a,v):self.cpu.mem_write(a,struct.pack('<I',v))
 def get(self,a):return struct.unpack('<I',self.cpu.mem_read(a,4))[0]
 def finish(self,v):self.cpu.reg_write(UC_ARM_REG_R0,v);self.cpu.reg_write(UC_ARM_REG_PC,self.cpu.reg_read(UC_ARM_REG_LR))
 def code(self,uc,pc,size,opaque):
  r0,r1,r2,r3=[uc.reg_read(x) for x in REGS]
  if pc==RETURN:self.returned=True;uc.emu_stop()
  elif pc==0x4033b7cc:self.finish(0)
  elif pc==0x4033bee8:
   assert r0==A and r2==16;self.put(r1,OBJECT);uc.mem_write(OBJECT,bytes(16));self.finish(0)
  elif pc==0x4033bfec:self.finish(0) # synthetic free, no OEM OS allocator execution
  elif pc==0x40562f10:
   assert r2<=1024 and (0x41c00000<=r0<r0+r2<=0x41c20000 or 0x41e00000<=r0<r0+r2<=0x41e10000)
   uc.mem_write(r0,bytes([r1&255])*r2);self.finish(r0)
  elif pc==0x40563fa4:
   assert DATA<=r0<r0+r2<=DATA+1024
   uc.mem_write(r0,bytes(uc.mem_read(r1,r2)));self.finish(r0)
  elif pc==0x4026097c:
   assert r0==A and 0<r1<=960
   uc.mem_write(MSG,bytes(128));uc.mem_write(SKB,bytes(32));self.put(MSG+28,A);self.put(MSG+32,SKB);self.put(SKB+12,DATA)
   self.finish(0 if self.alloc_fail else MSG)
  elif pc==0x404fb9b4:self.finish(0x41c1c000)
  elif pc==0x4033c4bc:
   assert r0==SKB and 0<r1<=960
   n=self.get(SKB+8);self.put(SKB+8,n+r1);self.finish(self.get(SKB+12)+n)
  elif pc==0x4033c510:
   assert r0==SKB and r1==32
   ptr=self.get(SKB+12)-32;self.put(SKB+12,ptr);self.put(SKB+8,self.get(SKB+8)+32);self.finish(ptr)
  elif pc==0x402aaf44:
   assert (r0,r1)==(A,MSG)
   attrs=bytes(uc.mem_read(MSG,24));cid=attrs[2];body=bytes(uc.mem_read(self.get(SKB+12),self.get(SKB+8)))
   self.seen[cid]=self.seen.get(cid,0)+1
   self.calls.append({'cid':cid,'flags':attrs[4],'pqid':hex(struct.unpack_from('<H',attrs,20)[0]),'body_hex':body.hex(),'bytes':len(body),'callback':hex(self.get(MSG+16)),'download_stage_flag':uc.mem_read(A+0x33c26d,1)[0]})
   if cid==0x10:uc.mem_write(A+0x33c26c,bytes([self.sem if struct.unpack('<I',body)[0] else 3]))
   self.finish(5 if cid==self.fail_cid and self.seen[cid]==self.fail_nth else 0)
 def invoke(self,entry,*args):
  self.returned=False;self.cpu.reg_write(UC_ARM_REG_CPSR,0xd3);self.cpu.reg_write(UC_ARM_REG_SP,STACK);self.cpu.reg_write(UC_ARM_REG_LR,RETURN)
  for reg,arg in zip(REGS,args):self.cpu.reg_write(reg,arg)
  self.cpu.emu_start(entry,RETURN+4,count=30000,timeout=1_000_000)
  assert self.returned and self.cpu.reg_read(UC_ARM_REG_SP)==STACK,hex(self.cpu.reg_read(UC_ARM_REG_PC))
  return self.cpu.reg_read(UC_ARM_REG_R0)
 def packet(self,entry,args,seq):
  self.invoke(entry,A,*args);assert len(self.calls)==1
  self.cpu.mem_write(MSG+22,bytes([seq]));self.invoke(0x4026249c,MSG,SKB)
  p=bytes(self.cpu.mem_read(self.get(SKB+12),self.get(SKB+8)))
  attrs=self.calls[0];payload=bytes.fromhex(attrs['body_hex']);n=64+len(payload);qid=int(attrs['pqid'],16)
  expected=bytearray(n);struct.pack_into('<II',expected,0,((qid&0xfc00)<<16)|n,0x0300a000 if attrs['cid']==0xee else 0x0200a000)
  struct.pack_into('<HHBBBB',expected,32,32+len(payload),qid,attrs['cid'],0xa0,3,seq);expected[64:]=payload
  assert p==expected,(p.hex(),expected.hex())
  return dict(attrs,sequence=seq,packet_hex=p.hex())

cases=[]
for sem in (0,1,2,9):
 m=Model(sem);assert m.invoke(0x402ef53c,A,0,OUT)==0
 assert m.get(OUT)==OBJECT and m.cpu.mem_read(OUT+4,1)[0]==1
 assert tuple(m.get(OBJECT+i*4) for i in range(3))==(FW+30,0x1c000,1808)
 rc=m.invoke(0x402ef378,A,0,OUT)
 assert rc==(0 if sem in (1,2) else 1)
 c=m.calls
 if sem==2:
  assert [x['cid'] for x in c]==[16,5,238,238,7,16]
  assert bytes.fromhex(c[1]['body_hex'])==struct.pack('<III',0x1c000,1808,0x80000000)
  assert b''.join(bytes.fromhex(x['body_hex']) for x in c if x['cid']==238)==PATCH[30:]
  assert [x['bytes'] for x in c if x['cid']==238]==[960,848]
  assert [x['download_stage_flag'] for x in c]==[1,1,2,2,1,1]
 else:assert [x['cid'] for x in c]==[16]
 cases.append({'case':f'patch-flow-semaphore-{sem}','rc':rc,'calls':c})
for cid,nth in ((16,1),(5,1),(238,1),(238,2),(7,1),(16,2)):
 m=Model(fail_cid=cid,fail_nth=nth);assert m.invoke(0x402ef53c,A,0,OUT)==0
 assert m.invoke(0x402ef378,A,0,OUT)==5
 assert m.calls[-1]['cid']==cid
 cases.append({'case':f'patch-send-fails-{cid}-occurrence-{nth}','rc':5,'calls':m.calls})
packets=[]
for name,entry,args,seq in (
 ('get',0x40313f04,(1,),1),('patch-address',0x40313d04,(0x1c000,1808,0x80000000),2),
 ('scatter960',0x40313e50,(FW+30,960),3),('scatter848',0x40313e50,(FW+990,848),4),
 ('patch-finish',0x40313fb8,(),5),('release',0x40313f04,(0,),6),
 ('main-address',0x40313d04,(0x20400,2896,0x80000000),7),('main-start',0x4031408c,(0,0),8)):
 m=Model();p=m.packet(entry,args,seq);p['name']=name;packets.append(p)
 cases.append({'case':f'packet-{name}','passed':True})
# Actual scoped FWDL kick, no real DMA. Empty slots and wrap are modeled.
for index in (0,127):
 m=Model();m.packet(0x40313e50,(FW+30,960),3)
 m.put(HIF+0x7c,0x18000000);m.put(HIF+0xf0,0x41c10000);m.put(HIF+0x10c,index);m.put(HIF+0x108,0x4338)
 m.put(HIF+0xf4,index);m.cpu.mem_write(HIF+0x13c,struct.pack('<H',128))
 desc=0x41c1d000;m.put(0x41c10000+40*index+4,desc)
 m.invoke(0x402f54ac,H)
 writes=[]
 def mmio_read(*args):raise AssertionError('unexpected MMIO read')
 def mmio_write(uc,off,n,v,opaque):assert off==0x338 and n==4;writes.append(v)
 m.cpu.mmio_map(0x18004000,0x1000,mmio_read,None,mmio_write,None)
 def services(uc,pc,size,opaque):
  if pc==0x4033dfe0:m.finish(1)
  elif pc in (0x4033d9e8,0x4033da04,0x40260da8):m.finish(0)
  elif pc==0x4033af7c:
   assert uc.reg_read(UC_ARM_REG_R1)==DATA-64 and uc.reg_read(UC_ARM_REG_R2)==1024;m.finish(0x41420000)
 m.cpu.hook_add(UC_HOOK_CODE,services)
 assert m.invoke(0x402622ac,A,MSG)==0
 assert bytes(m.cpu.mem_read(desc,16))==struct.pack('<4I',0x41420000,0x44000000,0,0)
 assert writes==[(index+1)&127]
 cases.append({'case':f'FWDL3-kick-{index}','descriptor_hex':bytes(m.cpu.mem_read(desc,16)).hex(),'CPU_index_writes_modeled':writes})
# Run the real generic-event dispatch branch, then its status parser. The
# surrounding queue/completion/OS tail is deliberately stopped at40264120.
for status in (0,1,0xfe):
 m=Model();m.put(SKB+12,DATA);m.cpu.mem_write(DATA+8,bytes([status]));seen=[]
 m.cpu.reg_write(UC_ARM_REG_R3,1);m.cpu.reg_write(__import__('unicorn.arm_const',fromlist=['UC_ARM_REG_R6']).UC_ARM_REG_R6,DATA)
 m.cpu.reg_write(__import__('unicorn.arm_const',fromlist=['UC_ARM_REG_R10']).UC_ARM_REG_R10,SKB)
 def event_branch(uc,pc,size,opaque):
  if pc==0x40261ee0:seen.append(uc.reg_read(UC_ARM_REG_R0));assert seen[-1]==DATA+8
  elif pc==0x40261ef4:assert uc.reg_read(UC_ARM_REG_R1)==status
  elif pc==0x40264120:uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,RETURN)
 m.cpu.hook_add(UC_HOOK_CODE,event_branch)
 assert m.invoke(0x4026410c)==0 and seen==[DATA+8]
 cases.append({'case':f'generic-EID1-status-at-event-plus8-{status}','passed':True,'surrounding_OS_completion_tail_skipped':True})
report={'source_sha256':SHA,'scope':__doc__,'cases_passed':len(cases),'hardware_tested':False,'patch_file':{'bytes':len(PATCH),'sha256':hashlib.sha256(PATCH).hexdigest(),'crc32':f'{zlib.crc32(PATCH):08x}','header_bytes':30,'payload_bytes':1808,'payload_crc32':f'{zlib.crc32(PATCH[30:]):08x}'},'packets':packets,'cases':cases,'limitations':['Synthetic source selection, allocator/skb/copy/log/free/send/response/lock/DMA/MMIO services','OEM error paths do not always release acquired semaphore; new implementation must explicitly track ownership and attempt release if transport remains healthy','Patch-only next test must not send main-start or RF commands','MCU firmware destinations are address-space values carried in packets, not CPU MMIO addresses']}
(ROOT/'stock-download-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'OEM patch/download ARM model: {len(cases)} cases passed; parser, 6-command flow, 8 packets, FWDL3 kick; all hardware effects synthetic.')
