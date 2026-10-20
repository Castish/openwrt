#!/usr/bin/env python3
"""Actual OEM ARM channel/path/MAC builders and RX metadata offset instructions.
Synthetic memory, arguments, alloc/copy/send/events; no RF/physical DMA emulated.
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
DevModel=ns['DevModel'];A,H,MSG,SKB,DATA,STACK=(ns[x] for x in ('A','H','MSG','SKB','DATA','STACK'))
RETURN=ns['ns']['RETURN'];RXBLK=0x41c1b000
class RadioModel(DevModel):
 def code(self,uc,pc,size,opaque):
  if pc==0x4033c0b8:
   d,s,n=[uc.reg_read(x) for x in ns['ns']['REGS'][:3]]
   assert n==49 and d==A+0xa7f2d and 0x41e00000<=s<s+n<0x41e10000
   uc.mem_write(d,bytes(uc.mem_read(s,n)));self.finish(d)
  else:super().code(uc,pc,size,opaque)

def cfg(channel=6,bw=0,tx=1,rx=1,band=0):
 return bytes([channel,0,channel,bw,tx,rx,0,band,band,0,0,0])+bytes(4)
def invoke_cfg(m,entry,b):
 m.put(STACK,int.from_bytes(b[12:16],'little'))
 return m.invoke(entry,A,*struct.unpack('<III',b[:12]))
def packet(m,name,seq):
 assert len(m.calls)==1;c=m.calls[0];c['attributes_hex']=bytes(m.cpu.mem_read(MSG,24)).hex()
 m.cpu.mem_write(MSG+22,bytes([seq]));m.invoke(0x4026249c,MSG,SKB)
 p=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)))
 assert p[36]==0xed and p[38]==1 and p[43]==1 and len(p)==64+c['bytes']
 return dict(c,name=name,sequence=seq,packet_hex=p.hex())
cases=[];packets=[]
for name,enable in [('mac-off-initial',0),('mac-on',1),('mac-off-final',0)]:
 m=RadioModel();assert m.invoke(0x4031479c,A,0,enable)==0
 p=packet(m,name,3);assert bytes.fromhex(p['body_hex'])==bytes([enable,0,0,0]) and bytes.fromhex(p['packet_hex'])[41]==0x46
 packets.append(p);cases.append({'case':'actual-MAC-builder-header-'+name})
for name,entry,ext in [('channel6',0x40310114,8),('path1x1',0x403103d0,0x4e)]:
 m=RadioModel();m.cpu.mem_write(A+0x1e2324,b'\x64') # selected normal100%, no extra drop
 assert invoke_cfg(m,entry,cfg())==0
 p=packet(m,name,4);body=bytearray(76);body[:5]=bytes([6,6,0,1,1])
 if ext==8:body[20:69]=bytes([63])*49
 assert bytes.fromhex(p['body_hex'])==body and bytes.fromhex(p['packet_hex'])[41]==ext
 at=bytes.fromhex(p['attributes_hex']);assert at[4]==15 and int.from_bytes(at[6:8],'little')==8
 assert int.from_bytes(at[8:10],'little')==(5000 if ext==8 else 0)
 packets.append(p);cases.append({'case':'actual-builder-header-'+name,'bytes':76,'flags':'0f','expected_response_body':8})
# Whole actual channel wrapper calls channel then path. Synthetic prior/after
# RF register helpers are explicitly intercepted, never executed as MMIO.
m=RadioModel();m.cpu.mem_write(A+0x1e2324,b'\x64');helpers=[]
def wrapper(uc,pc,size,opaque):
 if pc in (0x40348f14,0x40307b9c):helpers.append(hex(pc));m.finish(0)
m.cpu.hook_add(UC_HOOK_CODE,wrapper);invoke_cfg(m,0x4030931c,cfg())
assert [bytes.fromhex(c['body_hex']) for c in m.calls]==[bytes.fromhex(packets[3]['body_hex']),bytes.fromhex(packets[4]['body_hex'])]
cases.append({'case':'actual-board-channel-wrapper-order','commands':['08','4e'],'surrounding_RF_helpers_synthetic':helpers})
# Exact board pointer bindings for RX type and RX metadata parser.
m=RadioModel();m.cpu.reg_write(UC_ARM_REG_R4,H+0xb80)
def bind(uc,pc,size,opaque):
 if pc==0x4030a080:uc.reg_write(UC_ARM_REG_PC,RETURN)
m.cpu.hook_add(UC_HOOK_CODE,bind);m.invoke(0x4030a070)
assert m.get(H+0xb80+0x170)==0x402b327c and m.get(H+0xb80+0x174)==0x4031b680
cases.append({'case':'actual-board-RX-type-binding'})
for typ in range(8):
 m=RadioModel();m.put(DATA,(typ<<29)|96);assert m.invoke(0x4031b680,A,DATA)==typ
 cases.append({'case':f'actual-RX-type-{typ}','shift':29})
# Execute exact RX metadata prefix to 4031b728: base16, group table,
# optional2B pad. Stop before the remaining host protocol processing.
for group in range(16):
 for pad in (0,1):
  m=RadioModel();m.put(SKB+12,DATA);raw=bytearray(256);struct.pack_into('<I',raw,0,256|(group<<25)|(2<<29));raw[6]=pad<<6
  m.cpu.mem_write(DATA,bytes(raw));seen=[]
  def prefix(uc,pc,size,opaque):
   if pc==0x4031b728:
    seen.append(uc.reg_read(UC_ARM_REG_R7));uc.reg_write(UC_ARM_REG_SP,STACK);uc.reg_write(UC_ARM_REG_PC,RETURN)
  m.cpu.hook_add(UC_HOOK_CODE,prefix);m.invoke(0x4031b68c,A,RXBLK,SKB)
  expected=16+16*bool(group&8)+16*bool(group&1)+8*bool(group&2)+24*bool(group&4)+2*pad
  assert seen==[expected] and int.from_bytes(m.cpu.mem_read(RXBLK+72,2),'little')==256-expected
  cases.append({'case':f'actual-RX-offset-groups{group:x}-pad{pad}','offset':expected,'OEM_bounds_not_assumed':True})
# Dispatch enforces fixed8B bodies (flags0f has no variable20). The actual
# generic extended response callback402ec530 is a NOP: host validates echo/
# full32status more strictly, based on documented EXT_CMD_RESULT format.
for ext in (0,8,0x4e,0x46):
 for size,accept in ((8,True),(7,False),(12,False)):
  m=RadioModel();m.put(SKB+12,DATA);m.put(MSG+16,0x402ec530);m.cpu.mem_write(MSG+4,b'\x0f');m.cpu.mem_write(MSG+6,struct.pack('<H',8))
  m.cpu.mem_write(DATA,struct.pack('<HHBBBBB3x',size+12,0xe000,0xed,3,0,0,ext)+bytes(size));seen=[]
  def dispatch(uc,pc,size,opaque):
   if pc==0x402ec530:seen.append((uc.reg_read(UC_ARM_REG_R1),uc.reg_read(UC_ARM_REG_R2)))
   if pc==0x40264120:uc.reg_write(UC_ARM_REG_PC,RETURN)
  m.cpu.hook_add(UC_HOOK_CODE,dispatch)
  for reg,value in ((UC_ARM_REG_R5,MSG),(UC_ARM_REG_R6,DATA),(UC_ARM_REG_R10,SKB)):m.cpu.reg_write(reg,value)
  m.invoke(0x402637b4);assert bool(seen)==accept
  cases.append({'case':f'actual-fixed-response-ext{ext:02x}-body{size}','accepted':accept,'NOP_callback':True})
for entry,args in ((0x4031479c,(0,1)),):
 m=RadioModel();m.alloc_fail=True;assert m.invoke(entry,A,*args)==3 and not m.calls
 cases.append({'case':'actual-MAC-allocation-refused'})
for entry in (0x40310114,0x403103d0):
 m=RadioModel();m.alloc_fail=True;assert invoke_cfg(m,entry,cfg())==3 and not m.calls
 cases.append({'case':f'actual-channel-path-allocation-refused-{entry:08x}'})
m=RadioModel();assert invoke_cfg(m,0x40310114,cfg(channel=0))==0xffffffff and not m.calls
cases.append({'case':'actual-zero-channel-refused'})
report={'scope':__doc__,'source_sha256':ns['ns']['SHA'],'cases_passed':len(cases),'cases':cases,'packets':packets,
 'channel_builder':'40310114','path_builder':'403103d0','MAC_builder':'4031479c','board_channel_wrapper':'4030931c','generic_callback':'402ec530 (NOP)',
 'RX_type':'4031b680','RX_offset_prefix':'4031b68c..4031b728','public_synthetic_only':True,
 'limits':['All host services/events/MMIO surroundings synthetic; no actual RF or calibration emulated','No radioON/OFF05 command: actual MT7626 channel wrapper sends08 then4e; power-on hook previously proven NOP','No beacon template, sync enable, STA record, data TX or AP service','Receive parser proves bounded raw-header candidates, not decryption/FCS verification or full receive path']}
(ROOT/'stock-radio-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'packet_sizes':[len(bytes.fromhex(p['packet_hex'])) for p in packets]}))
