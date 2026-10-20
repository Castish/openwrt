#!/usr/bin/env python3
"""Actual OEM STA BASIC/WTBL commands and callback; synthetic OS/peer context.
Own analysis code: SPDX-License-Identifier: MIT. No firmware/MCU/RF execution.
"""
from pathlib import Path
import struct,json
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent;P=ROOT.parent/'mac-init/trace-stock-devinfo.py'
if not P.exists():P=ROOT/'trace-stock-devinfo.py'
ns={'__file__':str(P)};exec(compile(P.read_text().split('\ncases=[]')[0],str(P),'exec'),ns)
Base=ns['DevModel'];A,H,MSG,SKB,DATA,STACK=[ns[k] for k in ('A','H','MSG','SKB','DATA','STACK')]
ENTRY=0x41c10000;WDEV=0x41c14000;ALLOC=0x41c16000;PEER=bytes.fromhex('027122334455')
class StaModel(Base):
 def __init__(self,aid=1,wcid=1,peer=PEER):
  super().__init__();self.put(ENTRY+8,WDEV);self.put(WDEV+20,1);self.cpu.mem_write(ENTRY+103,peer);self.cpu.mem_write(ENTRY+120,struct.pack('<H',aid));self.put(A+0x71564+wcid*944,WDEV)
 def code(self,uc,pc,n,o):
  r0,r1,r2,r3=[uc.reg_read(k) for k in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
  if pc in (0x4033c0b8,0x40563fa4):
   assert r2<=512;uc.mem_write(r0,bytes(uc.mem_read(r1,r2)));self.finish(r0)
  elif pc==0x4033c098:
   assert r1<=512;uc.mem_write(r0,bytes(r1));self.finish(r0)
  elif pc==0x4033bee8:
   assert r0==A and 0<r2<=512;self.put(r1,ALLOC);uc.mem_write(ALLOC,bytes(r2));self.finish(0)
  elif pc==0x40260b80:
   assert r0==MSG;old=self.get(SKB+8);start=self.get(SKB+12)-r2;uc.mem_write(start,bytes(uc.mem_read(r1,r2)));self.put(SKB+12,start);self.put(SKB+8,old+r2);self.finish(0)
  else:super().code(uc,pc,n,o)
 def sta(self,state=2,features=1,new=1,wcid=1):
  cfg=bytearray(156);cfg[0:4]=bytes([0,wcid,state,0]);struct.pack_into('<II',cfg,4,0x10001,features);cfg[12]=new;struct.pack_into('<I',cfg,148,ENTRY)
  self.cpu.mem_write(STACK,bytes(cfg[12:]));return self.invoke(0x402ede60,A,*struct.unpack_from('<3I',cfg))

def full_report():
 from unicorn import UC_HOOK_CODE
 import hashlib
 rows=[];packets=[];settings=[]
 for wcid,aid in ((1,1),(2,37),(127,2007)):
  for state,feature,new in ((2,0x2001,1),(0,1,0),(1,1,1),(2,1,0)):
   settings.append((wcid,aid,state,feature,new))
 for wcid,aid,state,features,new in settings:
  m=StaModel(aid,wcid);assert m.sta(state,features,new,wcid)==0 and len(m.calls)==1
  call=m.calls[0];body=bytes.fromhex(call['body_hex']);basic=struct.pack('<HHIBBH6sH',0,20,0x10001,state,0,aid,PEER,3 if new else 1)
  assert body[:8]==struct.pack('<BBHB3x',0,wcid,2 if features&0x2000 else 1,1)
  assert body[8:28]==basic and call['flags']==0x27 and call['callback']=='0x402ecc90'
  if features&0x2000:
   assert len(body)==244 and body[28:32]==struct.pack('<HH',13,216)
   assert body[32:36]==bytes([wcid,1,10,0]) and body[44:50]==PEER
  else:assert len(body)==28
  seq=8 if state else 9;m.cpu.mem_write(MSG+22,bytes([seq]));m.invoke(0x4026249c,MSG,SKB)
  wire=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)));assert len(wire)==64+len(body)
  assert wire[38]==0 and wire[39]==seq and wire[41]==0x25 and wire[43]==1
  item={'case':f'actual-STA-wcid{wcid}-aid{aid}-state{state}-mask{features:04x}-new{new}','wcid':wcid,'aid':aid,'state':state,'features':features,'new':new,'packet_bytes':len(wire),'body_hex':body.hex(),'packet_hex':wire.hex(),'callback':'402ecc90'};rows.append(item)
  if wcid==aid==1 and ((state==2 and features==0x2001) or state==0):packets.append(item)
 for ext in (0,0x25):
  for status in (0,1,0x80000000):
   for size in (16,28,60):
    m=StaModel();m.put(SKB+12,DATA);m.put(MSG+16,0x402ecc90);m.cpu.mem_write(MSG+4,b'\x27');m.cpu.mem_write(MSG+6,struct.pack('<H',16))
    body=struct.pack('<B3xIBBHB3x',0x25,status,0,1,2,0)+bytes(size-16)
    m.cpu.mem_write(DATA,struct.pack('<HHBBBBB3x',12+size,0xe000,0xed,8,0,0,ext)+body);seen=[]
    def hook(uc,pc,n,o):
     if pc==0x402ecc90:seen.append((uc.reg_read(UC_ARM_REG_R1),uc.reg_read(UC_ARM_REG_R2)))
     if pc==0x40264120:uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,ns['ns']['RETURN'])
    m.cpu.hook_add(UC_HOOK_CODE,hook)
    for reg,val in ((UC_ARM_REG_R5,MSG),(UC_ARM_REG_R6,DATA),(UC_ARM_REG_R10,SKB)):m.cpu.reg_write(reg,val)
    m.invoke(0x402637b4);assert seen==[(DATA+12,size)] and m.get(MSG+84)==status
    rows.append({'case':f'actual-STA-variable-callback-ext{ext:02x}-status{status:08x}-body{size}','status_offset':4,'body_length_checked_by_dispatcher':True,'other_reply_metadata_not_consumed_by_OEM':True})
 assert len(rows)==30
 q={'passed':True,'cases_passed':len(rows),'source_sha256':ns['ns']['SHA'],'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'builder':'402ede60','BASIC_handler':'402ed04c','WTBL_handler':'402ed4e0','callback':'402ecc90','features_table':'405bb2cc','cases':rows,'profile_packets':packets,'profile':'BSS0/WCID1/MUAR0/infra-station10001/AID1/non-WMM/non-HT20/CCK-only/portsecure open; disconnect BASIC-only',
 'minimum_reply_body_bytes':16,'variable_reply_flag':32,'status_offset':4,'peer_address_offsets_body':[20,44],
 'limits':['Actual ARM factory builder/header/dispatcher/callback; OS alloc/copy/send and host peer/WDEV context synthetic','Explicit minimal peer profile chosen, not a complete normal AP host-side lifecycle','No BMC entry creation, key/AMPDU/HT/VHT/data path in this trial','OEM callback consumes status only; optional response metadata is diagnostic, not assumed physical ABI','No real firmware acceptance/association/DMA/RF proven by emulator']}
 (ROOT/'stock-station-traces.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps({'passed':True,'cases_passed':len(rows),'profile_packet_sizes':[x['packet_bytes'] for x in packets]}))
if __name__=='__main__':full_report()
