#!/usr/bin/env python3
"""Exact OEM ARM BSS OWN/BASIC builder, AP helper, wrappers and response.
Synthetic MAC/arguments, alloc/copy/send/events/OS. No MCU, RF or physical DMA.
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
DevModel=ns['DevModel'];A,H,MSG,SKB,DATA,STACK,MAC,PUBLIC_MAC=(ns[x] for x in ('A','H','MSG','SKB','DATA','STACK','MAC','PUBLIC_MAC'))
ARG=0x41c1b000
class BSSModel(DevModel):
 def __init__(self):
  super().__init__();self.put(H+0xb80+0x28,0x402a3640)
 def code(self,uc,pc,size,opaque):
  if pc==0x4033c0b8:
   dst,src,n=[uc.reg_read(x) for x in ns['ns']['REGS'][:3]]
   assert n==6 and 0x41e00000<=dst<dst+n<=0x41e10000
   assert src==MAC or src==ARG+4 or 0x41e00000<=src<src+n<=0x41e10000
   uc.mem_write(dst,bytes(uc.mem_read(src,n)));self.finish(dst)
  else:super().code(uc,pc,size,opaque)

def args(state=2,features=3,own=0,index=0,network=0x10000,connection=0x10002,
         bmc=0,peer=9,cipher=1,wmm=0,phy=0,beacon=0,dtim=0):
 b=bytearray(144);b[1:4]=bytes([state,own,index]);b[4:10]=PUBLIC_MAC
 b[10]=bmc;b[11]=peer;struct.pack_into('<II',b,12,network,connection)
 b[20:23]=bytes([cipher,wmm,phy]);struct.pack_into('<I',b,48,features)
 struct.pack_into('<H',b,76,beacon);b[78]=dtim;return bytes(b)
def expected(b):
 features=int.from_bytes(b[48:52],'little');body=struct.pack('<BBHB3x',b[3],0,(features&1)+((features>>1)&1),1)
 if features&1:
  body+=struct.pack('<HHBBBBII',0,16,b[2] if b[2]<=4 else 0,b[2],0,0,int.from_bytes(b[16:20],'little'),0)
 if features&2:
  tlv=bytearray(28);struct.pack_into('<HHI',tlv,0,1,28,int.from_bytes(b[12:16],'little'))
  tlv[8]=b[1]>1;tlv[10:12]=b[76:78];tlv[12:18]=PUBLIC_MAC;tlv[18]=b[21];tlv[19]=b[78]
  tlv[20]=b[11] if int.from_bytes(b[16:20],'little')==0x10001 else b[10];tlv[21]=b[20];tlv[22]=b[22];body+=tlv
 return body
cases=[];packets=[]
settings=[('bss-on',15,args()),('bss-off',1,args(state=1,features=2)),
 ('bss-own-only',4,args(features=1)),('bss-other-AP',7,args(own=1,index=2,bmc=127,cipher=3,wmm=2,phy=4,beacon=100,dtim=1)),
 ('bss-STA-peer-index',8,args(own=5,index=3,connection=0x10001,bmc=7,peer=9))]
for name,sequence,b in settings:
 m=BSSModel();m.cpu.mem_write(ARG,b);assert m.invoke(0x402ee440,A,ARG)==0 and len(m.calls)==1
 call=m.calls[0];assert bytes.fromhex(call['body_hex'])==expected(b)
 assert call['cid']==0xed and call['flags']==0x27 and call['callback']=='0x402eccdc'
 assert bytes.fromhex(call['attributes_hex'])[3]==0x26
 assert int.from_bytes(bytes.fromhex(call['attributes_hex'])[6:8],'little')==16
 m.cpu.mem_write(MSG+22,bytes([sequence]));m.invoke(0x4026249c,MSG,SKB)
 packet=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)))
 assert len(packet)==64+len(expected(b)) and packet[38]==0 and packet[41]==0x26 and packet[43]==1
 packets.append(dict(call,name=name,packet_hex=packet.hex(),sequence=sequence))
 cases.append({'case':'actual-builder-and-header-'+name,'body_bytes':len(expected(b)),'response_minimum':16})
# Dedicated factory AP-basic helper: creates its144B argument from zero,
# network10000/connection10002/cipher1/active2/feature2,BMC/WMM/PHY/beacon/DTIM0.
m=BSSModel();assert m.invoke(0x4031d708,A,0,0,MAC)==0 and len(m.calls)==1
b=args(features=2);assert bytes.fromhex(m.calls[0]['body_hex'])==expected(b)
cases.append({'case':'actual-factory-AP-basic-helper','argument_zeroed_bytes':144,'feature_mask':2,'network':'00010000','connection':'00010002','cipher':1,'beacon_and_DTIM':0})
m=BSSModel();m.put(H+0xb80+0x28,0);m.cpu.reg_write(UC_ARM_REG_R4,H+0xb80)
def bind(uc,pc,size,opaque):
 if pc==0x40309f08:uc.reg_write(UC_ARM_REG_PC,ns['ns']['RETURN'])
m.cpu.hook_add(UC_HOOK_CODE,bind);m.invoke(0x40309f00);assert m.get(H+0xb80+0x28)==0x402a3640
cases.append({'case':'actual-board-BSS-archops28-binding'})
for state,features in ((2,3),(1,2)):
 m=BSSModel();b=args(state=state,features=features);m.cpu.mem_write(ARG,b)
 assert m.invoke(0x4029f8f4,A,ARG)==0 and bytes.fromhex(m.calls[0]['body_hex'])==expected(b)
 cases.append({'case':f'actual-ASIC-board-wrapper-state{state}-features{features}'})
for ext in (0,0x26):
 for status in (0,1,0x80000000):
  for body_bytes in (16,28,1508):
   m=BSSModel();m.put(SKB+12,DATA);m.put(MSG+16,0x402eccdc);m.cpu.mem_write(MSG+4,b'\x27');m.cpu.mem_write(MSG+6,struct.pack('<H',16))
   body=struct.pack('<B3xIBxH4x',0x26,status,0,2)+bytes((i*13+7)&255 for i in range(body_bytes-16))
   m.cpu.mem_write(DATA,struct.pack('<HHBBBBB3x',body_bytes+12,0xe000,0xed,15,0,0,ext)+body);seen=[]
   def dispatch(uc,pc,size,opaque):
    if pc==0x402eccdc:seen.append((uc.reg_read(UC_ARM_REG_R1),uc.reg_read(UC_ARM_REG_R2)))
    if pc==0x40264120:uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,ns['ns']['RETURN'])
   m.cpu.hook_add(UC_HOOK_CODE,dispatch)
   for reg,value in ((UC_ARM_REG_R5,MSG),(UC_ARM_REG_R6,DATA),(UC_ARM_REG_R10,SKB)):m.cpu.reg_write(reg,value)
   m.invoke(0x402637b4);assert seen==[(DATA+12,body_bytes)] and len(m.logs)==bool(status)
   cases.append({'case':f'actual-BSS-reply-ext{ext:02x}-status{status:08x}-body{body_bytes}','status_offset':4,'synthetic_response':True})
m=BSSModel();m.alloc_fail=True;m.cpu.mem_write(ARG,args());assert m.invoke(0x402ee440,A,ARG)==3 and not m.calls
cases.append({'case':'actual-BSS-allocation-refused-no-send'})
report={'scope':__doc__,'source_sha256':ns['ns']['SHA'],'cases_passed':len(cases),'cases':cases,'packets':packets,'public_synthetic_MAC':PUBLIC_MAC.hex(),
 'builder':'0x402ee440','ASIC_wrapper':'0x4029f8f4','board_wrapper':'0x402a3640','callback':'0x402eccdc','dedicated_AP_basic_helper':'0x4031d708',
 'OWN_TLV_handler':'0x402eca04','BASIC_TLV_handler':'0x402ecb94','minimum_response_body_bytes':16,'variable_response_flag':'20',
 'limits':['OS/send/copy/allocation/events are synthetic,not MCU execution','Only OWN/BASIC TLVs for first experiment;no RF/channel/beacon/sync/STA record or MAC TX/RX enable','Chosen narrow AP fields follow actual dedicated helper;OWN mapping composed from actual builder to bindOwnMac0/BSS0','MCU acceptance and AP operation unproven']}
(ROOT/'stock-bss-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'packet_sizes':[len(bytes.fromhex(x['packet_hex'])) for x in packets],'hardware_tested':False}))
