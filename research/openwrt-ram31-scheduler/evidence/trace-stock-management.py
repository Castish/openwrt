#!/usr/bin/env python3
"""Actual OEM ARM management TX policy/builder; synthetic host context only.
Own analysis code: SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import json,struct
from unicorn import UC_HOOK_CODE, UcError
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'beacon-init/trace-stock-beacon.py'
if not BASE.exists():BASE=ROOT/'trace-stock-beacon.py'
ns={'__file__':str(BASE)};exec(compile(BASE.read_text().split('\ncases=[]')[0],str(BASE),'exec'),ns)
Model=ns['BeaconModel'];A,H,DATA,STACK,RETURN=(ns[x] for x in ('A','H','DATA','STACK','RETURN'))
WDEV=0x41c18000;CTX=0x41c1a000;PKT=0x41c10000;INFO=0x41c1b000;PHY=0x41c1b100
MAC=bytes.fromhex('525400123456');PEER=bytes.fromhex('027122334455')
class MgmtModel(Model):
 def __init__(self,subtype=11,broadcast=False):
  super().__init__();self.saved=[];self.subtype=subtype
  self.cpu.mem_write(H+0x810+2,b'\x20');self.put(H+0x810+0x60,128)
  self.put(WDEV+8,A);self.put(WDEV+0xff4,1);self.cpu.mem_write(WDEV+25,b'\x06')
  self.cpu.mem_write(CTX+5,b'\x01');self.put(CTX+60,PKT);self.put(CTX+32,DATA);self.put(CTX+36,62);self.put(CTX+80,INFO)
  self.put(PKT+52,WDEV);self.put(PKT+8,62);self.put(PKT+12,DATA)
  f=bytearray(30);struct.pack_into('<H',f,0,subtype<<4);f[4:10]=b'\xff'*6 if broadcast else PEER;f[10:16]=f[16:22]=MAC
  self.cpu.mem_write(DATA,bytes(32)+bytes(f))
 def code(self,uc,pc,size,opaque):
  self.lastpc=pc
  r0,r1,r2,r3=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
  if pc==0x40273da4:
   assert (r0,r1,r2)==(A,WDEV,CTX) # execute actual skb->TX context extraction
  elif pc==0x404f9cc0:
   assert 0<r2<=512;uc.mem_write(r1,bytes(uc.mem_read(r0,r2)));self.finish(r1)
  elif pc==0x402a0ba0:
   assert r0==A and r1==DATA
   self.saved.append({'info_hex':bytes(uc.mem_read(r2,44)).hex(),'phy_hex':bytes(uc.mem_read(r3,4)).hex()})
   self.finish(0)
  else:super().code(uc,pc,size,opaque)

TXRING=0x41c13000;CELL=0x41c14000;DESC=0x41c15000;POOL=0x41c16000;OUTPUT=0x41c1d000
class LowerModel(MgmtModel):
 def __init__(self,subtype=11,broadcast=False):
  super().__init__(subtype,broadcast);self.lower=False;self.dma_calls=[];self.tokens=[]
 def code(self,uc,pc,size,o):
  r0,r1,r2,r3=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
  if self.lower and pc==0x4033af7c:
   st=self.get(uc.reg_read(UC_ARM_REG_SP));self.dma_calls.append([r0,r1,r2,r3,st])
   if r3==1:
    assert (r0,r1,r2,r3,st)==(A,CTX,0,1,1)
    self.put(CTX+56,0x41420000);self.finish(0x41420000)
   else:
    assert (r0,r1,r2,r3,st)==(A,INFO,64,0,1);self.finish(0x41410000)
  elif self.lower and pc==0x402e20a8:
   self.tokens.append([r0,r1,r2,r3]);assert (r0,r1,r2,r3)==(POOL,PKT,1,0);self.finish(self.token)
  else:super().code(uc,pc,size,o)

def chip_caps(m):
 for reg,val in ((UC_ARM_REG_R4,H+0x9c4),(UC_ARM_REG_R5,0x40681eac),(UC_ARM_REG_R6,0),(UC_ARM_REG_R7,A+0x33c000),(UC_ARM_REG_R8,H+0x810),(UC_ARM_REG_R9,2),(UC_ARM_REG_R10,A)):
  m.cpu.reg_write(reg,val)
 def stop(uc,pc,size,o):
  if pc==0x40309e8c:uc.reg_write(UC_ARM_REG_PC,RETURN)
 hook=m.cpu.hook_add(UC_HOOK_CODE,stop);m.invoke(0x40309b10);m.cpu.hook_del(hook)
 c=bytes(m.cpu.mem_read(H+0x810,436));assert c[2]==32 and struct.unpack_from('<H',c,6)[0]==512 and c[0x166:0x168]==b'\0\0'
 return c

def lower_case(index,token,phyword=0):
 m=LowerModel();chip_caps(m)
 assert m.invoke(0x40274848,A,WDEV,CTX)==0
 info=bytes.fromhex(m.saved[0]['info_hex']);m.cpu.mem_write(OUTPUT,info);m.cpu.mem_write(PHY,struct.pack('<I',phyword))
 ops=m.invoke(0x402f289c,H)
 for off,v in ((0x15c,0x403199fc),(0x13c,0x4031a5b4),(0x140,0x402f30bc)):m.put(ops+off,v)
 m.put(A+0xa8134,POOL);m.put(POOL+0x48,4095);m.cpu.mem_write(CTX,b'\x05');m.put(CTX+80,INFO)
 hif=m.invoke(0x402f2884,H);m.put(hif+0x10,TXRING)
 ring=TXRING+5*88;cell=CELL+index*40
 # Independent placement for the end-of-ring case avoids aliasing public fixtures.
 if index:cell=0x41c00000+index*40
 m.put(ring+8,cell-index*40);m.put(ring+36,index);m.put(cell+4,DESC);m.put(cell+28,INFO)
 m.lower=True;m.token=token;m.put(STACK,CTX)
 assert m.invoke(0x40316eb4,A,DATA,OUTPUT,PHY)==0
 hdr=bytes(m.cpu.mem_read(INFO,64));desc=bytes(m.cpu.mem_read(DESC,16))
 assert len(m.tokens)==1 and len(m.dma_calls)==2
 want=bytearray(32);struct.pack_into('<H',want,0,token|0x8000);struct.pack_into('<IH',want,8,0x41420000,30|0x8000)
 assert hdr[32:]==want,(hdr[32:].hex(),want.hex())
 assert desc==struct.pack('<4I',0x41410000,0x40400000,0x41420000,0)
 assert m.get(ring+36)==(index+1)%512
 m.put(hif+0x7c,0x18000000);m.put(ring+32,0x4358);m.invoke(0x402f54ac,H)
 writes=[]
 def rd(*args):raise AssertionError('unexpected MMIO read')
 def wr(uc,off,n,value,o):
  assert (off,n,value)==(0x358,4,(index+1)%512);writes.append(value)
  assert bytes(uc.mem_read(DESC,16))==desc and bytes(uc.mem_read(INFO,64))==hdr
 m.cpu.mmio_map(0x18004000,0x1000,rd,None,wr,None)
 m.invoke(0x402f3424,A,CTX,5);assert writes==[(index+1)%512]
 assert hdr[:2]==b'\x3e\0' and hdr[7]&3==0 and hdr[31:32]==b'\0'
 return {'case':f'actual-management-TXD-TXP-HIF-slot{index}-token{token}-PHY{phyword:04x}','entry':'40316eb4','TXP_builder':'4031a5b4','DMA_builder':'402f30bc',
  'host_services_synthetic':['OS_DMA_map','token_allocator'],'ring_resource_index':5,'ring_size':512,'software_next_index':m.get(ring+36),
  'token':token,'PHY_word':phyword,'header_hex':hdr.hex(),'descriptor_hex':desc.hex(),'header_DMA_bytes':64,'frame_DMA_bytes':30,'DMA_calls':m.dma_calls,'publisher_entry':'402f3424','CPU_register':'18004358','CPU_value_published':writes[0]}

def token_allocator_case(token):
 m=LowerModel();q=POOL+0x100;ids=POOL+0x200;entries=POOL+0x400
 m.put(POOL+4,A);m.cpu.mem_write(POOL+8,b'\x01');m.put(POOL+12,q)
 m.put(POOL+0x48,4095);m.put(POOL+0x4c,4096);m.put(POOL+0x54,4096)
 m.put(q+4,ids);m.put(q+8,entries);m.put(q+12,4096)
 m.cpu.mem_write(ids,struct.pack('<H',token));m.put(STACK,0x41420000);m.put(STACK+4,30)
 assert m.invoke(0x402e20a8,POOL,PKT,1,0)==token
 entry=entries+36*token
 assert m.get(entry)==PKT and m.get(entry+24)==0x41420000 and m.get(entry+28)==30
 assert m.get(q+12)==4095 and m.get(q+16)==1
 return {'case':f'actual-host-token-allocator-valid-token{token}','entry':'402e20a8','token':token,'actual_slot_ownership_recorded':True,'OS_table_context_synthetic':True,'firmware_token_handling_emulated':False}

def full_report():
 cases=[];packets=[]
 m=LowerModel();cap=chip_caps(m)
 table=bytes(m.cpu.mem_read(0x405be454,84));rows=[struct.unpack_from('<3I',table,i*12) for i in range(7)]
 assert [x[1] for x in rows]==[0x4300,0x4310,0x4320,0x4330,0x4340,0x4350,0x43f0]
 assert rows[5]==(0x500,0x4350,512)
 assert m.invoke(0x402adc78,A,0,14)==304
 cases.append({'case':'actual-chip-capability-prefix-and-ring-table','entry':'40309b10','end_exclusive':'40309e8c','TXD_bytes':32,'ordinary_TX_ring_entries':512,'prefetch_SDP1_bytes':0,'ring_table':[list(x) for x in rows],'prefix_not_full_chip_initialization':True})
 for subtype,broadcast in ((11,False),(5,False),(5,True),(12,False)):
  m=LowerModel(subtype,broadcast);chip_caps(m);assert m.invoke(0x40274848,A,WDEV,CTX)==0
  info=bytes.fromhex(m.saved[0]['info_hex']);phy=bytes.fromhex(m.saved[0]['phy_hex'])
  assert info[0]==0 and info[30]==subtype and info[40]==0
  cases.append({'case':f'actual-unassociated-policy-subtype{subtype}-broadcast{int(broadcast)}','entry':'40274848','skb_extraction':'40273da4','MAC_entry_null':True,'host_context_and_tx_gate_synthetic':True,'info_hex':info.hex(),'PHY_hex':phy.hex(),'caller_does_not_allocate_STA_record':True})
  for length in (30,62,128):
   for phyword in (0,0x2000):
    v=bytearray(info);struct.pack_into('<I',v,16,length);m.cpu.mem_write(OUTPUT,bytes(v));m.cpu.mem_write(PHY,struct.pack('<I',phyword))
    m.invoke(0x403199fc,A,INFO,OUTPUT,PHY);txd=bytes(m.cpu.mem_read(INFO,32))
    assert struct.unpack_from('<H',txd)[0]==length+32 and txd[3]==0x40 and txd[7]&3==0 and txd[30]==subtype
    item={'case':f'actual-fixed-TXD-subtype{subtype}-broadcast{int(broadcast)}-length{length}-PHY{phyword:04x}','TXD_hex':txd.hex(),'PHY_word':phyword,'frame_bytes':length,'no_PHY_RF_emulation':True};cases.append(item)
    if subtype==11 and length==30 and phyword==0:packets.append(item)
 for idx in (0,511):
  for token in (0,1,31,4095):cases.append(lower_case(idx,token))
 for token in (0,1,31):cases.append(token_allocator_case(token))
 assert len(cases)==40
 report={'scope':__doc__,'source_sha256':ns['ns']['ns']['ns']['SHA'],'passed':True,'cases_passed':len(cases),'cases':cases,'auth_TxD_CCK1':packets[0],
  'ring5_registers':['18004350','18004354','18004358','1800435c'],'TXP_token_valid_bit':15,'TXP_length_last_bit':15,'TXP_token_offset':0,'TXP_frame_DMA_offset':8,'TXP_frame_length_offset':12,
  'ACK_duration_CCK1_14B_bytes':304,'TXD_bytes':32,'TXP_bytes':32,'DMA_header_bytes':64,'policy_no_associated_MAC_entry_WCID':0,
  'limits':['Adapter/tx gate/OS skb context synthetic; cap prefix only, no full initialization','DMA mapping and token allocator synthetic, no actual firmware/DMA/RF/ACK','DMA DONE only establishes header consumption, not frame/air completion','No TX-free/payload-engine drain validated here; retain the complete pool unchanged until full system reset after any submission','No STA/BMC firmware setup or peer association proven; fixed CCK1 chosen to match existing beacon/test channel','Ring table is actual OEM static data; actual publisher402f3424 verifies next-producer CPU index at4358']}
 (ROOT/'stock-management-traces.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases_passed':len(cases),'auth_TxD_CCK1':packets[0]['TXD_hex']}))

if __name__=='__main__':full_report()
