#!/usr/bin/env python3
"""OEM ARM TSF query/callback/dispatcher and mapped MAC register reads.
Synthetic adapter,OS allocation/copy/send/events/MMIO;not MCU/RF emulation.
Own analysis SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent/'runtime-query/trace-stock-query.py'
if not BASE.exists():BASE=ROOT/'trace-stock-query.py'
ns={'__file__':str(BASE)};exec(compile(BASE.read_text().split('\ncases=[]')[0],str(BASE),'exec'),ns)
Model=ns['QueryModel'];A,H,HIF,MSG,SKB,DATA,OUT,STACK=(ns[x] for x in ('A','H','HIF','MSG','SKB','DATA','OUT','STACK'));RETURN=ns['ns']['RETURN']
cases=[];packets=[]
for own in (0,1,3):
 for seq in (1,7,8,15):
  m=Model();assert m.invoke(0x4031469c,A,own,OUT)==0 and len(m.calls)==1
  c=m.calls[0];at=bytes(m.cpu.mem_read(MSG,24));body=bytes.fromhex(c['body_hex'])
  want=struct.pack('<H2xB',2,own)+bytes(99)
  assert body==want and at[3]==0x3c and at[4]==7 and int.from_bytes(at[6:8],'little')==12 and int.from_bytes(at[8:10],'little')==0
  assert c['callback']=='0x4030ec1c'
  m.cpu.mem_write(MSG+22,bytes([seq]));m.invoke(0x4026249c,MSG,SKB)
  packet=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)));assert len(packet)==168 and packet[38]==0 and packet[41]==0x3c and packet[43]==1
  packets.append(dict(c,name=f'tsf-own{own}-seq{seq}',sequence=seq,packet_hex=packet.hex(),attributes_hex=at.hex()))
  cases.append({'case':f'actual-TSF-builder-header-own{own}-seq{seq}','body_bytes':104,'flags':7,'expected_body':12,'callback':'4030ec1c'})
for low,high in ((0,0),(0x12345678,0x9abcdef0),(0xffffffff,0),(0,1),(0xffffffff,0xffffffff)):
 m=Model();m.put(MSG+12,OUT);m.cpu.mem_write(OUT,b'\xa5'*16);m.cpu.mem_write(DATA,struct.pack('<H2xII',2,low,high))
 m.invoke(0x4030ec1c,MSG,DATA,12);assert bytes(m.cpu.mem_read(OUT,16))==struct.pack('<II',low,high)+b'\xa5'*8
 cases.append({'case':f'actual-TSF-callback-{high:08x}{low:08x}','low_offset':4,'high_offset':8,'canary_preserved':True})
for ext in (0,0x3c):
 for length in (11,12,13):
  m=Model();m.put(SKB+12,DATA);m.put(MSG+12,OUT);m.put(MSG+16,0x4030ec1c);m.cpu.mem_write(MSG+4,b'\x07');m.cpu.mem_write(MSG+6,struct.pack('<H',12))
  m.cpu.mem_write(DATA,struct.pack('<HHBBBBB3x',12+length,0xe000,0xed,7,0,0,ext)+struct.pack('<H2xII',2,0x12345678,0x9abcdef0)+bytes(8));seen=[]
  def hook(uc,pc,n,o):
   if pc==0x4030ec1c:seen.append((uc.reg_read(UC_ARM_REG_R1),uc.reg_read(UC_ARM_REG_R2)))
   if pc==0x40264120:uc.reg_write(UC_ARM_REG_PC,RETURN)
  m.cpu.hook_add(UC_HOOK_CODE,hook)
  for reg,v in ((UC_ARM_REG_R5,MSG),(UC_ARM_REG_R6,DATA),(UC_ARM_REG_R10,SKB)):m.cpu.reg_write(reg,v)
  m.invoke(0x402637b4);assert bool(seen)==(length==12)
  cases.append({'case':f'actual-TSF-dispatch-ext{ext:02x}-length{length}','accepted':bool(seen),'Linux_only_accepts_ext3c_and_category2':True})
regs=[('ARB_SCR',0x820f3080),('ARB_TQSM0',0x820f3110),('ARB_TQFM0',0x820f3130),('LPON_T0CR',0x820fb010),('LPON_T0TPCR',0x820fb034),('LPON_PISR',0x820fb030),('LPON_MPTCR0',0x820fb05c),('TMAC_TCR',0x820f4000),('MIB_M0SCR0',0x820fd000),('MIB_M0SCR1',0x820fd008),('MIB_M0SDR0',0x820fd010),('PLE_QUEUE_EMPTY',0x820600b0)]
m=Model();m.put(HIF+0x7c,0x18000000);m.invoke(0x402f54ac,H);reads=[];mapped=[]
# Mapping follows the actual MT7626 global->host address routine and installed
# MAC-read callback. No guessed low comments from other silicon are used.
def rd(uc,off,n,page):
 assert n==4;reads.append(page+off);return 0x13579bdf
def wr(uc,off,n,value,page):raise AssertionError(('unexpected write',hex(page+off),value))
for page in (0x18008000,0x18023000,0x18024000,0x1802b000,0x1802d000):m.cpu.mmio_map(page,0x1000,rd,page,wr,page)
for name,a in regs:
 old=len(reads);m.put(OUT,a);assert m.invoke(0x4031bb30,A,OUT)==1;host=m.get(OUT)
 m.put(OUT,0);m.invoke(0x4031bc6c,H,host,OUT)
 assert len(reads)==old+1 and m.get(OUT)==0x13579bdf
 expected=0x18000000+(a-0x820f0000+0x20000 if a>=0x820f0000 else a-0x82060000+0x8000)
 assert reads[-1]==expected,(name,hex(reads[-1]),hex(expected))
 mapped.append({'name':name,'global':hex(a),'physical':hex(reads[-1]),'host':hex(reads[-1]-0x18000000)})
 cases.append({'case':'actual-MAC-mapped-read-'+name,'global':hex(a),'physical':hex(reads[-1]),'writes':0})
report={'scope':__doc__,'source_sha256':ns['ns']['SHA'],'cases_passed':len(cases),'cases':cases,'packets':packets,'registers':mapped,'TSF_builder':'4031469c','TSF_callback':'4030ec1c','global_to_host_mapper':'4031bb30','MAC_read_wrapper':'4031bc6c','IO_init':'402f54ac','limits':['Synthetic MMIO returns fixture values;no physical C80 RF/MCU executed','Counters may clear on read or be maintained by firmware;raw snapshots are observations,not cumulative deltas','MIB_M0SDR0 low16 beacon TX count semantic from matching vendor DMAC reference,not proof of received RF/FCS','Zero TSF or unchanged TSF is valid data to diagnose,not automatically rejected','Read only selected register addresses;no selector,enable or counter configuration writes']}
(ROOT/'stock-beacon-state-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'packets':len(packets),'registers':mapped}))
