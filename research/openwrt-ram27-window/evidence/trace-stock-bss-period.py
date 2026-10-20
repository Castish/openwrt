#!/usr/bin/env python3
"""Exact OEM ARM normal AP argument initialization and BASIC period marshalling.
OS services, adapter configuration and MCU send/response are synthetic.
No physical MCU, scheduler or RF execution. Own analysis SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import json,struct
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'bss-init/trace-stock-bss.py'
if not BASE.exists():BASE=ROOT/'trace-stock-bss.py'
ns={'__file__':str(BASE)}
exec(compile(BASE.read_text().split('\ncases=[]')[0],str(BASE),'exec'),ns)
BSSModel=ns['BSSModel'];A,H,ARG,MSG,SKB,STACK=(ns[x] for x in ('A','H','ARG','MSG','SKB','STACK'))
WDEV=0x41c1b800
PUBLIC=ns['PUBLIC_MAC'];cases=[];packets=[]
class NormalAP(BSSModel):
 def code(self,uc,pc,n,o):
  r0,r1,r2,r3=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
  if pc==0x402fc8e8: # AP config lookup, return NULL; AP period comes from adapter.
   assert r0==A and r1==WDEV;self.finish(0)
  elif pc==0x4033c0b8 and r0==ARG+4:
   assert r1==WDEV+32 and r2==6;uc.mem_write(r0,bytes(uc.mem_read(r1,6)));self.finish(r0)
  elif pc==0x402d0258:self.finish(1) # synthetic cipher mapping, unchanged open AP helper.
  elif pc==0x402f2408:self.finish(0) # unrelated protection/capability fill.
  elif pc in (0x402f1ef0,0x402f1cd8):self.finish(0) # BMC allocation and WMM selection.
  elif pc in (0x402fbfc8,0x402fc368,0x40360534,0x40331b5c):
   self.finish(0) # BMC OS tables, RF context and protection; outside period proof.
  elif pc==0x4033c098:
   assert r1==2 and 0x41e00000<=r0<r0+2<=0x41e10000
   uc.mem_write(r0,bytes(2));self.finish(0)
  else:super().code(uc,pc,n,o)

for period,dtim in ((100,1),(200,2),(1,255),(65535,255),(0,0)):
 m=NormalAP();m.put(WDEV+8,A);m.put(WDEV+20,0) # WDEV_TYPE_AP
 m.cpu.mem_write(WDEV+32,PUBLIC)
 m.cpu.mem_write(A+0x1e22ac,struct.pack('<H',period))
 m.cpu.mem_write(A+0xceb70,bytes([dtim]))
 m.cpu.mem_write(ARG,bytes(144))
 assert m.invoke(0x403606f8,A,WDEV,ARG)==0 # actual final return value, not an API status
 b=bytes(m.cpu.mem_read(ARG,144))
 assert b[1]==1 and b[4:10]==PUBLIC and struct.unpack_from('<H',b,76)[0]==period and b[78]==dtim
 assert struct.unpack_from('<II',b,12)==(0x10000,0x10002)
 cases.append({'case':f'actual-normal-AP-argument-period{period}-DTIM{dtim}',
  'entry':'403606f8','period_source':'adapter+1e22ac','DTIM_source':'adapter+ceb70',
  'argument_period_offset':76,'argument_DTIM_offset':78,
  'unrelated_helpers_intercepted':True,'period_TSF_FW_RF_emulated':False})

for state,name,seq in ((2,'bss-period-on',15),(1,'bss-period-off',1)):
 for period,dtim in ((100,1),(200,2),(0,0)):
  m=BSSModel();b=ns['args'](state=state,features=3 if state==2 else 2,beacon=period,dtim=dtim)
  m.cpu.mem_write(ARG,b);assert m.invoke(0x402ee440,A,ARG)==0 and len(m.calls)==1
  c=m.calls[0];body=bytes.fromhex(c['body_hex']);offset=24 if state==2 else 8
  assert body==ns['expected'](b) and struct.unpack_from('<H',body,offset+10)[0]==period and body[offset+19]==dtim
  m.cpu.mem_write(MSG+22,bytes([seq]));m.invoke(0x4026249c,MSG,SKB)
  p=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)))
  assert len(p)==64+len(body) and p[38]==0 and p[41]==0x26 and p[43]==1
  if period==100:packets.append(dict(c,name=name,sequence=seq,packet_hex=p.hex()))
  cases.append({'case':f'actual-BASIC-builder-state{state}-period{period}-DTIM{dtim}',
   'builder':'402ee440','BASIC_handler':'402ecb94','body_bytes':len(body)})

out={'scope':__doc__,'source_sha256':ns['ns']['ns']['SHA'],'cases_passed':len(cases),'cases':cases,
 'packets':packets,'normal_AP_argument_entry':'403606f8','BASIC_builder':'402ecb94',
 'change':'BASIC beacon interval0→100 TU and DTIM0→1,matching unchanged beacon/SYNC',
 'limits':['Adapter configuration,unrelated OS/BMC/RF helpers and MCU send synthetic',
  'Proves actual factory normal AP period marshalling,not RF causality or SSID visibility',
  'No new RF/MMIO setting,channel/rate/power/PHY/BMC/STA change']}
(ROOT/'stock-bss-period-traces.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'packet_sizes':[len(bytes.fromhex(x['packet_hex'])) for x in packets]}))
