#!/usr/bin/env python3
"""Own MIT analysis: actual normal-AP request construction; synthetic helpers/queue.
Capture the real BMC STA feature mask before executing any firmware operation.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn.arm_const import *
R=Path(__file__).resolve().parent;p=R.parent/'wifi-bringup/beacon-state/trace-stock-bss-period.py'
n={'__file__':str(p),'__name__':'normal_ap_library'};exec(compile(p.read_text().split('\nfor period,dtim')[0],str(p),'exec'),n)
A,WDEV=n['A'],n['WDEV']
class Request(n['NormalAP']):
 def __init__(self,cipher):super().__init__();self.cipher=cipher;self.request=None
 def code(self,uc,pc,size,opaque):
  r0,r1,r2,r3=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
  if pc==0x402f20e4:assert r0==WDEV;self.finish(1)
  elif pc==0x4033c0b8:
   assert r2<=348 and 0x40800000<=r0<r0+r2<=0x41e10000 and 0x40800000<=r1<r1+r2<=0x41e10000
   uc.mem_write(r0,bytes(uc.mem_read(r1,r2)));self.finish(r0)
  elif pc==0x4033c098:
   assert r1<=348;uc.mem_write(r0,bytes(r1));self.finish(0)
  elif pc==0x402d0258:self.finish(self.cipher)
  elif pc==0x40361e44:
   assert r0==WDEV and r1==0x10002 and r2==0
   self.put(r3,3);self.finish(1) # synthetic unrelated BSS feature selection
  elif pc==0x402f8194:
   assert r0==A;self.request=bytes(uc.mem_read(r1,348));self.finish(0)
  else:super().code(uc,pc,size,opaque)
rows=[]
for cipher in [1,4]:
 m=Request(cipher);m.put(WDEV+8,A);m.put(WDEV+20,0);m.cpu.mem_write(WDEV+32,n['PUBLIC']);m.put(WDEV+0x871,0)
 m.cpu.mem_write(A+0x1e22ac,struct.pack('<H',100));m.cpu.mem_write(A+0xceb70,b'\x01')
 assert m.invoke(0x40361efc,WDEV,0)==1 and m.request is not None
 b=m.request;s=b[32:196]
 assert s[0]==s[1]==0 and struct.unpack_from('<I',s,4)[0]==0x10020 and s[8]==2
 assert struct.unpack_from('<I',s,12)[0]==0x2101 and s[16]==1
 rows.append({'cipher':cipher,'entry':'40361efc','queue':'402f8194','request_bytes':348,'BMC_STA_offset':32,'BSS_offset':196,'BMC_connection':'10020','BMC_state':s[8],'BMC_features':hex(struct.unpack_from('<I',s,12)[0]),'BMC_new':s[16],'synthetic_BSS_feature_helper':True,'BMC_STA_request_hex':s.hex()})
result={'passed':True,'cases_passed':len(rows),'factory_sha256':n['ns']['ns']['ns']['SHA'],'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':rows,'physical_MCU_or_RF_emulated':False}
(R/'evidence/normal-ap-request.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
