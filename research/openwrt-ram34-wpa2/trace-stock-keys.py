#!/usr/bin/env python3
"""Own MIT analysis: actual OEM key/WTBL builder, synthetic nonsecret keys/OS.
No firmware/DMA/RF is executed. The private factory image is never packaged.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn.arm_const import *
r=Path(__file__).resolve().parent;p=r.parent/'wifi-bringup/mac-init/trace-stock-devinfo.py'
ns={'__file__':str(p),'__name__':'library'};exec(compile(p.read_text().split('\ncases=[]')[0],str(p),'exec'),ns)
Base=ns['DevModel'];A,H,MSG,SKB,DATA,STACK=[ns[k] for k in ['A','H','MSG','SKB','DATA','STACK']]
ARG=0x41c1b000
class Keys(Base):
 def code(self,uc,pc,size,opaque):
  r0,r1,r2=[uc.reg_read(k) for k in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]]
  if pc==0x4033c0b8:
   assert 0<r2<=512;uc.mem_write(r0,bytes(uc.mem_read(r1,r2)));self.finish(r0)
  else:super().code(uc,pc,size,opaque)
def run(operation=0,direction=2,wcid=1,keyid=0,keybytes=16):
 m=Keys();b=bytearray(92);b[0]=operation;b[1]=direction;struct.pack_into('<I',b,4,0x20);b[8]=wcid;b[10]=keyid
 b[11:11+keybytes]=bytes((n*13+3)&255 for n in range(keybytes));b[91]=keybytes
 m.cpu.mem_write(ARG,bytes(b));rc=m.invoke(0x402a3c6c,A,ARG);assert rc==0 and len(m.calls)==(2 if keybytes==32 or operation in (1,3) else 1),(operation,direction,rc,m.calls)
 out=[]
 for c in m.calls:
  out.append(c)
 m.cpu.mem_write(MSG+22,b'\x09');m.invoke(0x4026249c,MSG,SKB)
 packet=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)))
 assert packet[41]==0x32 and packet[38]==1 and packet[43]==1
 return {'operation':operation,'direction':direction,'wcid':wcid,'keyid':keyid,'keybytes':keybytes,'body_hex':m.calls[-1]['body_hex'],'attributes_hex':m.calls[-1]['attributes_hex'],'packet_hex':packet.hex(),'callback':m.calls[-1]['callback']}
rows=[run(op,di,w,idx) for op,w,idx in [(0,1,0),(1,1,0),(2,0,1),(3,0,1)] for di in [0,1,2]]
d={'passed':True,'cases_passed':len(rows),'factory_sha256':ns['ns']['SHA'],'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':rows,'hardware_tested':False,'firmware_acceptance_or_RF_emulated':False}
(r/'evidence/stock-key-traces.json').write_text(json.dumps(d,indent=2)+'\n')
for x in rows:print(x['operation'],x['direction'],x['wcid'],x['body_hex'],x['attributes_hex'])
