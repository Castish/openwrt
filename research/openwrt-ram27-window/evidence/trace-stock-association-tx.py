#!/usr/bin/env python3
"""Actual OEM association-response TXD/TXP/descriptor/publication with explicit WCID.
Own analysis code SPDX-License-Identifier: MIT; host context/DMA maps synthetic.
"""
from pathlib import Path
import json,struct,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent;P=ROOT.parent/'management-tx/trace-stock-management.py'
if not P.exists():P=ROOT/'trace-stock-management.py'
ns={'__file__':str(P),'__name__':'library'};exec(compile(P.read_text(),str(P),'exec'),ns)
M=ns['LowerModel'];A,H,DATA,CTX,PKT,INFO,PHY,OUTPUT,TXRING,CELL,DESC,POOL,STACK=[ns[k] for k in ('A','H','DATA','CTX','PKT','INFO','PHY','OUTPUT','TXRING','CELL','DESC','POOL','STACK')]
def run(wcid,index,token):
 m=M(subtype=1);ns['chip_caps'](m);m.put(CTX+36,68);m.put(PKT+8,68)
 f=bytearray(36);struct.pack_into('<HH',f,0,0x10,304);f[4:10]=ns['PEER'];f[10:16]=f[16:22]=ns['MAC'];struct.pack_into('<HHH',f,24,1,0,0xc001);f[30:]=bytes([1,4,0x82,0x84,0x8b,0x96]);m.cpu.mem_write(DATA+32,bytes(f))
 assert m.invoke(0x40274848,A,ns['WDEV'],CTX)==0
 info=bytearray.fromhex(m.saved[0]['info_hex']);info[0]=wcid # our explicit already-created STA context
 m.cpu.mem_write(OUTPUT,bytes(info));m.cpu.mem_write(PHY,bytes(4))
 ops=m.invoke(0x402f289c,H)
 for off,v in ((0x15c,0x403199fc),(0x13c,0x4031a5b4),(0x140,0x402f30bc)):m.put(ops+off,v)
 m.put(A+0xa8134,POOL);m.put(POOL+0x48,4095);m.cpu.mem_write(CTX,b'\x05');m.put(CTX+80,INFO)
 hif=m.invoke(0x402f2884,H);m.put(hif+0x10,TXRING);ring=TXRING+5*88;cell=CELL+40 if index==1 else 0x41c00000+index*40
 m.put(ring+8,cell-index*40);m.put(ring+36,index);m.put(cell+4,DESC);m.put(cell+28,INFO)
 m.lower=True;m.token=token;m.put(STACK,CTX);assert m.invoke(0x40316eb4,A,DATA,OUTPUT,PHY)==0
 hdr=bytes(m.cpu.mem_read(INFO,64));desc=bytes(m.cpu.mem_read(DESC,16))
 assert hdr[:4]==bytes.fromhex('44000040') and hdr[4]==wcid and hdr[30]==1
 txp=bytearray(32);struct.pack_into('<H',txp,0,token|0x8000);struct.pack_into('<IH',txp,8,0x41420000,0x8024)
 assert hdr[32:]==txp and desc==struct.pack('<4I',0x41410000,0x40400000,0x41420000,0)
 expected=(index+1)%512;assert m.get(ring+36)==expected
 m.put(hif+0x7c,0x18000000);m.put(ring+32,0x4358);m.invoke(0x402f54ac,H);writes=[]
 def rd(*args):raise AssertionError('unexpected MMIO read')
 def wr(uc,off,n,value,o):
  assert (off,n,value)==(0x358,4,expected);writes.append(value)
  assert bytes(uc.mem_read(DESC,16))==desc and bytes(uc.mem_read(INFO,64))==hdr
 m.cpu.mmio_map(0x18004000,0x1000,rd,None,wr,None);m.invoke(0x402f3424,A,CTX,5);assert writes==[expected]
 return {'case':f'actual-assoc-response-wcid{wcid}-slot{index}-token{token}','wcid':wcid,'slot':index,'token':token,'PHY':'CCK1/20','TXD_hex':hdr[:32].hex(),'TXP_hex':hdr[32:].hex(),'frame_hex':f.hex(),'descriptor_hex':desc.hex(),'next_producer':expected,'publisher':'402f3424','CPU_register':'18004358','payload_bytes':36}
def full_report():
 rows=[run(w,i,t) for w in (0,1) for i in (1,511) for t in (1,31)]
 q={'passed':True,'cases_passed':len(rows),'source_sha256':'efdf45c9767bad9b30c93383ee2f5b99a38f5bc2441064e327b026097030fd95','verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':rows,'profile':next(x for x in rows if x['wcid']==1 and x['slot']==1 and x['token']==1),
 'limits':['Actual OEM unassociated-management input policy, then explicit WCID1 chosen by this port; factory host caller selection of a peer record not emulated','Actual TXD/TXP/descriptor/publisher, synthetic HIF/OS/token/DMA context','Standard association-response frame has capabilityESS/open,success0,AID1|c000 and four basic CCK rates matching beacon','No firmware STA acceptance, RF/FCS/ACK, successful association or data connectivity established']}
 (ROOT/'stock-association-tx-traces.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps({'passed':True,'cases_passed':len(rows),'profile_TXD':q['profile']['TXD_hex']}))
if __name__=='__main__':full_report()
