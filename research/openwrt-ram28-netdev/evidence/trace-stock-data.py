#!/usr/bin/env python3
"""Actual OEM RX metadata and explicit raw legacy-data TXD/TXP/HIF profile.
Own analysis code: SPDX-License-Identifier: MIT. Host/MCU/DMA/RF synthetic.
"""
from pathlib import Path
import json,struct,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent;P=ROOT.parent/'management-tx/trace-stock-management.py'
if not P.exists():P=ROOT/'trace-stock-management.py'
ns={'__file__':str(P),'__name__':'library'};exec(compile(P.read_text(),str(P),'exec'),ns)
M=ns['LowerModel'];A,H,DATA,CTX,PKT,INFO,PHY,OUTPUT,TXRING,CELL,DESC,POOL,STACK,RETURN=[ns[k] for k in ('A','H','DATA','CTX','PKT','INFO','PHY','OUTPUT','TXRING','CELL','DESC','POOL','STACK','RETURN')]
RXBLK=0x41c1b800
def rx_case(group,pad,translated,errors=0):
 m=M();m.put(A+0xa9d40,0x7626);raw=bytearray(256)
 struct.pack_into('<III',raw,0,256|(group<<25)|(2<<29),(pad<<22)|(translated<<23)|2,1|errors)
 off=16+16*bool(group&8)+16*bool(group&1)+8*bool(group&2)+24*bool(group&4)+2*pad
 struct.pack_into('<H',raw,16,0x0108);raw[18:24]=ns['PEER'];struct.pack_into('<HH',raw,24,0x1230,0)
 raw[off:off+6]=ns['MAC'];raw[off+6:off+12]=ns['PEER'];raw[off+12:off+14]=b'\x08\x06'
 if not translated:
  struct.pack_into('<H',raw,off,0x0108);raw[off+4:off+10]=ns['MAC'];raw[off+10:off+16]=ns['PEER'];raw[off+16:off+22]=b'\xff'*6
 m.cpu.mem_write(DATA,bytes(raw));m.put(PKT+12,DATA);m.put(PKT+8,256)
 lookup=[]
 def host(uc,pc,size,opaque):
  if pc in (0x40360ff4,0x40360edc):lookup.append(pc);m.finish(ns['WDEV'])
 m.cpu.hook_add(UC_HOOK_CODE,host);ret=m.invoke(0x4031b68c,A,RXBLK,PKT)
 flags=bytes(m.cpu.mem_read(RXBLK+12,4));p=m.get(RXBLK+60)
 assert p==DATA+off and m.get(PKT+8)==256-off
 if translated:
  assert ret!=0 and m.get(RXBLK+28)==DATA+16 and lookup
  assert m.get(RXBLK+44)==DATA+off+6 and m.get(RXBLK+48)==DATA+off
 else:assert m.get(RXBLK+28)==p and m.get(RXBLK+40)==p+4 and m.get(RXBLK+44)==p+10
 # Original byte10 bits1/4 -> exported FCS/ICV error flags in byte13.
 assert bool(flags[1]&1)==bool(errors&(1<<17))
 assert bool(flags[1]&2)==bool(errors&(1<<20))
 return {'case':f'RX-groups{group:x}-pad{pad}-translated{translated}-errors{errors:08x}','entry':'4031b68c','offset':off,'FC_group4_offset':16 if translated else None,'group4_transmitter_offset':18 if translated else None,'WLAN_index_offset':8,'FCS_error_bit':17,'ICV_error_bit':20,'flags_hex':flags.hex(),'factory_performs_length_validation':False,'lookup_stubbed':bool(lookup)}
def tx_case(length,slot,token):
 m=M();ns['chip_caps'](m);assert m.invoke(0x40274848,A,ns['WDEV'],CTX)==0
 info=bytearray.fromhex(m.saved[0]['info_hex']);info[0]=1;info[29]=2;info[30]=0;struct.pack_into('<I',info,16,length)
 m.cpu.mem_write(OUTPUT,bytes(info));m.cpu.mem_write(PHY,bytes(4));m.put(CTX+36,length+32);m.put(PKT+8,length+32)
 f=bytearray(length);struct.pack_into('<HH',f,0,0x0208,304);f[4:10]=ns['PEER'];f[10:16]=f[16:22]=ns['MAC'];m.cpu.mem_write(DATA+32,bytes(f))
 ops=m.invoke(0x402f289c,H)
 for off,v in ((0x15c,0x403199fc),(0x13c,0x4031a5b4),(0x140,0x402f30bc)):m.put(ops+off,v)
 m.put(A+0xa8134,POOL);m.put(POOL+0x48,4095);m.cpu.mem_write(CTX,b'\x05');m.put(CTX+80,INFO)
 hif=m.invoke(0x402f2884,H);m.put(hif+0x10,TXRING);ring=TXRING+5*88;cell=CELL+slot*40
 m.put(ring+8,cell-slot*40);m.put(ring+36,slot);m.put(cell+4,DESC);m.put(cell+28,INFO)
 m.lower=True;m.token=token;m.put(STACK,CTX);assert m.invoke(0x40316eb4,A,DATA,OUTPUT,PHY)==0
 hdr=bytes(m.cpu.mem_read(INFO,64));desc=bytes(m.cpu.mem_read(DESC,16))
 assert struct.unpack_from('<H',hdr)[0]==length+32 and hdr[3:5]==b'\x40\x01' and hdr[30]==0x20
 txp=bytearray(32);struct.pack_into('<H',txp,0,token|0x8000);struct.pack_into('<IH',txp,8,0x41420000,0x8000|length)
 assert hdr[32:]==txp and desc==struct.pack('<4I',0x41410000,0x40400000,0x41420000,0)
 expected=(slot+1)%512;assert m.get(ring+36)==expected
 m.put(hif+0x7c,0x18000000);m.put(ring+32,0x4358);m.invoke(0x402f54ac,H);writes=[]
 def rd(*a):raise AssertionError('unexpected MMIO read')
 def wr(uc,off,n,value,o):
  assert (off,n,value)==(0x358,4,expected);writes.append(value)
  assert bytes(uc.mem_read(DESC,16))==desc and bytes(uc.mem_read(INFO,64))==hdr
 m.cpu.mmio_map(0x18004000,0x1000,rd,None,wr,None);m.invoke(0x402f3424,A,CTX,5);assert writes==[expected]
 return {'case':f'raw-data-length{length}-slot{slot}-token{token}','WCID':1,'frame_type':2,'subtype':0,'PHY':'CCK1/20','LMAC_queue':16,'format':0,'entry':'40316eb4','TXD_hex':hdr[:32].hex(),'TXP_hex':hdr[32:].hex(),'descriptor_hex':desc.hex(),'frame_bytes':length,'token':token,'slot':slot,'next_CPU':expected,'caller_metadata_profile_explicit':True}
def full_report():
 rows=[rx_case(g,p,t) for g in range(16) for p in (0,1) for t in (0,1) if not t or g&8]
 rows +=[rx_case(8,0,1,1<<bit) for bit in (16,17,18,19,20,23,24,25)]
 tx=[tx_case(n,s,t) for n in (60,92,124) for s in (2,3) for t in (2,3)]
 rows+=tx
 report={'passed':True,'cases_passed':len(rows),'source_sha256':'efdf45c9767bad9b30c93383ee2f5b99a38f5bc2441064e327b026097030fd95','script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':rows,'profile':tx[0],
 'limits':['Real ARM RX metadata/offset/flags and TXD/TXP/descriptor/publisher instructions; synthetic host services/context','Data TX profile is explicitly selected from proven fixed-rate raw builder, not full factory AP policy or hardware acceptance','Translated RX requires original group4 TA+FC, matching pinned peer/Ethernet SA and WCID1; own BSSID comes from validated STA context','Independent FCS and RF ACK not proven; HW error flags are observed, untrusted lengths checked separately in port','No firmware/MCU/DMA/RF/phone or IP stack emulation']}
 (ROOT/'stock-data-traces.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases_passed':len(rows),'profile_TXD':tx[0]['TXD_hex']}))
if __name__=='__main__':full_report()
