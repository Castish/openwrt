#!/usr/bin/env python3
"""Own MIT protocol analysis using factory ARM builders and synthetic keys/OS.
No real firmware, DMA, crypto engine, air interface or secret is executed.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn.arm_const import *
R=Path(__file__).resolve().parent

def library(p,split=None):
 t=p.read_text();t=t.split(split)[0] if split else t
 n={'__file__':str(p),'__name__':'library'};exec(compile(t,str(p),'exec'),n);return n
k=library(R/'trace-stock-keys.py','\nrows=');S=library(R.parent/'wifi-bringup/station-init/trace-stock-station.py')
D=library(R.parent/'openwrt-ram31-scheduler/evidence/trace-stock-data.py')
rows=[]
for op,wcid,idx in [(0,1,0),(1,1,0),(2,0,1),(3,0,1)]:
 m=k['Keys']();b=bytearray(92);b[0]=op;b[1]=2;struct.pack_into('<I',b,4,0x20);b[8]=wcid;b[10]=idx;b[11:27]=bytes((n*13+3)&255 for n in range(16));b[91]=16
 m.cpu.mem_write(k['ARG'],bytes(b));assert m.invoke(0x402a3c6c,k['A'],k['ARG'])==0
 assert len(m.calls)==(2 if op&1 else 1)
 for j,c in enumerate(m.calls):
  body=bytes.fromhex(c['body_hex']);assert len(body)==52 and body[0]==wcid and body[12]==(op&1) and body[13]==(0 if op&1 else 1)
  assert c['flags']==15 and body[15]==(10 if op&1 and j==0 else 4)
 rows.append({'kind':'key','operation':op,'wcid':wcid,'index':idx,'bodies':[c['body_hex'] for c in m.calls],'attributes':[c['attributes_hex'] for c in m.calls]})
for kind,wcid,aid,peer,conn,state,feature,new in [('bmc-on',0,0,b'\xff'*6,0x10020,2,0x2001,1),('bmc-off',0,0,b'\xff'*6,0x10020,0,1,0),('peer-prepare',1,1,S['PEER'],0x10001,1,0x2001,1),('peer-authorize',1,1,S['PEER'],0x10001,2,1,0),('peer-unauthorize',1,1,S['PEER'],0x10001,1,1,0)]:
 m=S['StaModel'](aid,wcid,peer)
 if not wcid:m.put(S['A']+0x71560,0x400)
 cfg=bytearray(156);cfg[:4]=bytes([0,wcid,state,0]);struct.pack_into('<II',cfg,4,conn,feature);cfg[12]=new;struct.pack_into('<I',cfg,148,S['ENTRY'])
 m.cpu.mem_write(S['STACK'],bytes(cfg[12:]));assert m.invoke(0x402ede60,S['A'],*struct.unpack_from('<3I',cfg))==0 and len(m.calls)==1
 rows.append({'kind':kind,'body_hex':m.calls[0]['body_hex'],'attributes_hex':m.calls[0]['attributes_hex']})
for protect in [0,1]:
 n=D['ns'];m=n['LowerModel']();n['chip_caps'](m);assert m.invoke(0x40274848,n['A'],n['WDEV'],n['CTX'])==0
 info=bytearray.fromhex(m.saved[0]['info_hex']);info[0]=1;info[25]=protect;info[29]=2;info[30]=0;struct.pack_into('<I',info,16,92)
 m.cpu.mem_write(n['OUTPUT'],bytes(info));m.cpu.mem_write(n['PHY'],bytes(4));m.put(n['CTX']+36,124);m.put(n['PKT']+8,124)
 f=bytearray(92);struct.pack_into('<HH',f,0,0x0208|(protect<<14),304);f[4:10]=n['PEER'];f[10:16]=f[16:22]=n['MAC'];m.cpu.mem_write(n['DATA']+32,bytes(f))
 ops=m.invoke(0x402f289c,n['H'])
 for off,v in [(0x15c,0x403199fc),(0x13c,0x4031a5b4),(0x140,0x402f30bc)]:m.put(ops+off,v)
 m.put(n['A']+0xa8134,n['POOL']);m.put(n['POOL']+0x48,4095);m.cpu.mem_write(n['CTX'],b'\x05');m.put(n['CTX']+80,n['INFO'])
 hif=m.invoke(0x402f2884,n['H']);m.put(hif+0x10,n['TXRING']);ring=n['TXRING']+5*88;cell=n['CELL']+2*40
 m.put(ring+8,cell-2*40);m.put(ring+36,2);m.put(cell+4,n['DESC']);m.put(cell+28,n['INFO'])
 m.lower=True;m.token=16;m.put(n['STACK'],n['CTX']);assert m.invoke(0x40316eb4,n['A'],n['DATA'],n['OUTPUT'],n['PHY'])==0
 h=bytes(m.cpu.mem_read(n['INFO'],64));assert bool(h[12]&2)==bool(protect)
 rows.append({'kind':'data-protected' if protect else 'data-clear','TXD_hex':h[:32].hex(),'TXP_hex':h[32:].hex(),'host_metadata_protect_offset':25})
a=bytes.fromhex(rows[-2]['TXD_hex']);b=bytes.fromhex(rows[-1]['TXD_hex']);assert [(i,a[i]^b[i]) for i in range(32) if a[i]!=b[i]]==[(12,2)]
B=library(R.parent/'wifi-bringup/bss-init/trace-stock-bss.py','\ncases=[];packets=[]')
for off in [0,1]:
 m=B['BSSModel']();arg=B['args'](state=1 if off else 2,features=2 if off else 3,cipher=4,beacon=100,dtim=1)
 m.cpu.mem_write(B['ARG'],arg);assert m.invoke(0x402ee440,B['A'],B['ARG'])==0 and len(m.calls)==1
 rows.append({'kind':'bss-CCMP-off' if off else 'bss-CCMP-on','body_hex':m.calls[0]['body_hex']})
d={'passed':True,'cases_passed':len(rows),'factory_sha256':k['ns']['ns']['SHA'],'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':rows,'hardware_tested':False,'firmware_acceptance_or_RF_emulated':False}
(R/'evidence/stock-security-traces.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({'passed':True,'cases_passed':len(rows)}))
