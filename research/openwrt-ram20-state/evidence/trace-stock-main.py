#!/usr/bin/env python3
"""Scoped actual OEM main parser/loader/sync callbacks; synthetic host services.
No MCU firmware, physical DMA, power or radio emulation. Own analysis code: MIT.
The shared service model is loaded without executing or rewriting its test runs.
"""
from pathlib import Path
import hashlib,json,struct,zlib
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3
ROOT=Path(__file__).resolve().parent
BASE_SCRIPT=ROOT.parent/'firmware-download/trace-stock-download.py'
if not BASE_SCRIPT.exists():BASE_SCRIPT=ROOT/'trace-stock-download.py'
ns={'__file__':str(BASE_SCRIPT)}
# Bounded1501-poll OEM timeout requires more instructions than short packet tests.
exec(compile(BASE_SCRIPT.read_text().split('\ncases=[]')[0].replace('count=30000','count=1000000').replace('timeout=1_000_000','timeout=5_000_000'),str(BASE_SCRIPT),'exec'),ns)
Model=ns['Model'];A,H,HIF,FW,MSG,SKB,DATA,OUT,OBJECT,CAP=[ns[k] for k in ('A','H','HIF','FW','MSG','SKB','DATA','OUT','OBJECT','CAP')]
RESEARCH=ns['RESEARCH'];SHA=ns['SHA']
MAIN=(RESEARCH/'firmware-ru-240812/minifs/fw/mtk/WIFI_RAM_CODE_7626.bin').read_bytes()
assert len(MAIN)==25808 and hashlib.sha256(MAIN).hexdigest()=='76a9a4fb62be68725fba016d0814911255cf62b819d41760198dc7e3911322b5'
REGIONS=((0x20400,2896),(0x2010000,1584),(0x40100000,21136))
class MainModel(Model):
 def __init__(self,*,sync=(2,),fail_cid=None,fail_nth=1,allocation_fail=False):
  self.main_mode=True;self.allocation_fail=allocation_fail
  super().__init__(fail_cid=fail_cid,fail_nth=fail_nth)
  self.cpu.mem_write(FW,MAIN);self.put(CAP+0x11c,1)
  self.put(A+0x33c188,FW);self.put(A+0x33c18c,len(MAIN))
  self.put(CAP+0x108,1);self.put(CAP+0x10d,1);self.put(CAP+0x114,2)
  self.put(HIF+0x7c,0x18000000);self.sync_values=iter(sync);self.last_sync=2
  self.sync_reads=[];self.delays=0
  self.put(H+0x9c4+0x190,0x40307a3c)
  self.invoke(0x402f54ac,H)
  def rd(uc,off,size,opaque):
   assert off==0x140 and size==4
   try:self.last_sync=next(self.sync_values)
   except StopIteration:pass
   self.sync_reads.append(self.last_sync);return self.last_sync
  def wr(*args):raise AssertionError('No sync MMIO writes permitted')
  self.cpu.mmio_map(0x180c1000,0x1000,rd,None,wr,None)
 def code(self,uc,pc,size,opaque):
  r0,r1,r2,r3=[uc.reg_read(x) for x in ns['REGS']]
  if pc==0x4033bee8 and self.main_mode:
   assert r0==A and r2==84
   if self.allocation_fail:self.finish(3)
   else:self.put(r1,OBJECT);uc.mem_write(OBJECT,bytes(84));self.finish(0)
  elif pc==0x4033bed8:
   assert r0==1;self.delays+=1;self.finish(0)
  else:super().code(uc,pc,size,opaque)
 def parse(self):
  rc=self.invoke(0x402ef9e0,A,0,OUT)
  if self.allocation_fail:return rc,[]
  assert not rc and self.get(OUT)==OBJECT and self.cpu.mem_read(OUT+4,1)[0]==3
  metadata=[];offset=0
  for i,(addr,length) in enumerate(REGIONS):
   p=OBJECT+i*28;ptr,destination,n=tuple(self.get(p+j*4) for j in range(3))
   feature=self.cpu.mem_read(p+12,1)[0]
   assert (ptr,destination,n,feature)==(FW+offset,addr,length,0)
   assert bytes(self.cpu.mem_read(ptr,n))==MAIN[offset:offset+n]
   metadata.append({'index':i,'offset':offset,'destination':hex(destination),'bytes':n,'feature':feature,'crc32':f'{zlib.crc32(MAIN[offset:offset+n]):08x}'})
   offset+=n
  assert offset==25616 and MAIN[offset:offset+36]==b'################\0\0\0\0################'
  return rc,metadata

cases=[];m=MainModel();rc,regions=m.parse();cases.append({'case':'actual-parser-three-regions','result':rc,'regions':regions})
# Actual selector config chooses compressed-capable loader and V2-format parser.
m=MainModel();m.put(CAP+0x104,1);assert m.invoke(0x402f05bc,A)==0
assert m.get(A+0x33c170)==0x402ef6b0 and m.get(A+0x33c178)==0x402ef9e0
cases.append({'case':'actual-function-selector','loader':'0x402ef6b0','parser':'0x402ef9e0'})
m=MainModel();m.parse();assert m.invoke(0x402ef6b0,A,0,OUT)==0
calls=m.calls;assert calls[-1]['cid']==2 and bytes.fromhex(calls[-1]['body_hex'])==bytes(8)
scatter=[];offset=0;index=0
for region in regions:
 addr=calls[index];index+=1
 assert addr['cid']==1 and bytes.fromhex(addr['body_hex'])==struct.pack('<III',int(region['destination'],16),region['bytes'],0x80000000)
 payload=bytearray();sizes=[]
 while index<len(calls) and calls[index]['cid']==0xee:
  packet=calls[index];index+=1;payload+=bytes.fromhex(packet['body_hex']);sizes.append(packet['bytes'])
 assert payload==MAIN[offset:offset+region['bytes']]
 assert sizes==([960]*(region['bytes']//960)+([region['bytes']%960] if region['bytes']%960 else []))
 scatter.append(sizes);offset+=region['bytes']
assert index==len(calls)-1 and offset==25616 and len(calls)==33
cases.append({'case':'actual-loader-all-regions-and-start','command_CIDs':[x['cid'] for x in calls],'scatter_sizes':scatter,'start_body_hex':calls[-1]['body_hex']})
# Abort branches must stop at the failed real OEM builder/send, never start early.
for cid,nth in ((1,1),(1,2),(1,3),(0xee,1),(0xee,4),(0xee,6),(0xee,29),(2,1)):
 m=MainModel(fail_cid=cid,fail_nth=nth);m.parse();rc=m.invoke(0x402ef6b0,A,0,OUT)
 assert rc==5 and m.calls[-1]['cid']==cid
 assert not any(x['cid']==2 for x in m.calls[:-1])
 cases.append({'case':f'loader-send-failure-{cid}-{nth}','result':rc,'calls':len(m.calls)})
m=MainModel(allocation_fail=True);rc,metadata=m.parse();assert rc==3 and not metadata and not m.calls
cases.append({'case':'parser-allocation-failure','result':rc})
# Decode actual host-state bits; no synthesized state interpretation.
for raw in (0,2,6,14,0xa5a50002,0xffffffff):
 m=MainModel(sync=(raw,));value=m.invoke(0x402a2e44,A)
 assert value==(raw>>1)&7
 cases.append({'case':f'host-sync-read-{raw:08x}','decoded':value,'CPU_register':'0x180c1140'})
for raw_values,success in (((2,),False),((6,),True),((2,2,6),True),((0,),False)):
 m=MainModel(sync=raw_values);rc=m.invoke(0x402ef0e4,A,3)
 assert rc==(0 if success else 1)
 assert m.delays==(0 if raw_values==(6,) else 1 if raw_values==(2,2,6) else 1501)
 cases.append({'case':'post-main-sync-'+','.join(map(str,raw_values)),'result':rc,'reads':len(m.sync_reads),'mode':3,'wanted_decoded_state':3,'delay_calls':m.delays})
# Capture exact packet oracles for all region-address/start and every fragment.
packets=[];seq=7
for i,region in enumerate(regions):
 seq=seq%15+1;m=MainModel();p=m.packet(0x40313d04,(int(region['destination'],16),region['bytes'],0x80000000),seq);p['name']=f'main-address-{i}';packets.append(p)
 n=region['bytes'];offset=region['offset'];j=0
 while n:
  length=min(n,960);seq=seq%15+1;m=MainModel();p=m.packet(0x40313e50,(FW+offset,length),seq);p['name']=f'main-scatter-{i}-{j}';packets.append(p)
  offset+=length;n-=length;j+=1
seq=seq%15+1;m=MainModel();p=m.packet(0x4031408c,(0,0),seq);p['name']='main-start';packets.append(p)
assert len(packets)==33 and seq==10
cases.append({'case':'33-actual-packet-oracles-with-sequence-wrap','passed':True,'last_wire_sequence':seq})
# Real OEM sender sequence-selection branch, stopped before ACK-queue traversal.
# fp/local pointer and adapter counter are synthetic; the increment/wrap is ARM.
from unicorn.arm_const import UC_ARM_REG_R11,UC_ARM_REG_PC
for old in (0,14,15,255):
 m=MainModel();fp=ns['STACK']-4;ctx=A+0x33c000
 m.cpu.reg_write(UC_ARM_REG_R11,fp);m.put(fp-56,ctx);m.cpu.mem_write(ctx+0xb0,bytes([old]))
 def seq_stop(uc,pc,size,opaque):
  if pc==0x40261ad0:uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,ns['RETURN'])
 m.cpu.hook_add(UC_HOOK_CODE,seq_stop)
 assert m.invoke(0x40261ab0)==0
 value=m.cpu.mem_read(ctx+0xb0,1)[0];assert value==(old+1 if old<=14 else 1)
 cases.append({'case':f'actual-sender-sequence-{old}','next':value,'queue-tail-skipped':True})
report={'scope':__doc__,'source_sha256':SHA,'cases_passed':len(cases),'hardware_tested':False,'main_file':{'bytes':len(MAIN),'sha256':hashlib.sha256(MAIN).hexdigest(),'crc32':f'{zlib.crc32(MAIN):08x}'},'regions':regions,'scatter_sizes':scatter,'post_start_sync':{'CPU_address':'0x180c1140','state_mask':'0x0000000e','wanted_state':3,'wanted_raw_masked':'0x00000006','initial_download_state':1,'OEM_delay_units_not_determined':True,'OEM_max_delay_calls':1501},'cases':cases,'packets':packets,'limitations':['Synthetic allocations, services, MMIO values and MCU response/send result; real scoped ARM parser/loader/builders/selector/state decode executed','No MCU firmware execution or physical-ready proof','Exact supplied image only, flags0/no entry override','State getters register mapping observed from actual OEM wrapper, not substituted register-offset decoding']}
(ROOT/'stock-main-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'OEM main firmware ARM model: {len(cases)} cases passed, 3 regions/29 fragments/33 packets, ready-state callback; hardware effects synthetic.')
