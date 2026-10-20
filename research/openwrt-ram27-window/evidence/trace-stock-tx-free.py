from pathlib import Path
import json,struct,hashlib
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent;P=ROOT.parent/'management-tx/trace-stock-management.py'
if not P.exists():P=ROOT/'trace-stock-management.py'
R=ROOT.parent
ns={'__file__':str(P),'__name__':'trace_library'};exec(compile(P.read_text(),str(P),'exec'),ns)
Base=ns['MgmtModel'];A,H,DATA,RETURN,STACK=[ns[k] for k in ('A','H','DATA','RETURN','STACK')]
POOL=0x41c1e000;STATS=POOL+0x100
class FreeModel(Base):
 def __init__(self):
  super().__init__();self.tokens=[];self.accept=None;self.stride=None;self.opaque_free=[]
  self.put(A+0xa8134,POOL);self.put(POOL+12,STATS);self.put(POOL+0x48,4095)
 def code(self,uc,pc,size,o):
  r0,r1,r2,r3=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
  if pc==0x402b2fc8:
   self.accept=True;self.stride=self.get(uc.reg_read(UC_ARM_REG_FP)-60)
  if pc==0x402b2f9c:self.accept=False;uc.reg_write(UC_ARM_REG_SP,STACK);uc.reg_write(UC_ARM_REG_PC,RETURN)
  elif pc==0x402b2f60:self.accept=False;uc.reg_write(UC_ARM_REG_SP,STACK);uc.reg_write(UC_ARM_REG_PC,RETURN)
  elif pc==0x402e1f04:
   assert r0==POOL;self.tokens.append(r1);uc.mem_write(r2,b'\x01');self.finish(0x41c10000)
  elif pc==0x4033c4a8:
   assert r0==A and r1==0x41c10000;self.opaque_free.append(r1);self.finish(0)
  elif pc==0x402b3030:uc.reg_write(UC_ARM_REG_SP,STACK);uc.reg_write(UC_ARM_REG_PC,RETURN)
  else:super().code(uc,pc,size,o)
rows=[]
for version in (0,1,7):
 for count in (0,1,2,3,31,127):
  stride=2 if version==0 else 4;n=8+count*stride
  b=bytearray(n);struct.pack_into('<II',b,0,(6<<29)|(count<<16)|n,version<<16)
  tokens=[(i*31)%4096 for i in range(count)]
  for i,t in enumerate(tokens):struct.pack_into('<H',b,8+stride*i,t)
  m=FreeModel();m.cpu.mem_write(DATA,bytes(b));m.invoke(0x402b2f2c,A,DATA)
  assert m.accept is True and m.stride==stride and m.tokens==tokens and len(m.opaque_free)==count
  rows.append({'case':f'actual-format-v{version}-count{count}','version':version,'count':count,'embedded_bytes':n,'stride':stride,'tokens':tokens,'token_dequeue_calls':len(m.tokens),'packet_free_calls':len(m.opaque_free)})
for version,count,delta in ((0,1,-1),(0,1,1),(1,1,-1),(1,1,1),(7,127,-4)):
 stride=2 if not version else 4;n=8+count*stride;b=bytearray(n);struct.pack_into('<II',b,0,(6<<29)|(count<<16)|(n+delta),version<<16)
 m=FreeModel();m.cpu.mem_write(DATA,bytes(b));m.invoke(0x402b2f2c,A,DATA);assert m.accept is False and not m.tokens
 rows.append({'case':f'actual-length-reject-v{version}-count{count}-delta{delta}','token_dequeue_calls':0})
# Actual event-ring dispatch: callback selector is resolved by real wrapper.
from unicorn import UC_HOOK_CODE
for t in range(8):
 m=FreeModel();ops=m.invoke(0x402f289c,H);m.put(ops+0x174,0x4031b680);m.cpu.mem_write(DATA,struct.pack('<II',(t<<29)|8,0));seen=[]
 def stop(uc,pc,n,o):
  if pc in (0x402b2f2c,0x402ad7b8,0x402ab0dc,0x402ad95c,0x402ad92c,0x4033c4a8,0x402c15d0):
   seen.append(pc);uc.reg_write(UC_ARM_REG_SP,STACK);uc.reg_write(UC_ARM_REG_PC,RETURN)
 m.cpu.hook_add(UC_HOOK_CODE,stop);m.invoke(0x402b327c,A,1,0x41c1c000,DATA)
 assert bool(seen) and (seen[0]==0x402b2f2c)==(t==6)
 if t==7:assert seen[0]==0x402ad92c
 rows.append({'case':f'actual-RX1-dispatch-type{t}','callback':f'{seen[0]:08x}','TX_free_selected':t==6})
q={'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'passed':True,'cases_passed':len(rows),'source_sha256':'efdf45c9767bad9b30c93383ee2f5b99a38f5bc2441064e327b026097030fd95','handler':'402b2f2c','dispatcher':'402b327c','packet_type':6,'MCU_packet_type':7,'MCU_handler':'402ad92c','report_type_bits':[23,28],'count_bits':[16,22],'byte_count_bits':[0,15],'version_bits_DW1':[16,18],'token_offset':8,'token_read_bits':16,'version0_stride':2,'nonzero_version_stride':4,'cases':rows,'limits':['Actual OEM ARM handler and dispatcher, synthetic HIF callback binding/host table/OS token dequeue and packet free','MCU/RF/ACK not emulated; hardware short-packet content not yet captured','Outer DMA size is not checked by OEM handler: new core must independently bound all reads','TX-free is host buffer completion, not an RF ACK; retain per-boot pool in this test']}
d=ROOT;(d/'stock-tx-free-traces.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps({'passed':True,'cases_passed':len(rows)}))
