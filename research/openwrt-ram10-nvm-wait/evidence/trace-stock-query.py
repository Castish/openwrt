#!/usr/bin/env python3
"""Actual OEM MT7626 runtime GET interrupt counter and host IRQ-mask disable.
Synthetic OS/MMIO/MCU replies, no physical hardware or MCU firmware execution.
No instructions are rewritten. Own analysis: SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'firmware-download/trace-stock-download.py'
if not BASE.exists(): BASE=ROOT/'trace-stock-download.py'
ns={'__file__':str(BASE)}
exec(compile(BASE.read_text().split('\ncases=[]')[0],str(BASE),'exec'),ns)
Model=ns['Model']
A,H,HIF,MSG,SKB,DATA,OUT,STACK=(ns[x] for x in ('A','H','HIF','MSG','SKB','DATA','OUT','STACK'))

class QueryModel(Model):
    def code(self,uc,pc,size,opaque):
        if pc==0x4033c098: # OEM zero-buffer OS service is synthetic.
            ptr,n=uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1)
            assert n<=104 and 0x41e00000<=ptr<=ptr+n<=0x41e10000
            uc.mem_write(ptr,bytes(n));self.finish(0)
        elif pc==0x402c27f8: # IRQ software predicate/lock helper, not executed.
            self.finish(0)
        else: super().code(uc,pc,size,opaque)

cases=[];packets=[]
for seq in (1,11,15):
    m=QueryModel();m.put(STACK,OUT)
    assert m.invoke(0x40314588,A,0,1,1)==0
    assert len(m.calls)==1
    call=m.calls[0]
    body=bytes.fromhex(call['body_hex'])
    expected=struct.pack('<H2xBB2xI',5,0,1,1)+bytes(92)
    assert body==expected and call['cid']==0xed and call['callback']=='0x4030f1e0'
    m.cpu.mem_write(MSG+22,bytes([seq]))
    m.invoke(0x4026249c,MSG,SKB)
    packet=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)))
    assert len(packet)==168 and packet[36]==0xed and packet[39]==seq
    # Values are retained directly from actual OEM builder/header execution.
    packets.append(dict(call,sequence=seq,packet_hex=packet.hex(),name=f'counter-query-seq{seq}'))
    cases.append({'case':f'actual-runtime-query-builder-{seq}','bytes':len(packet),
                  'query_byte':packet[38],'extension_byte':packet[41],
                  'payload_hex':body.hex(),'callback':call['callback']})

# Actual callback copies only returned counters from body+8, count at+4.
# Linux will impose its own length/category/count bounds before parsing.
for count in (0,1,2):
    m=QueryModel();m.put(MSG+12,OUT)
    values=[0x12345678,0x9abcdef0]
    body=struct.pack('<HBBI',5,0,0,count)+struct.pack('<2I',*values)
    m.cpu.mem_write(DATA,body);m.cpu.mem_write(OUT,b'\xa5'*32)
    m.invoke(0x4030f1e0,MSG,DATA,len(body))
    assert bytes(m.cpu.mem_read(OUT,32))==struct.pack('<2I',*values)[:4*count]+b'\xa5'*(32-4*count)
    cases.append({'case':f'actual-counter-callback-{count}','count':count,'counter_offset':8,'count_offset':4})

# Execute the actual EIDed branch up to callback dispatch, stopping before the
# surrounding OS queue/completion tail. The event header is synthetic.
from unicorn.arm_const import UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_PC
m=QueryModel();m.put(SKB+12,DATA);m.put(MSG+16,0x4030f1e0)
m.cpu.mem_write(MSG+6,struct.pack('<H',12))
m.cpu.mem_write(DATA,struct.pack('<HHBBBBB3x',24,0xe000,0xed,11,0,0,0x3c)+struct.pack('<HBBII',5,0,0,1,0x12345678))
m.put(MSG+12,OUT);seen=[]
def dispatch(uc,pc,size,opaque):
    if pc==0x4030f1e0:
        seen.append((uc.reg_read(UC_ARM_REG_R1),uc.reg_read(UC_ARM_REG_R2)))
    if pc==0x40264120:
        uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,ns['RETURN'])
m.cpu.hook_add(UC_HOOK_CODE,dispatch)
for reg,val in ((UC_ARM_REG_R3,0xed),(UC_ARM_REG_R5,MSG),(UC_ARM_REG_R6,DATA),(UC_ARM_REG_R10,SKB)):
    m.cpu.reg_write(reg,val)
# Non-generic EIDs use the12-byte event header before callback body.
assert m.invoke(0x402637b4)==0
assert seen==[(DATA+12,12)] and m.get(OUT)==0x12345678
cases.append({'case':'actual-EIDed-dispatch-body-offset','event_header_bytes':12,'callback_body_bytes':12})

for initial in (0x20000000,):
    m=QueryModel();m.put(HIF+0x7c,0x18000000);m.invoke(0x402f54ac,H)
    accesses=[]
    def rd(uc,off,size,unused):
        raise AssertionError(('unexpected MMIO read',hex(off)))
    def wr(uc,off,size,v,page):
        assert page+off in (0x18004204,0x180f0188) and size==4
        accesses.append({'address':hex(page+off),'value':hex(v)})
    for page in (0x18004000,0x180f0000):m.cpu.mmio_map(page,0x1000,rd,None,wr,page)
    m.invoke(0x40262a60,A)
    assert accesses==[{'address':'0x18004204','value':'0x0'},{'address':'0x180f0188','value':'0x0'}]
    cases.append({'case':f'actual-IRQ-disable-{initial:08x}','writes':accesses,
                  'note':'initial value irrelevant; OEM writes zero without read-modify-write'})

result={'scope':__doc__,'source_sha256':ns['SHA'],'cases_passed':len(cases),'packets':packets,'cases':cases,
        'query_entry':'0x40314588','query_callback':'0x4030f1e0','IRQ_disable_entry':'0x40262a60',
        'limits':['Synthetic OS/allocator/copy/send/response/MMIO; MCU code not executed',
                  'Linux uses only known host4204 zero-write, not the additional OEM PCIe0188 disable',
                  'The time/source of RAM6 mask change is not established; stage snapshots will distinguish it']}
(ROOT/'stock-query-traces.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'packet_header_hex':packets[1]['packet_hex'][:128],'body_bytes':len(bytes.fromhex(packets[1]['body_hex']))}))
