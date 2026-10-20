#!/usr/bin/env python3
"""Execute OEM MT7626 ISR acknowledgement/masking and IRQ route setup.
Synthetic host context, locks, interrupt source and W1C MMIO; no MCU execution.
Own analysis code: SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'firmware-download/trace-stock-download.py'
if not BASE.exists(): BASE=ROOT/'trace-stock-download.py'
ns={'__file__':str(BASE)}
exec(compile(BASE.read_text().split('\ncases=[]')[0],str(BASE),'exec'),ns)
Model=ns['Model'];A,H,HIF=(ns[x] for x in ('A','H','HIF'))
cases=[]

class IRQModel(Model):
    def __init__(self,source=0,mask=0):
        super().__init__()
        self.put(HIF+0x7c,0x18000000)
        self.invoke(0x402f54ac,H)
        self.state={0x18004200:source,0x18004204:mask}
        self.accesses=[]
        def read(uc,offset,size,unused):
            addr=0x18004000+offset
            assert addr in self.state and size==4,hex(addr)
            value=self.state[addr]
            self.accesses.append({'op':'read','address':hex(addr),'value':hex(value)})
            return value
        def write(uc,offset,size,value,unused):
            addr=0x18004000+offset
            assert addr in self.state and size==4,hex(addr)
            self.accesses.append({'op':'write','address':hex(addr),'value':hex(value)})
            if addr==0x18004200: self.state[addr]&=~value
            else: self.state[addr]=value
        self.cpu.mmio_map(0x18004000,0x1000,read,None,write,None)
    def code(self,uc,pc,size,opaque):
        if pc in (0x404fa3c8,0x404fa3cc): self.finish(0)
        elif pc==0x402c27f8:self.finish(0)
        else:super().code(uc,pc,size,opaque)

# The real callback table points at403087cc; do not derive ISR from a name.
assert struct.unpack_from('<I',ns['PROGRAM'],0x4030a368-0x40205000)[0]==0x403087cc
cases.append({'case':'actual-mt7626-ISR-table-pointer','entry':'0x403087cc'})

# Inactive OEM ISR acknowledges its exact observed source. All other paths
# (DMA completion scheduling/TPOS workqueues) are deliberately outside this scope.
for source in (0,1,2,0x80082):
    m=IRQModel(source)
    m.invoke(0x403087cc,A)
    assert m.accesses==[
        {'op':'read','address':'0x18004200','value':hex(source)},
        {'op':'write','address':'0x18004200','value':hex(source)}]
    assert m.state[0x18004200]==0
    cases.append({'case':f'actual-ISR-W1C-{source:08x}','accesses':m.accesses,
                  'W1C_effect_modeled':True})

for ring_bit in (1,2):
    m=IRQModel(0x400000|ring_bit,0x400003)
    m.put(A+0x2ff444,0x10000000) # synthetic IRQ-active software flag
    m.put(HIF,0x400003)
    ops=ns['OUT'];m.put(A+0xa9d30,ops);m.put(ops+8,ops+0x100)
    dispatched=[]
    def schedule(uc,pc,size,opaque):
        if pc==ops+0x100:
            assert uc.reg_read(UC_ARM_REG_R0)==A
            dispatched.append(uc.reg_read(UC_ARM_REG_R1));m.finish(1)
    m.cpu.hook_add(UC_HOOK_CODE,schedule)
    m.invoke(0x403087cc,A)
    assert dispatched==[8]
    assert m.get(HIF+8)==0x400000|ring_bit
    assert m.get(HIF+4)==ring_bit
    assert m.state[0x18004204]==0x400003&~ring_bit
    cases.append({'case':f'actual-active-ISR-RX-source-{ring_bit}',
                  'bottom_half_type':8,'callback_modeled':True,
                  'accesses':m.accesses})

# Real interrupt-disable helper masks a supplied subset and reads it back.
# HIF first word is configured software enable mask; +4 is disabled sources.
for enabled,disable in ((2,2),(3,2),(0x20000002,2),(2,0)):
    m=IRQModel(0,enabled);m.put(HIF,enabled)
    m.invoke(0x402f455c,A,disable)
    assert m.state[0x18004204]==enabled&~disable
    assert m.get(HIF+4)==disable
    assert m.accesses==[
        {'op':'write','address':'0x18004204','value':hex(enabled&~disable)},
        {'op':'read','address':'0x18004204','value':hex(enabled&~disable)}]
    cases.append({'case':f'actual-mask-subset-{enabled:x}-{disable:x}',
                  'accesses':m.accesses})

# Repeat the actual platform IRQ243/type8 function independently; source/CPU
# line topology remains a physical hypothesis until the Linux hardware test.
for before in (0,0xa5a01234):
    m=Model();m.put(0x406d8304,0x10310000)
    state={0x10200a98:before,0x1031011c:0};access=[]
    def rd(uc,off,size,page):
        addr=page+off;assert size==4 and addr in state
        access.append({'op':'read','address':hex(addr),'value':hex(state[addr])})
        return state[addr]
    def wr(uc,off,size,value,page):
        addr=page+off;assert size==4 and addr in state
        access.append({'op':'write','address':hex(addr),'value':hex(value)})
        state[addr]=value
    for page in (0x10200000,0x10310000):m.cpu.mmio_map(page,0x1000,rd,page,wr,page)
    m.invoke(0x403daa90,243,8)
    assert state=={0x10200a98:before|0x80000,0x1031011c:0x80000}
    cases.append({'case':f'actual-IRQ243-active-low-{before:08x}',
                  'accesses':access,'GIC_SPI':211,'raw_GIC_ID':243,
                  'physical_route_tested':False})

report={'source_sha256':ns['SHA'],'scope':__doc__,'cases_passed':len(cases),
        'cases':cases,'limits':['W1C behavior is modeled; actual physical clear/readback still required',
        'Scoped OEM functions only; full OS/ISR bottom halves and MCU are not executed',
        'New Linux test acknowledges only RX1 bit1; it never copies OEM all-source ACK',
        'Physical GIC243/SPI211 route remains unproven until hardware test']}
(ROOT/'stock-irq-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'scope':'actual OEM ISR, mask helper and IRQ route'}))
