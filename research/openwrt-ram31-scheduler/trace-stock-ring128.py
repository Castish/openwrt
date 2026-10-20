#!/usr/bin/env python3
"""Execute OEM ordinary-ring setup and producer wrap with128/512 host caps.

The128 cap is an explicit host input override, not a discovered OEM default.
MMIO, OS DMA mappings and tokens are synthetic; this cannot prove the cause
of the physical RAM29 stall or that the candidate works on C80 hardware.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *

R=Path(__file__).resolve().parent
path=R.parent/'wifi-bringup/management-tx/trace-stock-management.py'
ns={'__file__':str(path),'__name__':'library'}
exec(compile(path.read_text(),str(path),'exec'),ns)
M=ns['LowerModel']
A,H,CTX,PKT,INFO,PHY,OUTPUT,TXRING,CELL,DESC,POOL,STACK,RETURN,DATA=[ns[n] for n in
    ('A','H','CTX','PKT','INFO','PHY','OUTPUT','TXRING','CELL','DESC','POOL','STACK','RETURN','DATA')]
rows=[]

for size in (512,128):
    m=M();ns['chip_caps'](m)
    m.cpu.mem_write(H+0x810+6,struct.pack('<H',size))
    hif=m.invoke(0x402f2884,H);m.put(hif+0x10,TXRING);m.put(hif+0x7c,0x18000000)
    ring=TXRING+5*88;m.put(ring+8,CELL);m.put(CELL+8,0x41410000)
    writes=[]
    def read(*a):raise AssertionError('Unexpected MMIO read')
    def write(uc,offset,n,value,o):
        assert n==4 and offset in (0x350,0x354,0x358)
        writes.append([0x18004000+offset,value])
    m.cpu.mmio_map(0x18004000,0x1000,read,None,write,None)
    m.cpu.reg_write(UC_ARM_REG_R4,hif)
    m.cpu.reg_write(UC_ARM_REG_R7,5*88)
    m.cpu.reg_write(UC_ARM_REG_R8,A+0x33c000)
    m.cpu.reg_write(UC_ARM_REG_R9,0x4354)
    m.cpu.reg_write(UC_ARM_REG_R11,STACK+0x80)
    def stop(uc,pc,n,o):
        if pc==0x4031aad4:uc.reg_write(UC_ARM_REG_PC,RETURN)
        elif pc==0x4031bc2c:
            assert uc.reg_read(UC_ARM_REG_R0)==H
            offset=uc.reg_read(UC_ARM_REG_R1);value=uc.reg_read(UC_ARM_REG_R2)
            assert offset in (0x4350,0x4354,0x4358)
            writes.append([0x18000000+offset,value]);m.finish(0)
    hook=m.cpu.hook_add(UC_HOOK_CODE,stop)
    m.invoke(0x4031aa44)
    m.cpu.hook_del(hook)
    assert writes==[[0x18004350,0x41410000],[0x18004358,0],[0x18004354,size]],writes
    rows.append({'case':f'actual-ordinary-ring5-setup-cap{size}',
                 'entry':'4031aa44','end_exclusive':'4031aad4',
                 'actual_OEM_IO_calls':writes,'IO_service_synthetic':True,'cap_override':size==128})
    for slot in ((0,1,125,126,127,128,510,511) if size==512 else (0,1,125,126,127)):
        m=M();ns['chip_caps'](m)
        m.cpu.mem_write(H+0x810+6,struct.pack('<H',size))
        assert m.invoke(0x40274848,A,ns['WDEV'],CTX)==0
        m.cpu.mem_write(OUTPUT,bytes.fromhex(m.saved[0]['info_hex']))
        m.cpu.mem_write(PHY,bytes(4))
        ops=m.invoke(0x402f289c,H)
        for off,v in ((0x15c,0x403199fc),(0x13c,0x4031a5b4),(0x140,0x402f30bc)):m.put(ops+off,v)
        m.put(A+0xa8134,POOL);m.put(POOL+0x48,4095)
        m.cpu.mem_write(CTX,b'\x05');m.put(CTX+80,INFO)
        hif=m.invoke(0x402f2884,H);m.put(hif+0x10,TXRING)
        ring=TXRING+5*88;cell=0x41c00000+slot*40
        m.put(ring+8,cell-slot*40);m.put(ring+36,slot)
        m.put(cell+4,DESC);m.put(cell+28,INFO)
        m.lower=True;m.token=141;m.put(STACK,CTX)
        assert m.invoke(0x40316eb4,A,DATA,OUTPUT,PHY)==0
        expected=(slot+1)%size
        assert m.get(ring+36)==expected
        descriptor=bytes(m.cpu.mem_read(DESC,16));header=bytes(m.cpu.mem_read(INFO,64))
        assert descriptor==struct.pack('<4I',0x41410000,0x40400000,0x41420000,0)
        m.put(hif+0x7c,0x18000000);m.put(ring+32,0x4358)
        m.invoke(0x402f54ac,H);writes=[]
        def publish(uc,offset,n,value,o):
            assert (offset,n,value)==(0x358,4,expected)
            assert bytes(uc.mem_read(DESC,16))==descriptor
            assert bytes(uc.mem_read(INFO,64))==header
            writes.append(value)
        m.cpu.mmio_map(0x18004000,0x1000,read,None,publish,None)
        m.invoke(0x402f3424,A,CTX,5);assert writes==[expected]
        rows.append({'case':f'actual-OEM-cap{size}-slot{slot}-producer{expected}',
                     'builder_entry':'40316eb4','publisher_entry':'402f3424',
                     'CPU_register':'18004358','CPU_value':expected,
                     'descriptor_hex':descriptor.hex(),'cap_override':size==128})

assert len(rows)==15
result={'passed':True,'cases_passed':len(rows),'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'OEM_image_sha256':'efdf45c9767bad9b30c93383ee2f5b99a38f5bc2441064e327b026097030fd95',
        'cases':rows,'OEM_default_ordinary_count':512,'candidate_ordinary_count':128,
        'physical_DMA_firmware_RF_emulated':False,
        'hardware_cause_or_success_proved':False,
        'limitations':'128 is an explicit host capability input override. Actual OEM instructions support programming the count and wrapping127->0; hardware acceptance and underlying RAM29 stall cause remain unproved.'}
(R/'evidence/stock-ring128-result.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS:15 actual OEM ordinary-ring setup/producer-wrap cases;128 input override, synthetic MMIO/OS/DMA; no hardware claim.')
