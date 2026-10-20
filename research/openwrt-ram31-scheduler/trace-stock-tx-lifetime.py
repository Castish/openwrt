#!/usr/bin/env python3
"""Execute OEM ARM token allocation/release and TX-free dispatch.

OS DMA-unmap, packet-free and adapter memory are synthetic. No firmware,
physical DMA, RF, or device reset is emulated. No private image is packaged.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_PC

R=Path(__file__).resolve().parent
helper=R.parent/'wifi-bringup/management-tx/trace-stock-management.py'
ns={'__file__':str(helper),'__name__':'trace_library'}
exec(compile(helper.read_text(),str(helper),'exec'),ns)
Base=ns['MgmtModel'];A,DATA,STACK,RETURN,POOL=[ns[k] for k in ('A','DATA','STACK','RETURN','POOL')]
Q=POOL+0x100;IDS=0x42000000;ENTRIES=0x42004000;OUTPUT=POOL+0x300

class Lifetime(Base):
    def __init__(self,ids):
        super().__init__();self.ids=ids;self.capacity=len(ids)
        self.unmaps=[];self.frees=[];self.logs=[];self.current=None
        self.cpu.mem_map(0x42000000,0x40000)
        self.put(A+0xa8134,POOL);self.put(POOL+4,A);self.cpu.mem_write(POOL+8,b'\x01')
        self.put(POOL+12,Q);self.put(POOL+0x48,4095);self.put(POOL+0x4c,4096)
        self.put(POOL+0x50,4096);self.put(POOL+0x54,self.capacity)
        self.put(Q,0);self.put(Q+4,IDS);self.put(Q+8,ENTRIES);self.put(Q+12,self.capacity)
        self.cpu.mem_write(IDS,struct.pack('<'+'H'*self.capacity,*ids))
    def code(self,uc,pc,size,o):
        a=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
        if pc==0x4033b2c0:
            token,pkt,dma,size=self.current
            assert a==[A,dma,size,1],a
            assert self.get(ENTRIES+36*token)==0 # cleared BEFORE payload unmap
            assert self.get(Q+12)==self.capacity-1 # ID not yet re-enqueued
            self.unmaps.append([token,dma,size]);self.finish(0)
        elif pc==0x4033c4a8:
            token,pkt,dma,size=self.current
            assert a[:2]==[A,pkt] and self.unmaps[-1]==[token,dma,size]
            assert self.get(ENTRIES+36*token)==0 and self.get(Q+12)==self.capacity
            self.frees.append(pkt);self.finish(0)
        elif pc==0x4033b7cc:
            self.logs.append(pc);self.finish(0)
        elif pc==0x402b3030:
            uc.reg_write(UC_ARM_REG_SP,STACK);uc.reg_write(UC_ARM_REG_PC,RETURN)
        else:super().code(uc,pc,size,o)
    def allocate(self,i):
        pkt=0x41c10000+(i%16)*64;dma=0x41420000+(i%16)*0x1000;size=32+i%1400
        self.put(STACK,dma);self.put(STACK+4,size)
        token=self.invoke(0x402e20a8,POOL,pkt,1,0)
        assert token==self.ids[i%self.capacity]
        e=ENTRIES+36*token
        assert self.get(e)==pkt and self.get(e+24)==dma and self.get(e+28)==size
        assert self.get(Q+12)==self.capacity-1
        self.current=(token,pkt,dma,size);return token
    def release(self,token,version,via_report):
        count=len(self.unmaps)
        if via_report:
            stride=2 if version==0 else 4;b=bytearray((8+stride+3)&~3)
            struct.pack_into('<IIH',b,0,(6<<29)|(1<<16)|(8+stride),version<<16,token)
            self.cpu.mem_write(DATA,bytes(b));self.invoke(0x402b2f2c,A,DATA)
        else:
            assert self.invoke(0x402e1f04,POOL,token,OUTPUT)==self.current[1]
            assert bytes(self.cpu.mem_read(OUTPUT,1))==b'\x01'
        assert len(self.unmaps)==count+1 and self.get(ENTRIES+36*token)==0
        assert self.get(Q+12)==self.capacity

rows=[]
for version in (0,1,7):
    for cycles in (1,17,257):
        m=Lifetime([16,17,4094,4095])
        for i in range(cycles):m.release(m.allocate(i),version,True)
        assert len(m.unmaps)==len(m.frees)==cycles
        rows.append({'case':f'exact-OEM-TX-free-v{version}-allocate-release-{cycles}',
                     'cycles':cycles,'payload_unmaps':len(m.unmaps),'packet_frees':len(m.frees),
                     'ID_queue_reuses':max(0,cycles-4),'packet_buffer_reuses':max(0,cycles-16)})
for token in (0,1,16,31,4095):
    m=Lifetime([token]);m.release(m.allocate(0),1,False)
    count=len(m.unmaps);free=m.get(Q+12)
    assert m.invoke(0x402e1f04,POOL,token,OUTPUT)==0
    assert len(m.unmaps)==count and m.get(Q+12)==free
    rows.append({'case':f'exact-OEM-empty-ID-{token}-duplicate-release',
                 'second_release_returns_null':True,'no_second_unmap_or_ID_return':True})
m=Lifetime(list(range(4096)))
for i in range(4100):m.release(m.allocate(i),1,True)
assert len(m.frees)==len(m.unmaps)==4100
rows.append({'case':'exact-OEM-full4096-ID-FIFO-wrap','cycles':4100,'ID_queue_reuses':4,
             'payload_unmaps':4100,'packet_frees':4100})
report={'passed':True,'cases_passed':len(rows),'cases':rows,
        'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'OEM_image_sha256':'efdf45c9767bad9b30c93383ee2f5b99a38f5bc2441064e327b026097030fd95',
        'allocator_entry':'402e20a8','release_entry':'402e1f04','TX_free_handler':'402b2f2c',
        'DMA_unmap_service':'4033b2c0','packet_free_service':'4033c4a8',
        'host_DMA_unmap_packet_free_and_memory_synthetic':True,
        'physical_DMA_firmware_RF_emulated':False,
        'contract':'Matching TX-free releases the payload/ID; header DDONE remains independent. Firmware must not access a returned payload or emit an old-generation duplicate after ID reuse.',
        'device_exactly_once_contract_not_proved_by_emulation':True}
(R/'evidence/stock-tx-lifetime-result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'passed':True,'cases':len(rows),'actual_OEM_cycles':sum(x.get('cycles',0) for x in rows)}))
