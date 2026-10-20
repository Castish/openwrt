#!/usr/bin/env python3
"""Execute exact OEM NVM SET/GET builders,960-byte normalizer and dispatcher.
Synthetic EEPROM, OS allocation/copy/send/reply and TPOS partition services.
No private calibration or firmware execution is included in the emitted proof.
Own analysis code: SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R10,UC_ARM_REG_PC
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'firmware-download/trace-stock-download.py'
if not BASE.exists(): BASE=ROOT/'trace-stock-download.py'
ns={'__file__':str(BASE)}
exec(compile(BASE.read_text().split('\ncases=[]')[0],str(BASE),'exec'),ns)
Model=ns['Model'];A,H,CAP,MSG,SKB,DATA,OUT,STACK=(ns[x] for x in ('A','H','CAP','MSG','SKB','DATA','OUT','STACK'))
EE,BUF=0x41c1a000,0x41c19000
SYNTHETIC=bytes.fromhex('2676')+bytes((i*73+11)&255 for i in range(2,1024))
NORMALIZED=SYNTHETIC[:960]+bytes(64)

class NVMModel(Model):
    def __init__(self):
        super().__init__();self.partition=[]
        self.cpu.mem_write(EE,SYNTHETIC)
        # Exact literal from mt7626_init40309b80/90 and chip ops40309d28/2c.
        self.put(CAP+0xf8,0x04000400)
        self.put(H+0x9c4+0xd8,0x40308e78)
        self.put(A+0xa9dbc,EE)
    def code(self,uc,pc,size,opaque):
        r0,r1,r2,r3=[uc.reg_read(x) for x in ns['REGS']]
        if pc==0x4033bee8:
            assert r0==A and r2 in (6,1028)
            self.put(r1,0 if self.alloc_fail else BUF)
            uc.mem_write(BUF,b'\xa5'*1028);self.finish(0)
        elif pc==0x4033c098:
            assert r1<=1028 and (0x41c00000<=r0<r0+r1<=0x41c20000)
            uc.mem_write(r0,bytes(r1));self.finish(0)
        elif pc==0x4026097c:
            assert r0==A and 0<r1<=1028
            uc.mem_write(MSG,bytes(128));uc.mem_write(SKB,bytes(32))
            self.put(MSG+28,A);self.put(MSG+32,SKB);self.put(SKB+12,DATA)
            self.finish(MSG)
        elif pc==0x4033c4bc:
            assert r0==SKB and 0<r1<=1028
            n=self.get(SKB+8);self.put(SKB+8,n+r1);self.finish(self.get(SKB+12)+n)
        elif pc==0x40563fa4:
            assert r2<=1092 and 0x41c00000<=r0<r0+r2<=0x41c20000
            uc.mem_write(r0,bytes(uc.mem_read(r1,r2)));self.finish(r0)
        elif pc==0x4040adcc:
            assert (r0,r1,r2)==(9,0,1024)
            uc.mem_write(r3,SYNTHETIC);self.partition.append((r0,r1,r2));self.finish(0)
        else:
            before=len(self.calls);super().code(uc,pc,size,opaque)
            if len(self.calls)>before:self.calls[-1]['attributes_hex']=bytes(uc.mem_read(MSG,24)).hex()

cases=[];packets=[]
for seq in (1,12,15):
    m=NVMModel();m.invoke(0x40312678,A,2)
    assert len(m.calls)==1
    call=m.calls[0];body=bytes.fromhex(call['body_hex'])
    assert struct.unpack_from('<H',bytes.fromhex(call['attributes_hex']),8)[0]==60000
    assert body==bytes.fromhex('01010004')+NORMALIZED
    assert call['cid']==0xed and call['callback']=='0x4030f234'
    m.cpu.mem_write(MSG+22,bytes([seq]));m.invoke(0x4026249c,MSG,SKB)
    packet=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)))
    assert len(packet)==1092 and packet[38]==1 and packet[41]==0x21 and packet[43]==1
    packets.append(dict(call,name=f'nvm-set-seq{seq}',sequence=seq,packet_hex=packet.hex()))
    cases.append({'case':f'actual-SET-header-and-960-byte-normalization-{seq}','bytes':len(packet)})

for source,offset,count,seq in ((2,0,1024,13),(2,64,32,1),(1,64,32,15)):
    m=NVMModel();m.put(STACK,OUT)
    m.invoke(0x40312814,A,source,offset,count)
    body=bytes.fromhex(m.calls[0]['body_hex'])
    assert struct.unpack_from('<H',bytes.fromhex(m.calls[0]['attributes_hex']),8)[0]==60000
    assert body==struct.pack('<BBHH',source-1,1,offset,count)
    m.cpu.mem_write(MSG+22,bytes([seq]));m.invoke(0x4026249c,MSG,SKB)
    packet=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)))
    assert len(packet)==70 and packet[38]==0 and packet[41]==0x9b and packet[43]==1
    packets.append(dict(m.calls[0],name=f'nvm-get-{source}-{offset}-{count}',sequence=seq,packet_hex=packet.hex()))
    cases.append({'case':f'actual-GET-builder-{source}-{offset}-{count}','bytes':70,'callback':m.calls[0]['callback']})

# Execute actual board capability assignments, not just their decoded literals.
m=NVMModel();m.cpu.reg_write(UC_ARM_REG_R0,CAP)
def stop_caps(uc,pc,size,opaque):
    if pc==0x40309b94:
        uc.reg_write(UC_ARM_REG_PC,ns['RETURN'])
m.cpu.hook_add(UC_HOOK_CODE,stop_caps)
m.invoke(0x40309b80)
assert struct.unpack('<H',m.cpu.mem_read(CAP+0xfa,2))[0]==1024
cases.append({'case':'actual-capability-NVM-content-size','bytes':1024})

# Actual TPOS wrapper selects partition9, offset0 and1024-byte source copy.
m=NVMModel();m.invoke(0x4033e2fc,H,OUT,0,1024)
assert m.partition==[(9,0,1024)] and bytes(m.cpu.mem_read(OUT,1024))==SYNTHETIC
assert m.invoke(0x4033aac4,A)==0 and m.invoke(0x4033aacc,A)==1024
cases.append({'case':'actual-TPOS-radio-read-selection','partition':9,'offset':0,'bytes':1024})

for count in (0,32,960,1024):
    m=NVMModel();m.put(MSG+12,OUT);m.cpu.mem_write(OUT,b'\xa5'*1088)
    body=struct.pack('<BBHH',1,1,0,count)+NORMALIZED[:count]
    m.cpu.mem_write(DATA,body);m.invoke(0x4030eb8c,MSG,DATA,len(body))
    assert bytes(m.cpu.mem_read(OUT,1088))==NORMALIZED[:count]+b'\xa5'*(1088-count)
    cases.append({'case':f'actual-GET-callback-{count}','data_offset':6,'count_offset':4})

# The exact matched-sequence EIDed dispatcher does not filter the extension.
# We exercise only the command echo9b and documented result8a variants; Linux
# additionally requires source/format/offset/count AND all1024 returned bytes.
for extension in (0x8a,0x9b):
  for padding in (b'',b'\0\0',b'\xa5\x5a'):
    m=NVMModel();m.put(SKB+12,DATA);m.put(MSG+12,OUT);m.put(MSG+16,0x4030eb8c)
    m.cpu.mem_write(MSG+6,b'\xff\xff')
    event_len=1042+len(padding)
    event=struct.pack('<HHBBBBB3x',event_len,0xe000,0xed,13,0,0,extension)+struct.pack('<BBHH',1,1,0,1024)+NORMALIZED+padding
    m.cpu.mem_write(DATA,event);m.cpu.mem_write(OUT,b'\x7d'*1088);seen=[]
    def dispatch(uc,pc,size,opaque):
        if pc==0x4030eb8c:seen.append((uc.reg_read(UC_ARM_REG_R1),uc.reg_read(UC_ARM_REG_R2)))
        if pc==0x40264120:uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,ns['RETURN'])
    m.cpu.hook_add(UC_HOOK_CODE,dispatch)
    for reg,val in ((UC_ARM_REG_R5,MSG),(UC_ARM_REG_R6,DATA),(UC_ARM_REG_R10,SKB)):
        m.cpu.reg_write(reg,val)
    m.invoke(0x402637b4)
    assert seen==[(DATA+12,1030+len(padding))]
    assert bytes(m.cpu.mem_read(OUT,1088))==NORMALIZED+b'\x7d'*64
    cases.append({'case':f'actual-EIDed-GET-dispatch-{extension:02x}-padding-{padding.hex() or "none"}',
      'event_bytes':event_len,'payload_bytes':1030+len(padding),'copied_bytes':1024,
      'tail_canary_preserved':True,'padding_value_has_no_effect':True,
      'surrounding_OS_completion_skipped':True})

m=NVMModel();m.alloc_fail=True;m.invoke(0x40312678,A,2)
assert not m.calls
cases.append({'case':'actual-NVM-allocation-refusal-no-send'})

report={'scope':__doc__,'source_sha256':ns['SHA'],'cases_passed':len(cases),'cases':cases,'packets':packets,
 'synthetic_EEPROM_hex':SYNTHETIC.hex(),'normalized_synthetic_EEPROM_hex':NORMALIZED.hex(),
 'GET_compatible_event_lengths':[1042,1044],'GET_ignored_padding_bytes':[0,2],'response_wait_ms':{'SET':60000,'GET':60000},'SET_entry':'0x40312678','normalizer_entry':'0x40308e78','GET_entry':'0x40312814','GET_callback':'0x4030eb8c',
 'limits':['All NVM bytes are deterministic synthetic data, no private calibration or MAC',
 'OEM SET callback4030f234 is a NOP; Linux additionally validates generic ext-result echo21/status0',
 'RAM10 physically measured GET extension8a/eventlength1044; metadata and byte equality still unproved; both8a/9b/padded and unpadded traverse actual OEM dispatcher',
 'No MCU/RF/TPOS OS or physical flash/controller execution']}
(ROOT/'stock-nvm-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'SET_bytes':1092,'GET_bytes':70,'normalization':'960bytes+64zeros'}))
