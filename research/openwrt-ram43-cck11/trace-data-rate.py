#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute OEM ARM CCK converter and raw TXD constructor; no MCU/RF model."""
from pathlib import Path
import hashlib,json,struct

R=Path(__file__).resolve().parent
P=R.parent/'wifi-bringup/data-exchange/trace-stock-data.py'
n={'__file__':str(P),'__name__':'library'};exec(compile(P.read_text(),str(P),'exec'),n)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
cases=[];vectors=[]
for mcs in range(4):
    m=n['M']();m.put(n['STACK'],1) # OEM long-preamble enum, fifth argument.
    code=m.invoke(0x4031940c,0,mcs,1,0)
    ack=m.invoke(0x402adc78,n['A'],mcs,14)
    assert code==mcs and ack==(304,248,213,203)[mcs]
    cases.append({'name':f'actual-CCK-long-preamble-converter-{mcs}',
                  'entry':'4031940c','mode':0,'MCS':mcs,'long_preamble':1,
                  'TX_rate_code':code,'ACK_duration_us':ack})
    for length in (52,60,92,131,1432):
        for protected in (0,1):
            m=n['M']();n['ns']['chip_caps'](m)
            assert m.invoke(0x40274848,n['A'],n['ns']['WDEV'],n['CTX'])==0
            info=bytearray.fromhex(m.saved[0]['info_hex'])
            info[0]=1;info[25]=protected;info[29]=2;info[30]=0
            assert info[28]==1 # Preserve factory-selected long preamble.
            struct.pack_into('<I',info,16,length)
            m.cpu.mem_write(n['OUTPUT'],bytes(info));m.cpu.mem_write(n['PHY'],struct.pack('<I',mcs))
            m.invoke(0x403199fc,n['A'],n['INFO'],n['OUTPUT'],n['PHY'])
            txd=bytes(m.cpu.mem_read(n['INFO'],32))
            expected=bytearray.fromhex('5c00004001cc0000000000a00038000000000000002000000400000000c02000')
            struct.pack_into('<H',expected,0,32+length)
            if protected:expected[12]|=2
            struct.pack_into('<H',expected,26,mcs)
            assert txd==expected
            vectors.append(struct.pack('<III',mcs,protected,length)+txd)
            cases.append({'name':f'actual-data-TXD-MCS{mcs}-protected{protected}-length{length}',
                          'entry':'403199fc','mode':0,'MCS':mcs,'protected':protected,
                          'frame_bytes':length,'TXD_hex':txd.hex()})
assert len(cases)==44 and len(vectors)==40
oracle=R/'stock-data-rate-oracle.bin';oracle.write_bytes(b''.join(vectors))
proof={'passed':True,'cases_passed':len(cases),'cases':cases,
       'source_sha256':'efdf45c9767bad9b30c93383ee2f5b99a38f5bc2441064e327b026097030fd95',
       'verification_source_sha256':sha(Path(__file__)),'oracle_sha256':sha(oracle),
       'CCK_long_codes':[0,1,2,3],'CCK_rate_kbps':[1000,2000,5500,11000],
       'TXD6_CCK1':'00000004','TXD6_CCK11':'00030004','changed_byte':26,
       'actual_ARM_converter_and_constructor':True,'host_metadata_synthetic':True,
       'full_factory_rate_control_policy_executed':False,'MCU_DMA_CCMP_RF_emulated':False}
(R/'evidence/data-rate-OEM-result.json').write_text(json.dumps(proof,indent=2)+'\n')
print('PASS OEM CCK data rate:44 actual ARM converter/TXD cases; no physical firmware/RF emulation.')
