#!/usr/bin/env python3
"""Own MIT analysis: actual OEM STA builder for minimal and normal-AP BMC masks.
Synthetic tables, peer and OS; no physical firmware, key or radio execution.
"""
from pathlib import Path
import hashlib,json,struct
R=Path(__file__).resolve().parent;p=R.parent/'wifi-bringup/station-init/trace-stock-station.py'
n={'__file__':str(p),'__name__':'bmc_order_library'};exec(compile(p.read_text(),str(p),'exec'),n)
rows=[]
for feature in [0x2001,0x2101]:
 m=n['StaModel'](0,0,b'\xff'*6);m.put(n['A']+0x71560,0x400)
 cfg=bytearray(156);cfg[:4]=bytes([0,0,2,0]);struct.pack_into('<II',cfg,4,0x10020,feature);cfg[12]=1;struct.pack_into('<I',cfg,148,n['ENTRY'])
 m.cpu.mem_write(n['STACK'],bytes(cfg[12:]));assert m.invoke(0x402ede60,n['A'],*struct.unpack_from('<3I',cfg))==0 and len(m.calls)==1
 b=bytes.fromhex(m.calls[0]['body_hex']);pos=8;tlvs=[]
 while pos<len(b):
  tag,size=struct.unpack_from('<HH',b,pos);assert size>=4 and pos+size<=len(b)
  tlvs.append({'tag':tag,'bytes':size,'body_hex':b[pos:pos+size].hex()});pos+=size
 rows.append({'feature':hex(feature),'bytes':len(b),'tlvs':tlvs,'body_hex':b.hex()})
out={'passed':True,'factory_sha256':n['ns']['ns']['SHA'],'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'hardware_tested':False,'profiles':rows,'cases_passed':len(rows)}
(R/'evidence/bmc-profile-comparison.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
