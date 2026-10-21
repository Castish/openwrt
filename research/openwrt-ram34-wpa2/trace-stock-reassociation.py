#!/usr/bin/env python3
"""Execute the actual OEM ARM TXD/TXP builder for a reassociation response.
Own analysis code: SPDX-License-Identifier: MIT. Private OEM image is local.
The earlier trace library supplies synthetic host/HIF/token/DMA services.
No MCU acceptance, RF or ACK is emulated by this instruction-level trace.
"""
from pathlib import Path
import hashlib,json
r=Path(__file__).resolve().parent
p=r.parent/'openwrt-ram25-assoc/evidence/trace-stock-association-tx.py'
s=p.read_text().replace('M(subtype=1)','M(subtype=3)').replace("f,0,0x10,304","f,0,0x30,304").replace('hdr[30]==1','hdr[30]==3')
assert s!=p.read_text() and 'M(subtype=3)' in s and 'f,0,0x30,304' in s
ns={'__file__':str(p),'__name__':'trace_library'}
exec(compile(s,str(p),'exec'),ns)
rows=[ns['run'](w,i,t) for w in (0,1) for i in (1,511) for t in (1,31)]
old=json.loads((r/'evidence/stock-association-tx-traces.json').read_text())
for x in rows:
    x['case']=x['case'].replace('assoc-response','reassoc-response')
    before=next(y for y in old['cases'] if all(x[k]==y[k] for k in ['wcid','slot','token']))
    a=bytearray.fromhex(before['TXD_hex']);a[30]=3
    assert bytes.fromhex(x['TXD_hex'])==a
result={'passed':True,'cases_passed':len(rows),'cases':rows,'source_sha256':old['source_sha256'],
        'profile':next(x for x in rows if x['wcid']==1 and x['slot']==1 and x['token']==1),
        'prior_analysis_source_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
        'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'actual_ARM_TXD_TXP_descriptor_publisher_executed':True,
        'host_HIF_token_DMA_context_synthetic':True,'firmware_RF_ACK_proven':False}
(r/'evidence/stock-reassociation-traces.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS: 8 actual OEM ARM reassociation TXD/TXP/descriptor/publication cases; synthetic host context.')
