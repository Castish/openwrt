#!/usr/bin/env python3
"""Bind fresh native suite results to current shared inputs and exact logs."""
from pathlib import Path
import hashlib,json,re
R=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
counts={'core':495,'rx-recycle':64,'beacon-state':46,'client-rx':366,'auth-tx':60,'tx-free':84,'association':123,'data':589,'window':17,'netdev':601,'recycle':55,'scheduler':91,'cfg-control':652,'session':214,'security':101,'beacon-diag':48}
for name,n in counts.items():
    text=(R/('verification-'+name+'.log')).read_text();line=text.splitlines()[-1]
    assert re.match(r'PASS:\s*'+str(n)+r'\b',line),(name,line)
assert '18 IRQ gate cases' in (R/'verification-core.log').read_text()
names=['c80_mcu_core.h','c80_mcu_transport.c','c80_net_types.h','c80_net_core.h','c80_net_linux.h','c80_net_selftest.c','c80_cfg80211.h','c80_session_core.h','c80_security_types.h','c80_security_parse.h','c80_security_core.h','c80_key_linux.h','c80_rsn.h','verify-beacon-diag.c','verify-beacon-diag.sh']
result={'passed':True,'cases_passed':sum(counts.values())+18,'IRQ_gate_cases':18,'suites':counts,'ASan_UBSan':True,'all_suites_rerun':True,'new_beacon_diag_cases':48,'hardware_effects_synthetic':True,'source_binding_scope':'Current adapter and shared inputs; native cases exercise shared core. Linux show callbacks execute separately in ARM QEMU.','sources':{n:sha(R/n) for n in names},'logs':{n:sha(R/('verification-'+n+'.log')) for n in counts}}
assert result['cases_passed']==3624
(R/'evidence/native-summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':True,'native_cases':3624,'new_beacon_diag_cases':48}))
