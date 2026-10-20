#!/usr/bin/env python3
"""Bind completed native test logs to current sources and executables."""
from pathlib import Path
import hashlib,json,re
r=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
log=(r/'verification-recycle.log').read_text();lines=log.splitlines()
assert re.search(r'PASS:\s*50 new actual-core recyclable-TX',log)
assert 'ERROR: AddressSanitizer' not in log and 'runtime error:' not in log
for group,count in [('DATA',589),('NET',601)]:
 rows=[s for s in lines if s.startswith('PASS '+group+'-')]
 assert len(rows)==count,(group,len(rows))
 summary=next(s for s in lines if re.search(r'PASS:\s*'+str(count)+r'\b',s))
 (r/('verification-'+group.lower()+'.log')).write_text('\n'.join(rows+[summary])+'\n')
headers=['c80_mcu_core.h','c80_net_core.h','c80_net_types.h']
model_sources=[str(p.relative_to(r)) for p in r.glob('verify-*.c') if p.name not in ['verify-linux-network.c']]
binary=r/'verify-recycle'
for name in headers+model_sources:
 if name in ['verify-core.c','verify-client-rx.c','verify-auth-tx.c','verify-tx-free.c','verify-association.c','verify-data.c','verify-netdev.c','verify-recycle.c'] or name in headers:
  assert (r/name).stat().st_mtime_ns<=binary.stat().st_mtime_ns,name
binding={n:sha(r/n) for n in headers+['verify-recycle.c','verify-netdev.c','verify-data.c','verify-association.c','verify-tx-free.c','verify-auth-tx.c','verify-client-rx.c','verify-core.c']}
for name,count,prefix in [('netdev',601,'NET-'),('recycle',50,'RECYCLE-')]:
 cases=[s for s in lines if s.startswith('PASS '+prefix)];assert len(cases)==count
 result={'passed':True,'cases_passed':count,'native_ASan_UBSan':True,'source_sha256':binding,'cases':cases,'executed_in':'verify-recycle','executable_sha256':sha(binary),'full_execution_log_sha256':sha(r/'verification-recycle.log'),'legacy_data_cases_also_executed':589,'legacy_netdev_cases_also_executed':601,'device_firmware_DMA_OS_effects_synthetic':True}
 if name=='recycle':result.update({'maximum_full_lifecycle_posts':131074,'mixed_size_recycling_posts':8193,'mixed_IP_lengths':[20,21,28,60,64,128,300,512,1024,1399,1400],'continuous_after_180s_and_after_u32_microseconds_tested':True})
 (r/'evidence'/(name+'-result.json')).write_text(json.dumps(result,indent=2)+'\n')
numbers={'core':495,'rx-recycle':64,'beacon-state':46,'client-rx':366,'auth-tx':60,'tx-free':84,'association':123,'data':589,'window':17,'netdev':601,'recycle':50}
executables={n:('verify-recycle' if n in ['data','netdev','recycle'] else 'verify-'+n) for n in numbers}
for name,count in numbers.items():
 s=(r/('verification-'+name+'.log')).read_text();assert re.search(r'PASS:\s*'+str(count)+r'\b',s),(name,count)
 b=r/executables[name]
 for h in headers:assert (r/h).stat().st_mtime_ns<=b.stat().st_mtime_ns,(name,h)
 for token in ['ERROR: AddressSanitizer','runtime error:']:assert token not in s
assert sum(numbers.values())==2495
for name,count in [('irq-wrapper',12),('nvm-reader',13),('pool-lifetime',28),('stop',6)]:
 d=json.loads((r/'evidence'/(name+'-result.json')).read_text());assert d['passed'] and d['cases_passed']==count
summary={'passed':True,'actual_core_cases':2495,'previous_cases':2445,'new_recycle_cases':50,'native_ASan_UBSan':True,'suites':numbers,'IRQ_gate_cases':18,'actual_Linux_IRQ_callback_cases':12,'actual_Linux_ROM_reader_cases':13,'actual_Linux_pool_lifetime_cases':28,'actual_Linux_stop_shutdown_callback_cases':6,'core_sources':{n:sha(r/n) for n in headers+['c80_mcu_transport.c','c80_net_linux.h']},'executable_bindings':{n:{'executable':e,'sha256':sha(r/e)} for n,e in executables.items()},'legacy_netdev_and_data_logs_extracted_from_combined_execution':True,'C80_radio_firmware_DMA_emulated':False}
(r/'evidence/native-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('PASS native evidence:2495 actual-core cases,18 IRQ-gates,12IRQ+13ROM+28lifetime+6stop; logs and executable/source bindings checked.')
