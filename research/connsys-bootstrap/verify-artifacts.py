#!/usr/bin/env python3
"""Check pinned blob placement, script, CP15 scope and a separate exact rebuild."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile

root=Path(__file__).resolve().parent
data=(root/'c80-connsys-bootstrap.bin').read_bytes()
sha=hashlib.sha256(data).hexdigest()
assert len(data)==0x250000
for record in json.loads((root/'FIRMWARE-SOURCES.json').read_text())['components']:
    blob=(root/'blobs'/record['file']).read_bytes()
    offset=int(record['offset_in_payload'],16)
    assert len(blob)==record['bytes'] and hashlib.sha256(blob).hexdigest()==record['sha256']
    assert data[offset:offset+len(blob)]==blob
assert data[0x50000:]==bytes(0x200000),'Initial backup must be zero-filled, not captured RAM'
assert hashlib.sha256((root/'c80-script-runner.bin').read_bytes()).hexdigest()=='0b7923ac331ec96f308ee91424c2881d3b5532461c41199a7c83f1bfc36939f2'
spec=importlib.util.spec_from_file_location('script_generator',root/'make-script.py')
generator=importlib.util.module_from_spec(spec); spec.loader.exec_module(generator)
assert generator.make([('41000000',str(root/'c80-connsys-bootstrap.bin'))],['41000000'])==(root/'c80-start.txt').read_text()
symbols={n:int(a,16) for a,_,n in (l.split() for l in (root/'symbols.txt').read_text().splitlines())}
assert symbols['_start']==0x41000000 and symbols['firmware_mcu']==0x41004000
assert symbols['firmware_wifi']==0x41018000 and symbols['ddr_backup']==0x41050000
allowed={symbols[n] for n in ('entry_translate_read_op','entry_translate_write_op',
 'entry_restore_par_op','entry_fail_restore_par_op','translate_read_op','translate_write_op',
 'restore_par_op','clean_op','invalidate_op')}
assembly=(root/'disassembly.txt').read_text()
found={int(a,16) for a in re.findall(r'^([0-9a-f]+):\s+[0-9a-f]{8}\s+mcr\s',assembly,re.M)}
assert found==allowed,(found,allowed)
assert not re.search(r'\b(?:mcrr|msr|cpsid|cpsie)\b',assembly),'Unexpected CPU state write'
assert 'There are no relocations in this file.' in (root/'elf-inspection.txt').read_text()
checks=[]
for name,count in [('verification-full.json',1),('verification-fast.json',64)]:
    report=json.loads((root/name).read_text())
    assert report['passed'] and report['payload_sha256']==sha and len(report['cases'])==count
    checks.extend(report['cases'])
assert len(checks)==65 and sum(c['real_crc_and_copy_executed'] for c in checks)==1
combined={'scope':'One full ARM CRC/copy case plus64 fault cases using host CRC/copy substitution; CP15/cache/MCU effects modeled',
          'passed':True,'payload_sha256':sha,'payload_bytes':len(data),'cases':checks,
          'hardware_MCU_bootstrap_tested':False}
(root/'verification.json').write_text(json.dumps(combined,indent=2)+'\n')
with tempfile.TemporaryDirectory(prefix='c80-bootstrap-rebuild-') as folder:
    temporary=Path(folder); (temporary/'blobs').mkdir()
    for name in ('entry.S','blobs.S','bootstrap.c','bootstrap.ld','build.sh'):
        (temporary/name).write_bytes((root/name).read_bytes())
    for name in ('test_mcu.bin','test_wifi.bin'):
        (temporary/'blobs'/name).write_bytes((root/'blobs'/name).read_bytes())
    env=dict(os.environ,ARM_TOOLCHAIN_ROOT=str(root.parent/'linux-bringup/tools'))
    subprocess.run(['bash',str(temporary/'build.sh')],env=env,check=True,capture_output=True)
    assert (temporary/'c80-connsys-bootstrap.bin').read_bytes()==data
result={'passed':True,'bytes':len(data),'sha256':sha,'exact_rebuild':True,
        'OEM_blob_bytes_unchanged':True,'backup_initially_all_zero':True,'script_regenerated_exactly':True,
        'only_CP15_write_sites':'ATS1CPR/ATS1CPW, PAR restore, D-cache clean/invalidate by VA',
        'CP15_write_sites':len(found),'passed_ARM_cases':65,'full_CRC_copy_cases':1,
        'unchanged_hardware_confirmed_runner':True}
(root/'artifact-verification.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS: 65 ARM records match binary; exact rebuild; blob/layout/script pins; CP15 write scope.')
