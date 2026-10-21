#!/usr/bin/env bash
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$r/../../activate.sh"
python3 - "$r" <<'PY'
from pathlib import Path
import json,struct,sys
r=Path(sys.argv[1]);j=json.loads((r/'evidence/stock-security-traces.json').read_text());assert j['passed'] and j['cases_passed']==13
c=j['cases'];out=[]
for k in (0,2,1,3):out.extend(bytes.fromhex(b) for b in c[k]['bodies'])
for k in range(4,9):
 b=bytes.fromhex(c[k]['body_hex']);out.extend([struct.pack('<I',len(b)),b])
out.extend(bytes.fromhex(c[k]['TXD_hex']) for k in [9,10])
for k in [11,12]:
 b=bytes.fromhex(c[k]['body_hex']);out.extend([struct.pack('<I',len(b)),b])
(r/'stock-security-oracle.bin').write_bytes(b''.join(out))
PY
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$r/verify-security.c" -o "$r/verify-security"
ASAN_OPTIONS=detect_leaks=1 "$r/verify-security" "$r/stock-security-oracle.bin" > "$r/verification-security.log"
tail -1 "$r/verification-security.log"
python3 - "$r" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();rows=[x for x in (r/'verification-security.log').read_text().splitlines() if x.startswith('PASS SECURITY ')]
assert len(rows)>75
sources=['c80_mcu_core.h','c80_net_core.h','c80_security_types.h','c80_security_parse.h','c80_security_core.h','c80_rsn.h','verify-security.c','verify-security.sh']
(r/'evidence/security-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(rows),'ASan_UBSan':True,'sources':{n:sha(r/n) for n in sources},'oracle_sha256':sha(r/'stock-security-oracle.bin'),'cases':rows,'hardware_tested':False,'crypto_engine_RF_MCU_DMA_emulated':False},indent=2)+'\n')
PY
