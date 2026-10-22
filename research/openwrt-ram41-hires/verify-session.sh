#!/usr/bin/env bash
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$r/../../activate.sh"
python3 - "$r" <<'PY'
from pathlib import Path
import json,struct,sys
r=Path(sys.argv[1])
for name,out in [('stock-management-traces.json','stock-auth-txd.bin'),('stock-association-tx-traces.json','stock-association-txd.bin'),('stock-data-traces.json','stock-data-txd.bin')]:
    # TXD extraction is shared with the original, independently traced suites.
    assert (r/out).is_file(),f'Run the baseline suites first: {out}'
d=json.loads((r/'evidence/stock-station-traces.json').read_text());assert d['passed'] and d['cases_passed']==30
(r/'stock-station-command-oracle.bin').write_bytes(b''.join(struct.pack('<I',len(bytes.fromhex(x['packet_hex'])))+bytes.fromhex(x['packet_hex']) for x in d['profile_packets']))
d=json.loads((r/'evidence/stock-reassociation-traces.json').read_text());assert d['passed'] and d['cases_passed']==8
(r/'stock-reassociation-txd.bin').write_bytes(bytes.fromhex(d['profile']['TXD_hex']))
PY
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$r/verify-session.c" -o "$r/verify-session"
ASAN_OPTIONS=detect_leaks=1 "$r/verify-session" "$r/stock-auth-txd.bin" "$r/stock-association-txd.bin" "$r/stock-data-txd.bin" "$r/stock-station-command-oracle.bin" "$r/stock-reassociation-txd.bin" > "$r/verification-session.log"
tail -1 "$r/verification-session.log"
python3 - "$r" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
rows=[s for s in (r/'verification-session.log').read_text().splitlines() if s.startswith('PASS SESSION ')]
assert len(rows)==214
sources=['c80_mcu_core.h','c80_net_core.h','c80_net_types.h','c80_session_core.h','verify-session.c','verify-session.sh']
d={'passed':True,'cases_passed':len(rows),'ASan_UBSan':True,'sources':{n:sha(r/n) for n in sources},'cases':rows,
   'log_sha256':sha(r/'verification-session.log'),'test_binary_sha256':sha(r/'verify-session'),
   'max_sequential_sessions_per_stress_case':5000,'guard_page_lengths':129,
   'scope':'Actual shared session/RX/TX/MCU-command functions after synthetic boot; independent MMIO/firmware/completion effects. Both completion orders, disconnect while TX owned, missing ACK/DDONE/token, stale/duplicate tokens, malformed frames, RXD status, RX history reset, command/ring/token wraps.',
   'full_c80_run_boot_and_teardown_executed_with_session_mode':False,
   'reassociation_TXD_compared_to_actual_OEM_ARM_builder':True,
   'reassociation_oracle_sha256':sha(r/'stock-reassociation-txd.bin'),
   'hardware_RF_MCU_DMA_emulated':False,'exactly_once_firmware_completion_contract_proven':False}
(r/'evidence/session-result.json').write_text(json.dumps(d,indent=2)+'\n')
PY
