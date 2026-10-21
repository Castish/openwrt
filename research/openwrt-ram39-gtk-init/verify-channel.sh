#!/usr/bin/env bash
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$r/../../activate.sh"
python3 - "$r" <<'PY'
from pathlib import Path
import json,struct,sys
r=Path(sys.argv[1]);proof=json.loads((r/'evidence/stock-channel-traces.json').read_text())
assert proof['passed'] and proof['cases_passed']==6
packets=[bytes.fromhex(next(x for x in proof['packets'] if x['name']==name)['packet_hex']) for name in ['channel1','path1']]
(r/'stock-channel1-oracle.bin').write_bytes(b''.join(struct.pack('<I',len(p))+p for p in packets))
PY
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function -fsanitize=address,undefined -fno-omit-frame-pointer "$r/verify-channel.c" -o "$r/verify-channel"
ASAN_OPTIONS=detect_leaks=1 "$r/verify-channel" "$r/rootfs/lib/firmware/c80" "$r/stock-command-oracle.bin" "$r/stock-synthetic-eeprom.bin" "$r/stock-channel1-oracle.bin" > "$r/verification-channel.log"
tail -1 "$r/verification-channel.log"
python3 - "$r" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert 'PASS: 76 ' in (r/'verification-channel.log').read_text()
(r/'evidence/channel-result.json').write_text(json.dumps({'passed':True,'cases_passed':76,'ASan_UBSan':True,'full_core_radio_lifecycle_uses_actual_OEM_channel_oracle':True,'before_MMIO_invalid_channel_refusal':True,'hardware_tested':False,'sources':{n:sha(r/n) for n in ['c80_mcu_core.h','verify-core.c','verify-channel.c','verify-channel.sh','trace-stock-channel.py']},'stock_channel_proof_sha256':sha(r/'evidence/stock-channel-traces.json'),'log_sha256':sha(r/'verification-channel.log')},indent=2)+'\n')
PY
