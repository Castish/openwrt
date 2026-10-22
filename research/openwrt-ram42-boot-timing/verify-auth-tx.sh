#!/usr/bin/env bash
set -euo pipefail
auth_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$auth_root/../../activate.sh"
python3 - "$auth_root" <<'PY'
from pathlib import Path
import json,sys
r=Path(sys.argv[1]);q=json.loads((r/'evidence/stock-management-traces.json').read_text());assert q['passed'] and q['cases_passed']==40
(r/'stock-auth-txd.bin').write_bytes(bytes.fromhex(q['auth_TxD_CCK1']['TXD_hex']))
PY
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$auth_root/verify-auth-tx.c" -o "$auth_root/verify-auth-tx"
ASAN_OPTIONS=detect_leaks=1 "$auth_root/verify-auth-tx" "$auth_root/rootfs/lib/firmware/c80" "$auth_root/stock-command-oracle.bin" "$auth_root/stock-synthetic-eeprom.bin" "$auth_root/stock-auth-txd.bin" > "$auth_root/verification-auth-tx.log"
tail -1 "$auth_root/verification-auth-tx.log"
python3 - "$auth_root" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);s=(r/'verification-auth-tx.log').read_text();rows=[x for x in s.splitlines() if x.startswith('PASS AUTH-')]
assert len(rows)==60 and 'PASS: 60 actual-core single auth TX cases' in s
(r/'evidence/auth-tx-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(rows),'core_source_sha256':hashlib.sha256((r/'c80_mcu_core.h').read_bytes()).hexdigest(),'tests_source_sha256':hashlib.sha256((r/'verify-auth-tx.c').read_bytes()).hexdigest(),'oracle_sha256':hashlib.sha256((r/'stock-auth-txd.bin').read_bytes()).hexdigest(),'cases':rows,'native_ASan_UBSan':True,'physical_MCU_DMA_RF_client_emulated':False,'association_implemented':False},indent=2)+'\n')
PY
