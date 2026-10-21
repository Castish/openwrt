#!/usr/bin/env bash
set -euo pipefail
data_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$data_root/../../activate.sh"
python3 "$data_root/make-data-fixtures.py"
python3 - "$data_root" <<'PYDATA'
from pathlib import Path
import json,sys
r=Path(sys.argv[1]);q=json.loads((r/'evidence/stock-data-traces.json').read_text())
assert q['passed'] and q['cases_passed']==68
(r/'stock-data-txd.bin').write_bytes(bytes.fromhex(q['profile']['TXD_hex']))
PYDATA
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$data_root/verify-data.c" -o "$data_root/verify-data"
ASAN_OPTIONS=detect_leaks=1 "$data_root/verify-data" "$data_root/rootfs/lib/firmware/c80" "$data_root/stock-command-oracle.bin" "$data_root/stock-synthetic-eeprom.bin" "$data_root/stock-auth-txd.bin" "$data_root/stock-station-command-oracle.bin" "$data_root/stock-association-txd.bin" "$data_root/stock-data-txd.bin" "$data_root/data-protocol-fixtures.bin" > "$data_root/verification-data.log"
tail -1 "$data_root/verification-data.log"
python3 - "$data_root" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);rows=[s for s in (r/'verification-data.log').read_text().splitlines() if s.startswith('PASS DATA-')]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(r/'evidence/data-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(rows),'core_source_sha256':sha(r/'c80_mcu_core.h'),'tests_source_sha256':sha(r/'verify-data.c'),'TXD_oracle_sha256':sha(r/'stock-data-txd.bin'),'wire_fixtures_sha256':sha(r/'data-protocol-fixtures.bin'),'native_ASan_UBSan':True,'guard_pages':322,'cases':rows,'hardware_client_RF_MCU_DMA_emulated':False,'pool_release_on_report':False},indent=2)+'\n')
PY
