#!/usr/bin/env bash
set -euo pipefail
state_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$state_root/../../activate.sh"
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$state_root/verify-beacon-state.c" -o "$state_root/verify-beacon-state"
ASAN_OPTIONS=detect_leaks=1 "$state_root/verify-beacon-state" "$state_root/rootfs/lib/firmware/c80" "$state_root/stock-command-oracle.bin" "$state_root/stock-synthetic-eeprom.bin" > "$state_root/verification-beacon-state.log"
tail -1 "$state_root/verification-beacon-state.log"
python3 - "$state_root" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);s=(r/'verification-beacon-state.log').read_text();rows=[x for x in s.splitlines() if x.startswith('PASS STATE-')]
assert len(rows)==46
(r/'evidence/beacon-state-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(rows),'core_source_sha256':hashlib.sha256((r/'c80_mcu_core.h').read_bytes()).hexdigest(),'tests_source_sha256':hashlib.sha256((r/'verify-beacon-state.c').read_bytes()).hexdigest(),'cases':rows,'native_ASan_UBSan':True,'physical_MCU_RF_emulated':False},indent=2)+'\n')
PY
