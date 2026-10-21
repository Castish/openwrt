#!/usr/bin/env bash
set -euo pipefail
rx_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$rx_root/../../activate.sh"
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer \
 "$rx_root/verify-rx-recycle.c" -o "$rx_root/verify-rx-recycle"
ASAN_OPTIONS=detect_leaks=1 "$rx_root/verify-rx-recycle" "$rx_root/rootfs/lib/firmware/c80" \
 "$rx_root/stock-command-oracle.bin" "$rx_root/stock-synthetic-eeprom.bin" > "$rx_root/verification-rx-recycle.log"
tail -1 "$rx_root/verification-rx-recycle.log"
python3 - "$rx_root" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);s=(r/'verification-rx-recycle.log').read_text();cases=[x for x in s.splitlines() if x.startswith('PASS RX-')]
assert len(cases)==64 and 'PASS: 64 actual-core RX recycling scenarios' in s
(r/'evidence/rx-recycle-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(cases),'core_source_sha256':hashlib.sha256((r/'c80_mcu_core.h').read_bytes()).hexdigest(),'tests_source_sha256':hashlib.sha256((r/'verify-rx-recycle.c').read_bytes()).hexdigest(),'scenarios':cases,'native_ASan_UBSan':True,'hardware_causality_of_59_packet_threshold_proven':False,'effects_synthetic':True},indent=2)+'\n')
PY
