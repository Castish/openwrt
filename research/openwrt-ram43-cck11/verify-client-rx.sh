#!/usr/bin/env bash
set -euo pipefail
client_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$client_root/../../activate.sh"
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$client_root/verify-client-rx.c" -o "$client_root/verify-client-rx"
ASAN_OPTIONS=detect_leaks=1 "$client_root/verify-client-rx" "$client_root/rootfs/lib/firmware/c80" "$client_root/stock-command-oracle.bin" "$client_root/stock-synthetic-eeprom.bin" > "$client_root/verification-client-rx.log"
tail -1 "$client_root/verification-client-rx.log"
python3 - "$client_root" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);s=(r/'verification-client-rx.log').read_text();rows=[x for x in s.splitlines() if x.startswith('PASS CLIENT-')]
assert len(rows)==366 and f'PASS: {len(rows)} actual-core client RX/RX1 recycling scenarios' in s
(r/'evidence/client-rx-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(rows),'core_source_sha256':hashlib.sha256((r/'c80_mcu_core.h').read_bytes()).hexdigest(),'tests_source_sha256':hashlib.sha256((r/'verify-client-rx.c').read_bytes()).hexdigest(),'cases':rows,'native_ASan_UBSan':True,'management_guard_page_lengths':[0,80],'physical_MCU_DMA_RF_emulated':False,'association_implemented':False},indent=2)+'\n')
PY
