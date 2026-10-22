#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$r/../../activate.sh"
python3 - "$r" <<'PY'
from pathlib import Path
import sys
r=Path(sys.argv[1]);(r/'private').mkdir(exist_ok=True)
for source,name in [(r,'rx-status-fixture.h'),(r.parent/'openwrt-ram39-gtk-init','rx-old-fixture.h')]:
 (r/'private'/name).write_text((source/'verify-security.c').read_text().split('\nint main(')[0]+'\n')
PY
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function -I"$r/../openwrt-ram39-gtk-init" -DC80_RX_OLD_BASELINE -DC80_RX_FIXTURE='"private/rx-old-fixture.h"' -fsanitize=address,undefined -fno-omit-frame-pointer "$r/verify-management-status.c" -o "$r/private/verify-rx-old"
ASAN_OPTIONS=detect_leaks=1 "$r/private/verify-rx-old" "$r/stock-security-oracle.bin" "$r/stock-station-command-oracle.bin" > "$r/verification-rx-old-baseline.log"
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function -I"$r" -fsanitize=address,undefined -fno-omit-frame-pointer "$r/verify-management-status.c" -o "$r/verify-management-status"
ASAN_OPTIONS=detect_leaks=1 "$r/verify-management-status" "$r/stock-security-oracle.bin" "$r/stock-station-command-oracle.bin" > "$r/verification-management-status.log"
tail -1 "$r/verification-management-status.log"
python3 - "$r" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
cases=[x for x in (r/'verification-management-status.log').read_text().splitlines() if x.startswith('PASS RX STATUS ')]
assert len(cases)>70 and 'RAM39 actual RX0 gate discards' in (r/'verification-rx-old-baseline.log').read_text()
names=['c80_mcu_core.h','c80_mcu_transport.c','c80_security_core.h','c80_security_parse.h','c80_session_core.h','verify-management-status.c','verify-management-status.sh']
(r/'evidence/management-status-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(cases),'ASan_UBSan':True,'cases':cases,'sources':{n:sha(r/n) for n in names},'old_RAM39_actual_gate_refusal_reproduced':True,'physical_failed_frame_RXD_flags_known':False,'physical_hardware_or_RF_emulated':False},indent=2)+'\n')
PY
