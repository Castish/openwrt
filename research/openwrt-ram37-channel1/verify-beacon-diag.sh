#!/usr/bin/env bash
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$r/../../activate.sh"
test ! -f "$r/c80-openwrt-ram37-channel1.zip"
python3 - "$r" <<'PY'
from pathlib import Path
import sys
r=Path(sys.argv[1]);(r/'private').mkdir(exist_ok=True)
(r/'private/beacon-diag-fixture.h').write_text((r/'verify-security.c').read_text().split('\nint main(')[0]+'\n')
PY
gcc -I"$r" -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function -fsanitize=address,undefined -fno-omit-frame-pointer "$r/verify-beacon-diag.c" -o "$r/verify-beacon-diag"
ASAN_OPTIONS=detect_leaks=1 "$r/verify-beacon-diag" "$r/stock-security-oracle.bin" > "$r/verification-beacon-diag.log"
tail -1 "$r/verification-beacon-diag.log"
python3 - "$r" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
cases=[s for s in (r/'verification-beacon-diag.log').read_text().splitlines() if s.startswith('PASS BEACON DIAG ')]
assert len(cases)==48,len(cases)
names=['c80_mcu_core.h','c80_security_core.h','c80_security_types.h','verify-security.c','verify-session.c','verify-beacon-diag.c','verify-beacon-diag.sh']
(r/'evidence/beacon-diag-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(cases),'ASan_UBSan':True,'cases':cases,'sources':{n:sha(r/n) for n in names},'oracle_sha256':sha(r/'stock-security-oracle.bin'),'physical_MCU_DMA_RF_emulated':False},indent=2)+'\n')
PY
