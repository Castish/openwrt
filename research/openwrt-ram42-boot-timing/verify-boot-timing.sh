#!/usr/bin/env bash
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$r/../../activate.sh"
test ! -f "$r/c80-openwrt-ram42-boot-timing.zip"
gcc -I"$r" -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    "$r/verify-boot-timing.c" -o "$r/private/verify-boot-timing"
ASAN_OPTIONS=detect_leaks=1 "$r/private/verify-boot-timing" > "$r/verification-boot-timing.log"
python3 - "$r" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
cases=[line for line in (r/'verification-boot-timing.log').read_text().splitlines() if line.startswith('PASS BOOT TIMING ')]
assert len(cases)==12
names=['c80_timing.h','c80_mcu_core.h','c80_mcu_transport.c','verify-boot-timing.c','verify-boot-timing.sh']
result={'passed':True,'cases_passed':len(cases),'ASan_UBSan':True,'cases':cases,
        'sources':{name:sha(r/name) for name in names},'log_sha256':sha(r/'verification-boot-timing.log'),
        'physical_failure_cause_proven':False,'physical_MCU_DMA_RF_emulated':False}
(r/'evidence/boot-timing-result.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS boot timing:12 cases; bounded settling/ownership timeout, startup floor and precise active-AP waits.')
PY
