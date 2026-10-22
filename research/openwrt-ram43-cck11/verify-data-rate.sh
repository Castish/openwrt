#!/usr/bin/env bash
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$r/../../activate.sh"
test ! -f "$r/c80-openwrt-ram43-cck11.zip"
gcc -I"$r" -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function \
 -fsanitize=address,undefined -fno-omit-frame-pointer "$r/verify-data-rate.c" -o "$r/private/verify-data-rate"
ASAN_OPTIONS=detect_leaks=1 "$r/private/verify-data-rate" "$r/stock-auth-txd.bin" "$r/stock-association-txd.bin" \
 "$r/stock-data-txd.bin" "$r/stock-station-command-oracle.bin" "$r/stock-reassociation-txd.bin" \
 "$r/stock-data-rate-oracle.bin" > "$r/verification-data-rate.log"
python3 - "$r" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
cases=[s for s in (r/'verification-data-rate.log').read_text().splitlines() if s.startswith('PASS DATA RATE ')]
assert len(cases)==250,len(cases)
names=['c80_mcu_core.h','c80_mcu_transport.c','c80_net_types.h','c80_net_core.h','c80_security_core.h','verify-session.c','verify-data-rate.c','verify-data-rate.sh']
v={'passed':True,'cases_passed':len(cases),'ASan_UBSan':True,'mixed_posts':15000,
   'cases':cases,'sources':{n:sha(r/n) for n in names},'oracle_sha256':sha(r/'stock-data-rate-oracle.bin'),
   'log_sha256':sha(r/'verification-data-rate.log'),'MCU_DMA_CCMP_RF_emulated':False}
(r/'evidence/data-rate-result.json').write_text(json.dumps(v,indent=2)+'\n')
print('PASS data rate:250 actual-core cases,15000 mixed CCK11 data/CCK1 EAPOL posts; synthetic device effects.')
PY
