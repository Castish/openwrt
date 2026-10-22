#!/usr/bin/env bash
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$r/../../activate.sh"
python3 - "$r" <<'PY'
from pathlib import Path
import sys
r=Path(sys.argv[1]);(r/'private').mkdir(exist_ok=True)
for source,name in [(r,'gtk-refresh-fixture.h'),(r.parent/'openwrt-ram38-bmc-profile','gtk-old-fixture.h')]:
 (r/'private'/name).write_text((source/'verify-security.c').read_text().split('\nint main(')[0]+'\n')
PY
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function -I"$r/../openwrt-ram38-bmc-profile" -DC80_GTK_OLD_BASELINE -DC80_GTK_FIXTURE='"private/gtk-old-fixture.h"' -fsanitize=address,undefined -fno-omit-frame-pointer "$r/verify-gtk-refresh.c" -o "$r/private/verify-gtk-old"
ASAN_OPTIONS=detect_leaks=1 "$r/private/verify-gtk-old" "$r/../openwrt-ram38-bmc-profile/stock-security-oracle.bin" > "$r/verification-gtk-old-baseline.log"
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function -I"$r" -fsanitize=address,undefined -fno-omit-frame-pointer "$r/verify-gtk-refresh.c" -o "$r/verify-gtk-refresh"
ASAN_OPTIONS=detect_leaks=1 "$r/verify-gtk-refresh" "$r/stock-security-oracle.bin" > "$r/verification-gtk-refresh.log"
tail -1 "$r/verification-gtk-refresh.log"
python3 - "$r" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
cases=[x for x in (r/'verification-gtk-refresh.log').read_text().splitlines() if x.startswith('PASS GTK REFRESH ')]
assert len(cases)==41 and 'RAM38 actual core reproduces' in (r/'verification-gtk-old-baseline.log').read_text()
names=['c80_security_core.h','c80_security_types.h','verify-security.c','verify-gtk-refresh.c','verify-gtk-refresh.sh']
(r/'evidence/gtk-refresh-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(cases),'old_RAM38_actual_core_refusal_reproduced':True,'delete_both_ACK_and_DDONE_before_new_GTK':True,'identical_keys_no_reinstall':True,'live_PTK_or_authorized_GTK_replacement_refused':True,'initial_beacon_snapshots_preserved':True,'ASan_UBSan':True,'cases':cases,'sources':{n:sha(r/n) for n in names},'parent_core_sha256':sha(r.parent/'openwrt-ram38-bmc-profile/c80_security_core.h'),'physical_MCU_CCMP_DMA_RF_emulated':False},indent=2)+'\n')
PY
