#!/usr/bin/env bash
set -euo pipefail
txfree_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$txfree_root/../../activate.sh"
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$txfree_root/verify-tx-free.c" -o "$txfree_root/verify-tx-free"
ASAN_OPTIONS=detect_leaks=1 "$txfree_root/verify-tx-free" "$txfree_root/rootfs/lib/firmware/c80" "$txfree_root/stock-command-oracle.bin" "$txfree_root/stock-synthetic-eeprom.bin" "$txfree_root/stock-auth-txd.bin" > "$txfree_root/verification-tx-free.log"
tail -1 "$txfree_root/verification-tx-free.log"
python3 - "$txfree_root" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);rows=[x for x in (r/'verification-tx-free.log').read_text().splitlines() if x.startswith('PASS TXFREE-')];assert len(rows)==84
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(r/'evidence/tx-free-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(rows),'core_source_sha256':sha(r/'c80_mcu_core.h'),'tests_source_sha256':sha(r/'verify-tx-free.c'),'native_ASan_UBSan':True,'guard_pages':True,'cases':rows,'hardware_MCU_DMA_RF_emulated':False,'pool_release_on_completion':False},indent=2)+'\n')
PY
