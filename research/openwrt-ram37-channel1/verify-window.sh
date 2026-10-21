#!/usr/bin/env bash
set -euo pipefail
window_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$window_root/../../activate.sh"
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$window_root/verify-window.c" -o "$window_root/verify-window"
ASAN_OPTIONS=detect_leaks=1 "$window_root/verify-window" "$window_root/rootfs/lib/firmware/c80" "$window_root/stock-command-oracle.bin" "$window_root/stock-synthetic-eeprom.bin" "$window_root/stock-auth-txd.bin" "$window_root/stock-station-command-oracle.bin" "$window_root/stock-association-txd.bin" "$window_root/stock-data-txd.bin" "$window_root/data-protocol-fixtures.bin" > "$window_root/verification-window.log"
tail -1 "$window_root/verification-window.log"
python3 - "$window_root" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);rows=[s for s in (r/'verification-window.log').read_text().splitlines() if s.startswith('PASS WINDOW-')];assert len(rows)==17
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(r/'evidence/window-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(rows),'core_source_sha256':sha(r/'c80_mcu_core.h'),'tests_source_sha256':sha(r/'verify-window.c'),'native_ASan_UBSan':True,'late_client_arrival_us':[60000000,120000000,170000000,177000000],'CONTROL_us':30000000,'BEACON_us':180000000,'capture_us':178000000,'post_us':179000000,'MCU_and_data_timeout_us':1000000,'frozen_clock_max_samples':180001,'cases':rows,'hardware_client_RF_MCU_DMA_emulated':False},indent=2)+'\n')
PY
