#!/usr/bin/env bash
set -euo pipefail
association_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$association_root/../../activate.sh"
python3 - "$association_root" <<'PY'
from pathlib import Path
import json,struct,sys
r=Path(sys.argv[1]);q=json.loads((r/'evidence/stock-station-traces.json').read_text());assert q['passed'] and q['cases_passed']==30
(r/'stock-station-command-oracle.bin').write_bytes(b''.join(struct.pack('<I',len(bytes.fromhex(x['packet_hex'])))+bytes.fromhex(x['packet_hex']) for x in q['profile_packets']))
q=json.loads((r/'evidence/stock-association-tx-traces.json').read_text());assert q['passed'] and q['cases_passed']==8
(r/'stock-association-txd.bin').write_bytes(bytes.fromhex(q['profile']['TXD_hex']))
PY
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$association_root/verify-association.c" -o "$association_root/verify-association"
ASAN_OPTIONS=detect_leaks=1 "$association_root/verify-association" "$association_root/rootfs/lib/firmware/c80" "$association_root/stock-command-oracle.bin" "$association_root/stock-synthetic-eeprom.bin" "$association_root/stock-auth-txd.bin" "$association_root/stock-station-command-oracle.bin" "$association_root/stock-association-txd.bin" > "$association_root/verification-association.log"
tail -1 "$association_root/verification-association.log"
python3 - "$association_root" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);rows=[x for x in (r/'verification-association.log').read_text().splitlines() if x.startswith('PASS ASSOC-')];assert len(rows)==123
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(r/'evidence/association-result.json').write_text(json.dumps({'passed':True,'cases_passed':len(rows),'core_source_sha256':sha(r/'c80_mcu_core.h'),'tests_source_sha256':sha(r/'verify-association.c'),'STA_oracle_sha256':sha(r/'stock-station-command-oracle.bin'),'TXD_oracle_sha256':sha(r/'stock-association-txd.bin'),'native_ASan_UBSan':True,'guard_pages':47,'cases':rows,'hardware_client_RF_MCU_DMA_emulated':False,'pool_released_on_completion':False},indent=2)+'\n')
PY
