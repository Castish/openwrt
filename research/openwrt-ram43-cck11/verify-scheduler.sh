#!/usr/bin/env bash
set -euo pipefail
scheduler_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$scheduler_root/../../activate.sh"
cd "$scheduler_root"
python3 - "$scheduler_root" <<'PYSCHED'
from pathlib import Path
import hashlib,json,struct,sys
r=Path(sys.argv[1]);j=json.loads((r/'evidence/stock-scheduler-result.json').read_text());assert j['passed'] and j['cases_passed']==15
rows=[x for x in j['cases'] if 'IO_calls' in x and x['QM'] in (0,2)]
o=b''.join(struct.pack('<II',0x18000000+a,v) for a,v in rows[0]['IO_calls']);assert hashlib.sha256(o).hexdigest()==j['oracle_sha256']
(r/'stock-scheduler-oracle.bin').write_bytes(o)
(r/'stock-scheduler-vectors.bin').write_bytes(b''.join(struct.pack('<III',x['QM'],x['PKT_MAX_SIZE_before'],len(x['IO_calls']))+b''.join(struct.pack('<II',0x18000000+a,v) for a,v in x['IO_calls']) for x in rows))
PYSCHED
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function -fsanitize=address,undefined -fno-omit-frame-pointer verify-scheduler.c -o verify-scheduler
ASAN_OPTIONS=detect_leaks=1 ./verify-scheduler rootfs/lib/firmware/c80 stock-command-oracle.bin stock-synthetic-eeprom.bin stock-auth-txd.bin stock-station-command-oracle.bin stock-association-txd.bin stock-data-txd.bin data-protocol-fixtures.bin > verification-scheduler.log
tail -n 2 verification-scheduler.log
