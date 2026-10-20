#!/usr/bin/env bash
set -euo pipefail
c80_test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$c80_test_root/../../activate.sh"
python3 - "$c80_test_root" <<'PY'
import json,sys
from pathlib import Path
root=Path(sys.argv[1])
proof=json.loads((root/'evidence/stock-download-traces.json').read_text())
assert proof['source_sha256']=='efdf45c9767bad9b30c93383ee2f5b99a38f5bc2441064e327b026097030fd95'
import struct
packets=[]
for name in ('get','patch-address','scatter960','scatter848','patch-finish','release'):
    entry=next(x for x in proof['packets'] if x['name']==name)
    packet=bytes.fromhex(entry['packet_hex'])
    packets.append(struct.pack('<I',len(packet))+packet)
(root/'stock-command-oracle.bin').write_bytes(b''.join(packets))
PY
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
    -fno-omit-frame-pointer "$c80_test_root/verify-core.c" -o "$c80_test_root/verify-core"
ASAN_OPTIONS=detect_leaks=1 "$c80_test_root/verify-core" \
    "$c80_test_root/rootfs/lib/firmware/c80" "$c80_test_root/stock-command-oracle.bin" > "$c80_test_root/verification-core.log"
tail -1 "$c80_test_root/verification-core.log"
