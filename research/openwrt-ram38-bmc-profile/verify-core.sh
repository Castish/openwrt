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
main=json.loads((root/'evidence/stock-main-traces.json').read_text())
assert main['source_sha256']==proof['source_sha256']
assert len(main['packets'])==33
for entry in main['packets']:
    packet=bytes.fromhex(entry['packet_hex'])
    packets.append(struct.pack('<I',len(packet))+packet)
runtime=json.loads((root/'evidence/stock-query-traces.json').read_text())
assert runtime['source_sha256']==proof['source_sha256'] and runtime['cases_passed']==8
query=next(x for x in runtime['packets'] if x['sequence']==11)
packet=bytes.fromhex(query['packet_hex'])
packets.append(struct.pack('<I',len(packet))+packet)
nvm=json.loads((root/'evidence/stock-nvm-traces.json').read_text())
assert nvm['source_sha256']==proof['source_sha256'] and nvm['cases_passed']==19
for name in ('nvm-set-seq12','nvm-get-2-0-1024'):
    entry=next(x for x in nvm['packets'] if x['name']==name)
    packet=bytes.fromhex(entry['packet_hex'])
    packets.append(struct.pack('<I',len(packet))+packet)
dev=json.loads((root/'evidence/stock-devinfo-traces.json').read_text())
assert dev['source_sha256']==proof['source_sha256'] and dev['cases_passed']==39
for name in ('devinfo-0-0-1-1-seq14','devinfo-0-0-0-1-seq15'):
    entry=next(x for x in dev['packets'] if x['name']==name)
    packet=bytes.fromhex(entry['packet_hex'])
    packets.append(struct.pack('<I',len(packet))+packet)
bss=json.loads((root/'evidence/stock-bss-traces.json').read_text())
assert bss['source_sha256']==proof['source_sha256'] and bss['cases_passed']==28
for name in ('bss-on','bss-off'):
    entry=next(x for x in bss['packets'] if x['name']==name)
    packet=bytes.fromhex(entry['packet_hex'])
    packets.append(struct.pack('<I',len(packet))+packet)
radio=json.loads((root/'evidence/stock-radio-traces.json').read_text())
assert radio['source_sha256']==proof['source_sha256'] and radio['cases_passed']==63
for name in ('mac-off-initial','channel6','path1x1','mac-on','mac-off-final'):
    entry=next(x for x in radio['packets'] if x['name']==name)
    packet=bytes.fromhex(entry['packet_hex'])
    packets.append(struct.pack('<I',len(packet))+packet)
beacon=json.loads((root/'evidence/stock-beacon-traces.json').read_text())
assert beacon['source_sha256']==proof['source_sha256'] and beacon['cases_passed']==26
offload=json.loads((root/'evidence/stock-offload-traces.json').read_text())
assert offload['source_sha256']==proof['source_sha256'] and offload['cases_passed']==24
for name in ('sync-on','beacon-on','beacon-off','sync-off'):
    source=offload if name.startswith('beacon-') else beacon
    entry=next(x for x in source['packets'] if x['name']==name)
    packet=bytes.fromhex(entry['packet_hex'])
    packets.append(struct.pack('<I',len(packet))+packet)
state=json.loads((root/'evidence/stock-beacon-state-traces.json').read_text())
assert state['source_sha256']==proof['source_sha256'] and state['cases_passed']==35
for name in ('tsf-own0-seq7','tsf-own0-seq8'):
    entry=next(x for x in state['packets'] if x['name']==name)
    packet=bytes.fromhex(entry['packet_hex']);packets.append(struct.pack('<I',len(packet))+packet)
period=json.loads((root/'evidence/stock-bss-period-traces.json').read_text())
assert period['source_sha256']==proof['source_sha256'] and period['cases_passed']==11
for name in ('bss-period-on','bss-period-off'):
    entry=next(x for x in period['packets'] if x['name']==name)
    packet=bytes.fromhex(entry['packet_hex']);packets.append(struct.pack('<I',len(packet))+packet)
(root/'stock-synthetic-eeprom.bin').write_bytes(bytes.fromhex(nvm['synthetic_EEPROM_hex']))
(root/'stock-command-oracle.bin').write_bytes(b''.join(packets))
PY
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
    -fno-omit-frame-pointer "$c80_test_root/verify-core.c" -o "$c80_test_root/verify-core"
ASAN_OPTIONS=detect_leaks=1 "$c80_test_root/verify-core" \
    "$c80_test_root/rootfs/lib/firmware/c80" "$c80_test_root/stock-command-oracle.bin" "$c80_test_root/stock-synthetic-eeprom.bin" > "$c80_test_root/verification-core.log"
tail -1 "$c80_test_root/verification-core.log"
