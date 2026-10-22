#!/usr/bin/env bash
set -euo pipefail
cfg_test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$cfg_test_root/../../activate.sh"
python3 - "$cfg_test_root" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1])
p=r/'evidence/stock-offload-traces.json'
d=json.loads(p.read_text())
assert d['source_sha256']=='efdf45c9767bad9b30c93383ee2f5b99a38f5bc2441064e327b026097030fd95' and d['cases_passed']==24
b=bytes.fromhex(next(x for x in d['packets'] if x['name']=='beacon-on')['packet_hex'])
assert len(b)==592
(r/'stock-beacon-body.bin').write_bytes(b[64:])
PY
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    "$cfg_test_root/verify-cfg-control.c" -o "$cfg_test_root/verify-cfg-control"
ASAN_OPTIONS=detect_leaks=1 "$cfg_test_root/verify-cfg-control" "$cfg_test_root/stock-beacon-body.bin" > "$cfg_test_root/verification-cfg-control.log"
tail -n 1 "$cfg_test_root/verification-cfg-control.log"
python3 - "$cfg_test_root" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert 'PASS: 652 ' in (r/'verification-cfg-control.log').read_text()
(r/'evidence/cfg-control-result.json').write_text(json.dumps({
 'passed':True,'cases_passed':652,'ASan_UBSan':True,'hardware_tested':False,
 'scope':'Actual shared core; beacon bounds/guard pages, legacy OEM offload packet, variable SSID, wait/stop/timer/HIF and before-MMIO refusal. Synthetic hardware effects.',
 'sources':{n:sha(r/n) for n in ['c80_mcu_core.h','c80_net_core.h','c80_net_types.h','verify-cfg-control.c','verify-cfg-control.sh']},
 'oracle_sha256':sha(r/'stock-beacon-body.bin'),'test_binary_sha256':sha(r/'verify-cfg-control')},indent=2)+'\n')
PY
