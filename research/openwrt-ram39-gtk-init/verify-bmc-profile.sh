#!/usr/bin/env bash
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$r/../../activate.sh"
python3 - "$r" <<'PY'
from pathlib import Path
import sys
r=Path(sys.argv[1]);(r/'private').mkdir(exist_ok=True)
(r/'private/bmc-profile-fixture.h').write_text((r/'verify-security.c').read_text().split('\nint main(')[0]+'\n')
PY
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function -I"$r" -fsanitize=address,undefined -fno-omit-frame-pointer "$r/verify-bmc-profile.c" -o "$r/verify-bmc-profile"
ASAN_OPTIONS=detect_leaks=1 "$r/verify-bmc-profile" "$r/stock-security-oracle.bin" > "$r/verification-bmc-profile.log"
tail -1 "$r/verification-bmc-profile.log"
python3 - "$r" <<'PY'
from pathlib import Path
import hashlib,json,sys
r=Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert 'PASS: 12 ' in (r/'verification-bmc-profile.log').read_text()
names=['c80_mcu_core.h','c80_security_core.h','verify-security.c','verify-bmc-profile.c','verify-bmc-profile.sh','trace-stock-security.py','trace-bmc-profile.py','trace-normal-ap-request.py']
(r/'evidence/bmc-profile-result.json').write_text(json.dumps({'passed':True,'cases_passed':12,'ASan_UBSan':True,'actual_core_BMC_payload_compared_to_OEM_normal_AP_profile':True,'guard_page_create252_delete28':True,'BMC_reject_timeout_DDONE_sequence_extension_length_echo_descriptor_fail_closed':True,'sources':{n:sha(r/n) for n in names},'oracle_sha256':sha(r/'stock-security-oracle.bin'),'hardware_tested':False},indent=2)+'\n')
PY
