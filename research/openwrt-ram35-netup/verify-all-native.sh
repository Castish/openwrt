#!/usr/bin/env bash
set -euo pipefail
r=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$r"
for suite in core rx-recycle beacon-state client-rx auth-tx tx-free association data netdev recycle scheduler window cfg-control session security; do
    bash "verify-$suite.sh" > "native-$suite-run.log" 2>&1
    tail -1 "native-$suite-run.log"
done
