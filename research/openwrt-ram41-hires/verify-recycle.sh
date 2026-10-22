#!/usr/bin/env bash
set -euo pipefail
cycle_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$cycle_root/../../activate.sh"
gcc -D_GNU_SOURCE -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "$cycle_root/verify-recycle.c" -o "$cycle_root/verify-recycle"
ASAN_OPTIONS=detect_leaks=1 "$cycle_root/verify-recycle" "$cycle_root/rootfs/lib/firmware/c80" "$cycle_root/stock-command-oracle.bin" "$cycle_root/stock-synthetic-eeprom.bin" "$cycle_root/stock-auth-txd.bin" "$cycle_root/stock-station-command-oracle.bin" "$cycle_root/stock-association-txd.bin" "$cycle_root/stock-data-txd.bin" "$cycle_root/data-protocol-fixtures.bin" > "$cycle_root/verification-recycle.log"
tail -2 "$cycle_root/verification-recycle.log"
